import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { APIError } from "better-auth/api";
import { constantTimeEqual, symmetricDecrypt, type SecretConfig } from "better-auth/crypto";
import { mayEnrollManagementFactor } from "./bootstrap";
import { managementEmail, type AuthEnv } from "./env";

type Factor = { id: string; userId: string; secret: string; verified: number | null };
export type ManagementTotpProof = { factor: Factor; step: number };
const nextCode = () => new APIError("UNAUTHORIZED", { message: "Enter the next code from your authenticator app." });

/** Reserve the verified time step before the provider can issue a session. The provider
 * still verifies the full password/TOTP challenge and applies its normal attempt limits. */
export async function reserveManagementTotp(env: AuthEnv, code: unknown, sessionId: string | undefined, key: string | SecretConfig) {
  const factors = await env.DB.prepare(
    'SELECT f.id,f.userId,f.secret,f.verified FROM "twoFactor" f JOIN "user" u ON u.id=f.userId ' +
    "WHERE lower(u.email)=? AND u.role='admin' AND u.emailVerified=1 LIMIT 2"
  ).bind(env[managementEmail]).all<Factor>();
  if (factors.results.length !== 1) throw nextCode();
  const factor = factors.results[0];
  if (!factor.verified && (!sessionId || !await mayEnrollManagementFactor(env, factor.userId, sessionId, "/two-factor/enable")))
    throw new APIError("FORBIDDEN", { message: "Verify your enrolled method before activating this authenticator." });
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
    if (!factor.verified) throw nextCode();
    return null;
  }
  const value = await symmetricDecrypt({key, data: factor.secret});
  // Match the pinned provider's generated and imported secrets, period and adjacent-step window.
  const secret = value.startsWith("base32:") ? base32.decode(value.slice(7).toUpperCase()) : value;
  const otp = createOTP(secret);
  const now = Math.floor(Date.now() / 30000);
  const steps = [now - 1, now, now + 1];
  const matches = await Promise.all(steps.map(async step => constantTimeEqual(await otp.hotp(step), code)));
  const index = matches.lastIndexOf(true);
  if (index < 0) {
    if (!factor.verified) throw nextCode();
    return null;
  }
  const step = steps[index];
  const saved = await env.DB.prepare(`
    INSERT INTO nathan_management_totp_steps(factor_id,last_step,passkey_proof_until)
    SELECT f.id,?2,COALESCE((
      SELECT a.verified_at+900 FROM nathan_admin_assurance a
      JOIN "session" s ON s.id=a.session_id AND s.userId=a.user_id
      WHERE a.session_id=?3 AND a.user_id=f.userId AND a.method='passkey' AND unixepoch(s.expiresAt)>unixepoch()
    ),0) FROM "twoFactor" f WHERE f.id=?1 AND f.secret=?4
    AND (SELECT count(*) FROM "twoFactor" WHERE userId=f.userId)=1
    ON CONFLICT(factor_id) DO UPDATE SET last_step=excluded.last_step,passkey_proof_until=excluded.passkey_proof_until
    WHERE nathan_management_totp_steps.last_step<excluded.last_step
    RETURNING factor_id`).bind(factor.id, step, sessionId ?? null, factor.secret).first();
  if (!saved) throw nextCode();
  return { factor, step };
}

/** Only a successful Better Auth response can give the verified management session evidence. */
export async function recordManagementTotp(env: AuthEnv, proof: ManagementTotpProof | undefined, userId: string, sessionId: string) {
  if (!proof || proof.factor.userId !== userId) throw nextCode();
  const saved = await env.DB.prepare(`
    INSERT INTO nathan_management_totp(session_id,factor_id)
    SELECT s.id,f.id FROM "session" s JOIN "user" u ON u.id=s.userId
    JOIN "twoFactor" f ON f.userId=u.id JOIN nathan_management_totp_steps t ON t.factor_id=f.id
    WHERE s.id=? AND u.id=? AND lower(u.email)=? AND u.role='admin' AND u.emailVerified=1 AND u.twoFactorEnabled=1
      AND f.id=? AND f.secret=? AND f.verified=1 AND t.last_step=?
      AND NOT EXISTS(SELECT 1 FROM nathan_email_otp_sessions e WHERE e.session_id=s.id)
    ON CONFLICT(session_id) DO UPDATE SET factor_id=excluded.factor_id,verified_at=unixepoch()
    RETURNING session_id`).bind(sessionId, userId, env[managementEmail], proof.factor.id, proof.factor.secret, proof.step).first();
  if (!saved) throw nextCode();
}
