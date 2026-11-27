import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { APIError, createAuthEndpoint, getSessionFromCtx } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { constantTimeEqual, symmetricDecrypt, type SecretConfig } from "better-auth/crypto";
import { parseUserOutput } from "better-auth/db";
import type { twoFactor } from "better-auth/plugins";
import { mayEnrollManagementFactor } from "./bootstrap";
import { managementEmail, type AuthEnv } from "./env";
import { activeManagementUser, epochSeconds } from "./management-storage";
import { allowRequests } from "./request-limit";

type VerifyTotp = ReturnType<typeof twoFactor>["endpoints"]["verifyTOTP"];
type Factor = { id: string; userId: string; secret: string; verified: number | null; enabled: number };
const nextCode = () => new APIError("UNAUTHORIZED", { message: "Enter the next code from your authenticator app." });
const restartSignIn = () => new APIError("UNAUTHORIZED", { code: "MANAGEMENT_SIGN_IN_RESTART",
  message: "Sign in with your password again, then enter a new authenticator code." });
const enrollmentChanged = () => new APIError("FORBIDDEN", { message: "Check your authenticator setup and verify any enrolled passkey before continuing." });

async function matchingStep(factor: Factor, key: string | SecretConfig, code: string) {
  if (!/^\d{6}$/.test(code)) return null;
  const value = await symmetricDecrypt({ key, data: factor.secret });
  const secret = value.startsWith("base32:") ? base32.decode(value.slice(7).toUpperCase()) : value;
  const otp = createOTP(secret), now = Math.floor(Date.now() / 30_000);
  const steps = [now - 1, now, now + 1];
  const matches = await Promise.all(steps.map(async step => constantTimeEqual(await otp.hotp(step), code)));
  return steps[matches.lastIndexOf(true)] ?? null;
}

/** Commit one use of the exact secret and step with its session evidence. During
 * enrollment the original session authorizes activation and is retired in this batch. */
async function acceptCode(env: AuthEnv, factor: Factor, step: number, targetToken: string, originalSession?: string) {
  const db = env.DB;
  const batch = [db.prepare(`
    INSERT INTO nathan_management_totp_steps(factor_id,step)
    SELECT f.id,?1 FROM twoFactor f JOIN user u ON u.id=f.userId
      JOIN session target ON target.userId=u.id AND target.token=?2
      JOIN session source ON source.userId=u.id AND source.id=COALESCE(?3,target.id)
    WHERE f.id=?4 AND f.secret=?5 AND f.userId=?6 AND lower(u.email)=?7 AND ${activeManagementUser}
      AND (SELECT count(*) FROM twoFactor WHERE userId=u.id)=1
      AND NOT EXISTS(SELECT 1 FROM nathan_email_otp_sessions WHERE session_id IN (source.id,target.id))
      AND NOT EXISTS(SELECT 1 FROM session s WHERE s.id IN (source.id,target.id)
        AND COALESCE(${epochSeconds("s.expiresAt")},0)<=unixepoch())
      AND ?1 BETWEEN unixepoch()/30-1 AND unixepoch()/30+1
      AND ((?3 IS NULL AND f.verified=1 AND u.twoFactorEnabled=1)
        OR (?3 IS NOT NULL AND source.id<>target.id AND u.twoFactorEnabled IS NOT 1 AND f.verified IS NOT 1 AND (
          NOT EXISTS(SELECT 1 FROM passkey WHERE userId=u.id)
          OR EXISTS(SELECT 1 FROM nathan_admin_assurance WHERE user_id=u.id AND session_id=source.id
            AND method='passkey' AND verified_at BETWEEN unixepoch()-900 AND unixepoch()))))
    ON CONFLICT(factor_id,step) DO NOTHING`)
    .bind(step, targetToken, originalSession ?? null, factor.id, factor.secret, factor.userId, env[managementEmail])];
  // Each following write runs only if its predecessor matched. D1 rolls the
  // whole batch back on an error, including a failure to store session evidence.
  if (originalSession) batch.push(
    db.prepare("UPDATE twoFactor SET verified=1 WHERE id=? AND changes()=1").bind(factor.id),
    db.prepare("UPDATE user SET twoFactorEnabled=1,updatedAt=? WHERE id=? AND changes()=1").bind(new Date().toISOString(), factor.userId),
    db.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) SELECT ?,?,'management_totp_enrolled',?,'succeeded' WHERE changes()=1")
      .bind(crypto.randomUUID(), factor.userId, factor.id)
  );
  batch.push(db.prepare(`INSERT INTO nathan_management_totp(session_id,factor_id)
    SELECT id,? FROM session WHERE token=? AND changes()=1
    ON CONFLICT(session_id) DO UPDATE SET factor_id=excluded.factor_id,verified_at=unixepoch()`).bind(factor.id, targetToken));
  if (originalSession) batch.push(db.prepare("DELETE FROM session WHERE id=? AND changes()=1").bind(originalSession));
  batch.push(db.prepare("DELETE FROM nathan_management_totp_steps WHERE factor_id=? AND step<unixepoch()/30-1").bind(factor.id));
  const [accepted] = await db.batch(batch);
  return accepted.meta.changes === 1;
}

export function managementTotpEndpoint(env: AuthEnv, provider: VerifyTotp): VerifyTotp {
  return createAuthEndpoint(provider.path, provider.options, async ctx => {
    const current = await getSessionFromCtx(ctx);
    const { results } = await env.DB.prepare(`SELECT f.id,f.userId,f.secret,f.verified,COALESCE(u.twoFactorEnabled,0) AS enabled FROM twoFactor f
      JOIN user u ON u.id=f.userId WHERE lower(u.email)=? AND u.emailVerified=1 AND u.role='admin' LIMIT 2`)
      .bind(env[managementEmail]).all<Factor>();
    if (!results.length) throw nextCode();
    const [factor] = results;
    if (results.length !== 1 || (factor.verified === 1) !== Boolean(factor.enabled))
      throw new APIError("FORBIDDEN", { message: "Contact your Cloudflare account operator to recover this authenticator enrollment." });
    if (current) {
      if (current.user.id !== factor.userId) throw enrollmentChanged();
      if (!await allowRequests(env, "management-totp", factor.userId, 5))
        throw new APIError("TOO_MANY_REQUESTS", { message: "Wait a minute before trying another authenticator code." });
    }
    const step = await matchingStep(factor, ctx.context.secretConfig, ctx.body.code);
    const adapter = ctx.context.internalAdapter;

    if (current) {
      if (step === null) throw nextCode();
      if (factor.verified === 1) {
        if (!await acceptCode(env, factor, step, current.session.token)) throw nextCode();
        return { token: current.session.token, user: parseUserOutput(ctx.context.options, current.user) };
      }
      if (!await mayEnrollManagementFactor(env, factor.userId, current.session.id, "/two-factor/enable")) throw enrollmentChanged();
      const replacement = await adapter.createSession(factor.userId, false, current.session);
      try {
        if (!await acceptCode(env, factor, step, replacement.token, current.session.id)) throw enrollmentChanged();
      } catch (error) {
        await adapter.deleteSession(replacement.token);
        throw error;
      }
      const user = { ...current.user, twoFactorEnabled: true };
      await setSessionCookie(ctx, { session: replacement, user });
      return { token: replacement.token, user: parseUserOutput(ctx.context.options, user) };
    }

    // Better Auth owns the password challenge, expiry, attempts and account lockout.
    // Its response cookies stay private until this request's code and session commit.
    if (factor.verified !== 1) throw enrollmentChanged();
    const { response, headers } = await provider({ ...ctx, body: { code: ctx.body.code, trustDevice: false },
      asResponse: false, returnHeaders: true, returnStatus: false });
    try {
      if (step === null || response.user.id !== factor.userId || !await acceptCode(env, factor, step, response.token))
        throw restartSignIn();
    } catch (error) {
      await adapter.deleteSession(response.token);
      throw error;
    }
    for (const cookie of headers.getSetCookie()) ctx.responseHeaders.append("Set-Cookie", cookie);
    return response;
  });
}
