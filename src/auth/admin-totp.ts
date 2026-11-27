import type { AuthEnv } from "./env";

/** The snapshot is request-local. Better Auth can rotate the secret of a pending enrollment
 * in place, so both the row id and encrypted secret must still match after verification. */
export type TotpFactor = { id: string; userId: string; secret: string; verified: number | null };
export function adminTotpFactor(env: AuthEnv, userId: string) {
  return env.DB.prepare('SELECT f.id,f.userId,f.secret,f.verified FROM twoFactor f JOIN "user" u ON u.id=f.userId ' +
    'WHERE f.userId=? AND u.role=\'admin\' AND u.emailVerified=1').bind(userId).first<TotpFactor>();
}

export async function recordAdminTotp(env: AuthEnv, factor: TotpFactor, sessionId: string, code: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(env.BETTER_AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const tag = await crypto.subtle.sign("HMAC", key, enc.encode(JSON.stringify(["nathan:admin:totp", factor.id, code])));
  const [, proof] = await env.DB.batch([
    env.DB.prepare("DELETE FROM nathan_admin_totp_assurance WHERE verified_at < unixepoch()-900"),
    env.DB.prepare("INSERT INTO nathan_admin_totp_assurance(factor_id,code_tag,user_id,session_id) " +
      'SELECT f.id,?,f.userId,s.id FROM twoFactor f JOIN session s ON s.userId=f.userId ' +
      "WHERE f.id=? AND f.userId=? AND f.secret=? AND f.verified=1 AND s.id=? " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_email_otp_sessions e WHERE e.session_id=s.id) " +
      "ON CONFLICT(factor_id,code_tag) DO NOTHING")
      .bind(tag, factor.id, factor.userId, factor.secret, sessionId)
  ]);
  return proof.meta.changes === 1;
}

export async function recentAdminTotp(env: AuthEnv, userId: string, sessionId: string) {
  return Boolean(await env.DB.prepare(
    "SELECT 1 FROM nathan_admin_totp_assurance a JOIN twoFactor f ON f.id=a.factor_id AND f.userId=a.user_id " +
    "WHERE a.user_id=? AND a.session_id=? AND f.verified=1 AND a.invalidated=0 AND a.verified_at BETWEEN unixepoch()-900 AND unixepoch() LIMIT 1"
  ).bind(userId, sessionId).first());
}
