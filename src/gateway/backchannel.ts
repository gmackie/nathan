import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { discover } from "./oidc";
import type { GatewayEnv } from "./env";

const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const failed = () => new Response("Invalid logout token", {status: 400, headers: {"Cache-Control":"no-store"}});
const done = () => new Response(null, {status: 204, headers: {"Cache-Control":"no-store"}});
// 5xx tells the IdP to retry; used whenever the gateway could not decide, never for a bad token.
const retry = (reason: string) => new Response(reason + "; retry", {status: 503, headers: {"Cache-Control":"no-store", "Retry-After": "5"}});
const MAX_IAT_SKEW = 180, CLOCK_TOLERANCE = 30;
/**
 * jose reports token problems with ERR_JWT_* / ERR_JWS_* codes, and a token signed by an
 * unknown key or disallowed algorithm as ERR_JWKS_NO_MATCHING_KEY / ERR_JOSE_ALG_NOT_ALLOWED. Other JWKS failures (timeout, malformed or non-200
 * key set) and network errors are the identity provider's or network's, so they are retryable.
 */
const TOKEN_JWKS_ERRORS = ["ERR_JWKS_NO_MATCHING_KEY", "ERR_JWKS_MULTIPLE_MATCHING_KEYS", "ERR_JOSE_ALG_NOT_ALLOWED", "ERR_JOSE_NOT_SUPPORTED"];
const isTokenError = (error: unknown) => {
  const code = (error as {code?: unknown})?.code;
  if (typeof code !== "string") return false;
  return code.startsWith("ERR_JWT_") || code.startsWith("ERR_JWS_") || TOKEN_JWKS_ERRORS.includes(code);
};
export async function handleBackchannelLogout(request: Request, env: GatewayEnv): Promise<Response> {
  if (!request.headers.get("Content-Type")?.startsWith("application/x-www-form-urlencoded")) return failed();
  if (Number(request.headers.get("Content-Length") || 0) > 20000) return failed();
  let token: string | null = null;
  try {
    const body = await request.text();
    if (body.length > 20000) return failed();
    token = new URLSearchParams(body).get("logout_token");
  } catch { return failed(); }
  if (!token || token.length > 16000) return failed();
  let metadata: Awaited<ReturnType<typeof discover>>, payload: JWTPayload;
  try { metadata = await discover(env); }
  catch { return retry("Identity provider discovery unavailable"); }
  try {
    const verified = await jwtVerify(token, createRemoteJWKSet(new URL(metadata.jwks_uri)), {
      issuer: metadata.issuer, audience: env.OIDC_CLIENT_ID,
      algorithms: ["RS256", "ES256", "EdDSA"], clockTolerance: CLOCK_TOLERANCE
    });
    payload = verified.payload;
    if (verified.protectedHeader.typ !== "logout+jwt") return failed();
  } catch (error) {
    return isTokenError(error) ? failed() : retry("Identity provider signing keys unavailable");
  }
  if (!payload.events || typeof payload.events !== "object" || !(EVENT in payload.events)) return failed();
  if ("nonce" in payload || typeof payload.jti !== "string" || payload.jti.length > 256 || typeof payload.iat !== "number") return failed();
  const occurred = payload.toe;
  if (occurred !== undefined && (typeof occurred !== "number" || !Number.isFinite(occurred) || occurred < 0 || occurred > payload.iat)) return failed();
  if (typeof payload.sid !== "string" && typeof payload.sub !== "string") return failed();
  const now = Math.floor(Date.now()/1000);
  if (Math.abs(now - payload.iat) > MAX_IAT_SKEW) return failed();
  // Keep the replay record until the token can no longer pass the iat window, even when
  // the token is future-dated, so pruning never re-opens it for replay.
  const replayUntil = Math.max(now, payload.iat) + MAX_IAT_SKEW + CLOCK_TOLERANCE + 60;
  try {
    const seen = await env.SESSIONS.prepare("SELECT 1 AS seen FROM nathan_gateway_logout_jti WHERE jti=?").bind(payload.jti).first();
    if (seen) return done(); // replay safely ignored; never revokes sessions created after the original logout
    const revoke = typeof payload.sid === "string"
      ? env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE sid=? AND issuer=? AND client_id=?")
          .bind(payload.sid, metadata.issuer, env.OIDC_CLIENT_ID)
      : env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE subject=?1 AND issuer=?2 AND client_id=?3 " +
          "AND (?4 IS NULL OR created_at<=?4)")
          .bind(payload.sub, metadata.issuer, env.OIDC_CLIENT_ID, occurred ?? null);
    // One D1 batch is one transaction: the JTI is recorded only if revocation committed,
    // so a storage failure leaves the token retryable by the IdP.
    await env.SESSIONS.batch([
      revoke,
      env.SESSIONS.prepare("INSERT INTO nathan_gateway_logout_jti(jti,exp) VALUES (?,?)").bind(payload.jti, replayUntil)
    ]);
    return done();
  } catch (error) {
    if (String(error).includes("UNIQUE")) return done(); // a concurrent delivery of the same token committed first
    return retry("Logout could not be recorded");
  }
}
