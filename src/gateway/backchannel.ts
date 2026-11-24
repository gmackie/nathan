import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { discover } from "./oidc";
import type { GatewayEnv } from "./env";

const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const failed = () => new Response("Invalid logout token", {status: 400, headers: {"Cache-Control":"no-store"}});
const done = () => new Response(null, {status: 204, headers: {"Cache-Control":"no-store"}});
// 5xx tells the IdP to retry; used whenever the gateway could not decide, never for a bad token.
const retry = (reason: string) => new Response(reason + "; retry", {status: 503, headers: {"Cache-Control":"no-store", "Retry-After": "5"}});
const MAX_IAT_SKEW = 180, CLOCK_TOLERANCE = 30;
// The seven redelivery delays total nearly 20 hours, before scheduler delays.
const RECEIPT_SECONDS = 48 * 60 * 60;
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
  const replayUntil = Math.max(now, payload.iat) + RECEIPT_SECONDS;
  const sid = typeof payload.sid === "string" ? payload.sid : null;
  const subject = typeof payload.sub === "string" ? payload.sub : null;
  try {
    const record = env.SESSIONS.prepare(`
      INSERT INTO nathan_gateway_logout_receipts(issuer,client_id,jti,sid,subject,event_time,exp)
      SELECT ?1,?2,?3,?4,?5,?6,?7
      WHERE NOT EXISTS (SELECT 1 FROM nathan_gateway_logout_jti WHERE jti=?3 AND exp>unixepoch())
      ON CONFLICT(issuer,client_id,jti) DO NOTHING
    `).bind(metadata.issuer, env.OIDC_CLIENT_ID, payload.jti, sid, subject, occurred ?? null, replayUntil);
    // changes() is the receipt insertion in this transaction. Redelivery acknowledges
    // the original decision, including for older issuers that do not send an event time.
    const revoke = sid !== null
      ? env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE changes()=1 AND issuer=? AND client_id=? AND sid=?")
          .bind(metadata.issuer, env.OIDC_CLIENT_ID, sid)
      : env.SESSIONS.prepare(`
          DELETE FROM nathan_gateway_sessions WHERE changes()=1 AND issuer=?1 AND client_id=?2 AND subject=?3
          AND (?4 IS NULL OR coalesce(issued_at,created_at)<=?4)
        `).bind(metadata.issuer, env.OIDC_CLIENT_ID, subject, occurred ?? null);
    await env.SESSIONS.batch([record, revoke]);
    return done();
  } catch {
    return retry("Logout could not be recorded");
  }
}
