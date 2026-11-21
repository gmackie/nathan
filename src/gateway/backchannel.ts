import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { discover } from "./oidc";
import type { GatewayEnv } from "./env";

const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const failed = () => new Response("Invalid logout token", {status: 400, headers: {"Cache-Control":"no-store"}});
const done = () => new Response(null, {status: 204, headers: {"Cache-Control":"no-store"}});
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
  try {
    metadata = await discover(env);
    const verified = await jwtVerify(token, createRemoteJWKSet(new URL(metadata.jwks_uri)), {
      issuer: metadata.issuer, audience: env.OIDC_CLIENT_ID,
      algorithms: ["RS256", "ES256", "EdDSA"], clockTolerance: 30
    });
    payload = verified.payload;
    if (verified.protectedHeader.typ !== "logout+jwt") return failed();
  } catch { return failed(); }
  if (!payload.events || typeof payload.events !== "object" || !(EVENT in payload.events)) return failed();
  if ("nonce" in payload || typeof payload.jti !== "string" || payload.jti.length > 256 || typeof payload.iat !== "number") return failed();
  if (typeof payload.sid !== "string" && typeof payload.sub !== "string") return failed();
  const now = Math.floor(Date.now()/1000);
  if (Math.abs(now - payload.iat) > 180) return failed();
  try {
    const seen = await env.SESSIONS.prepare("SELECT 1 AS seen FROM nathan_gateway_logout_jti WHERE jti=?").bind(payload.jti).first();
    if (seen) return done(); // replay safely ignored; never revokes sessions created after the original logout
    const revoke = typeof payload.sid === "string"
      ? env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE sid=? AND issuer=? AND client_id=?")
          .bind(payload.sid, metadata.issuer, env.OIDC_CLIENT_ID)
      : env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE subject=? AND issuer=? AND client_id=?")
          .bind(payload.sub, metadata.issuer, env.OIDC_CLIENT_ID);
    // One D1 batch is one transaction: the JTI is recorded only if revocation committed,
    // so a storage failure leaves the token retryable by the IdP.
    await env.SESSIONS.batch([
      revoke,
      env.SESSIONS.prepare("INSERT INTO nathan_gateway_logout_jti(jti,exp) VALUES (?,?)").bind(payload.jti, now + 300)
    ]);
    return done();
  } catch (error) {
    if (String(error).includes("UNIQUE")) return done(); // a concurrent delivery of the same token committed first
    return new Response("Logout could not be recorded; retry", {status: 503, headers: {"Cache-Control":"no-store", "Retry-After": "5"}});
  }
}
