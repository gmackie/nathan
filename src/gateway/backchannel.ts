import { createRemoteJWKSet, jwtVerify } from "jose";
import { discover } from "./oidc";
import type { GatewayEnv } from "./env";

const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const failed = () => new Response("Invalid logout token", {status: 400, headers: {"Cache-Control":"no-store"}});
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
  try {
    const metadata = await discover(env);
    const { payload, protectedHeader } = await jwtVerify(token, createRemoteJWKSet(new URL(metadata.jwks_uri)), {
      issuer: metadata.issuer, audience: env.OIDC_CLIENT_ID,
      algorithms: ["RS256", "ES256", "EdDSA"], clockTolerance: 30
    });
    if (protectedHeader.typ !== "logout+jwt") return failed();
    if (!payload.events || typeof payload.events !== "object" || !(EVENT in payload.events)) return failed();
    if ("nonce" in payload || !payload.jti || typeof payload.iat !== "number") return failed();
    if (!payload.sub && !payload.sid) return failed();
    const now = Math.floor(Date.now()/1000);
    if (Math.abs(now - payload.iat) > 180) return failed();
    const inserted = await env.SESSIONS.prepare(
      "INSERT OR IGNORE INTO nathan_gateway_logout_jti(jti,exp) VALUES (?,?)"
    ).bind(payload.jti, now + 300).run();
    if (!inserted.meta?.changes) return new Response(null, {status:204}); // replay safely ignored
    if (typeof payload.sid === "string") {
      await env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE sid=? AND issuer=? AND client_id=?")
        .bind(payload.sid,metadata.issuer,env.OIDC_CLIENT_ID).run();
    } else if (typeof payload.sub === "string") {
      await env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE subject=? AND issuer=? AND client_id=?")
        .bind(payload.sub,metadata.issuer,env.OIDC_CLIENT_ID).run();
    }
    return new Response(null, {status:204,headers:{"Cache-Control":"no-store"}});
  } catch { return failed(); }
}
