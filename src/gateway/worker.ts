import { parseCookie, makeCookie, safeReturnPath, constantTimeEqual, validateIssuer, isAllowedUnsafeRequest } from "../shared/security.mjs";
import { randomId, seal, unseal, sha256 } from "./crypto";
import { discover, authorizeUrl, exchangeCode, verifyIdToken } from "./oidc";
import type { GatewayEnv } from "./env";
import { handleBackchannelLogout } from "./backchannel";

const SESSION_COOKIE = "__Host-nathan-session";
const FLOW_COOKIE = "__Host-nathan-flow";
type Flow = { state: string; nonce: string; verifier: string; returnTo: string; expiresAt: number };
type StoredSession = { subject: string; email: string | null; sessionIdHash: string; expiresAt: number; acr: string | null; authTime: number | null; issuer: string; sid?: string | null };

function origin(env: GatewayEnv) {
  const u = new URL(env.PUBLIC_ORIGIN);
  if (u.protocol !== "https:" || u.pathname !== "/" || u.search || u.hash) throw Error("PUBLIC_ORIGIN must be a bare HTTPS origin");
  validateIssuer(env.NATHAN_ISSUER);
  if (!env.OIDC_CLIENT_ID || !env.OIDC_CLIENT_SECRET || !env.SESSION_ENCRYPTION_KEY) throw Error("Missing gateway secret or OAuth client credentials");
  return u.origin;
}
function errorResponse(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}
function secureResponse(response: Response) {
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "no-referrer");
  return response;
}
function cleared(response: Response): Response {
  response.headers.append("Set-Cookie", makeCookie(FLOW_COOKIE, "", { deleteCookie: true }));
  return secureResponse(response);
}
async function beginLogin(url: URL, env: GatewayEnv) {
  const meta = await discover(env);
  const flow: Flow = {
    state: randomId(), nonce: randomId(), verifier: randomId(),
    returnTo: safeReturnPath(url.searchParams.get("returnTo") || "/"),
    expiresAt: Date.now() + 5 * 60_000
  };
  const loginUrl = await authorizeUrl(env, meta, flow.state, flow.nonce, flow.verifier);
  const response = Response.redirect(loginUrl, 302);
  response.headers.append("Set-Cookie", makeCookie(FLOW_COOKIE, await seal(flow, env.SESSION_ENCRYPTION_KEY), { maxAge: 300 }));
  return secureResponse(response);
}
async function completeLogin(url: URL, request: Request, env: GatewayEnv): Promise<Response> {
  const encrypted = parseCookie(request.headers.get("Cookie"), FLOW_COOKIE);
  const flow = encrypted && await unseal<Flow>(encrypted, env.SESSION_ENCRYPTION_KEY);
  if (!flow || !Number.isSafeInteger(flow.expiresAt) || flow.expiresAt < Date.now()
      || !constantTimeEqual(url.searchParams.get("state") || "", flow.state))
    return cleared(errorResponse(400, "Login state invalid or expired. Please try again."));
  if (url.searchParams.has("error")) return cleared(errorResponse(401, "Identity provider rejected login"));
  const code = url.searchParams.get("code");
  if (!code || code.length > 4096) return cleared(errorResponse(400, "Missing authorization code"));
  try {
    const meta = await discover(env);
    const token = await exchangeCode(env, meta, code, flow.verifier);
    const id = await verifyIdToken(env, meta, token.id_token, flow.nonce);
    const handle = randomId();
    const hash = await sha256(handle);
    const ttl = Math.max(300, Math.min(8 * 60 * 60, Number(env.SESSION_TTL_SECONDS || "28800")));
    const expiresAt = Math.floor(Date.now() / 1000) + ttl;
    await env.SESSIONS.prepare(
      "INSERT INTO nathan_gateway_sessions(id_hash, subject, email, issuer, client_id, acr, auth_time, sid, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(hash, id.sub, typeof id.email === "string" ? id.email : null, meta.issuer, env.OIDC_CLIENT_ID,
      typeof id.acr === "string" ? id.acr : null, typeof id.auth_time === "number" ? id.auth_time : null, typeof id.sid === "string" ? id.sid : null, expiresAt).run();
    const response = Response.redirect(origin(env) + flow.returnTo, 303);
    response.headers.append("Set-Cookie", makeCookie(SESSION_COOKIE, handle, { maxAge: ttl }));
    return cleared(response);
  } catch {
    return cleared(errorResponse(401, "Login validation failed. Please retry or contact your administrator."));
  }
}
async function currentSession(request: Request, env: GatewayEnv): Promise<StoredSession | null> {
  const handle = parseCookie(request.headers.get("Cookie"), SESSION_COOKIE);
  if (!handle || !/^[A-Za-z0-9_-]{32,128}$/.test(handle)) return null;
  const hash = await sha256(handle);
  const row = await env.SESSIONS.prepare(
    "SELECT subject, email, id_hash as sessionIdHash, expires_at as expiresAt, acr, auth_time as authTime, issuer FROM nathan_gateway_sessions WHERE id_hash=? AND client_id=? AND issuer=? AND expires_at > unixepoch()"
  ).bind(hash, env.OIDC_CLIENT_ID, env.NATHAN_ISSUER).first<StoredSession>();
  return row ?? null;
}
async function logout(request: Request, env: GatewayEnv): Promise<Response> {
  if (request.headers.get("Origin") !== origin(env)) return errorResponse(403, "Cross-origin logout denied");
  const handle = parseCookie(request.headers.get("Cookie"), SESSION_COOKIE);
  if (handle) await env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE id_hash=?").bind(await sha256(handle)).run();
  const response = new Response(null, { status: 204 });
  response.headers.append("Set-Cookie", makeCookie(SESSION_COOKIE, "", { deleteCookie: true }));
  return secureResponse(response);
}
function needsRedirect(req: Request): boolean {
  return req.method === "GET" && (req.headers.get("Accept") || "").includes("text/html");
}
async function upstream(request: Request, env: GatewayEnv, session: StoredSession): Promise<Response> {
  const headers = new Headers(request.headers);
  for (const key of [...headers.keys()]) {
    if (key.toLowerCase().startsWith("x-nathan-") || key.toLowerCase().startsWith("cf-access-")) headers.delete(key);
  }
  headers.delete("Cookie");
  headers.delete("Authorization");
  headers.set("X-Nathan-Subject", session.subject);
  if (session.email) headers.set("X-Nathan-Email", session.email);
  headers.set("X-Nathan-Application", env.APPLICATION_ID);
  const proxied = new Request(request, { headers });
  // The upstream Worker must have no public routes, workers.dev hostname or preview URL.
  return env.UPSTREAM.fetch(proxied);
}
export default {
  async fetch(request: Request, env: GatewayEnv): Promise<Response> {
    try {
      const expected = origin(env);
      const url = new URL(request.url);
      if (url.origin !== expected) return errorResponse(421, "Misdirected request");
      if (url.pathname === "/__nathan/health") return Response.json({ ok: true });
      if (url.pathname === "/__nathan/login" && request.method === "GET") return beginLogin(url, env);
      if (url.pathname === "/__nathan/callback" && request.method === "GET") return completeLogin(url, request, env);
      if (url.pathname === "/__nathan/logout" && request.method === "POST") return logout(request, env);
      if (url.pathname === "/__nathan/backchannel" && request.method === "POST") return handleBackchannelLogout(request, env);
      if (url.pathname.startsWith("/__nathan/")) return errorResponse(404, "Not found");
      if (!isAllowedUnsafeRequest(request.method,request.headers.get("Origin"),expected,request.headers.get("Sec-Fetch-Site")))
        return errorResponse(403, "Cross-origin state-changing request denied");
      const session = await currentSession(request, env);
      if (!session) {
        if (needsRedirect(request)) return Response.redirect(expected + "/__nathan/login?returnTo=" + encodeURIComponent(url.pathname + url.search), 302);
        return errorResponse(401, "Authentication required");
      }
      if (env.REQUIRE_AAL2 === "true" && !(env.ACCEPTED_ACRS || "").split(",").includes(session.acr || "")) {
        return errorResponse(403, "Insufficient authentication assurance");
      }
      return upstream(request, env, session);
    } catch {
      return errorResponse(503, "Access verification temporarily unavailable");
    }
  },
  async scheduled(_event: ScheduledEvent, env: GatewayEnv): Promise<void> {
    // TTL alone is not sufficient; remove expired opaque sessions and consumed logout JTIs.
    await env.SESSIONS.batch([
      env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE expires_at <= unixepoch()"),
      env.SESSIONS.prepare("DELETE FROM nathan_gateway_logout_jti WHERE exp <= unixepoch()")
    ]);
  }
};
