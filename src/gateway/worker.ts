import { serveUiAsset } from "../ui/assets.ts";
import { renderGatewayError } from "../ui/pages/gateway/GatewayErrorPage.tsx";
import { parseCookie, makeCookie, safeReturnPath, constantTimeEqual, validateIssuer, isAllowedUnsafeRequest, redirectWithCookies } from "../shared/security.mjs";
import { randomId, seal, unseal, sha256 } from "./crypto";
import { discover, authorizeUrl, exchangeCode, verifyIdToken } from "./oidc";
import type { GatewayEnv } from "./env";
import { handleBackchannelLogout } from "./backchannel";
import { signPrincipal, principalKey, PRINCIPAL_HEADER } from "../shared/principal.mjs";
import type { AccessDecision } from "./env";

const SESSION_COOKIE = "__Host-nathan-session";
const FLOW_COOKIE = "__Host-nathan-flow";
const FLOW_SECONDS = 300;
type Flow = { state: string; nonce: string; verifier: string; returnTo: string; expiresAt: number; logoutSequence?: number };
type StoredSession = { subject: string; email: string | null; sessionIdHash: string; expiresAt: number; acr: string | null; authTime: number | null; issuer: string; sid?: string | null };

function origin(env: GatewayEnv) {
  const u = new URL(env.PUBLIC_ORIGIN);
  if (u.protocol !== "https:" || u.pathname !== "/" || u.search || u.hash) throw Error("PUBLIC_ORIGIN must be a bare HTTPS origin");
  validateIssuer(env.NATHAN_ISSUER);
  if (!env.OIDC_CLIENT_ID || !env.OIDC_CLIENT_SECRET || !env.SESSION_ENCRYPTION_KEY) throw Error("Missing gateway secret or OAuth client credentials");
  return u.origin;
}
/** A top-level browser navigation, which gets the Kumo error page rather than plain text. */
function wantsHtml(request?: Request): boolean {
  return !!request && (request.method === "GET" || request.method === "HEAD") && (request.headers.get("Accept") || "").includes("text/html");
}
/** Same-origin "Try again" target that restarts login and comes back to `returnTo`. */
function loginRetry(returnTo = "/"): string {
  return "/__nathan/login?returnTo=" + encodeURIComponent(safeReturnPath(returnTo));
}
/**
 * NATH-40: browser navigations get a Kumo page (src/ui/pages/gateway/), built only from the
 * gateway's own /__nathan/ui/ assets; every other client gets exactly the plain-text body as before.
 * If the page cannot be rendered, the plain-text response is still returned (fail closed, same status).
 */
function errorResponse(status: number, message: string, request?: Request, retry?: string): Response {
  if (wantsHtml(request)) {
    try { return renderGatewayError({ status, message, retry }); } catch { /* plain text below */ }
  }
  return new Response(message, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}
function secureResponse(response: Response) {
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "same-origin");
  return response;
}
function cleared(response: Response): Response {
  response.headers.append("Set-Cookie", makeCookie(FLOW_COOKIE, "", { deleteCookie: true }));
  return secureResponse(response);
}
async function beginLogin(url: URL, env: GatewayEnv) {
  const meta = await discover(env);
  // A sequence orders same-second logins against a subject logout from an issuer without toe.
  const logoutSequence = await env.SESSIONS.prepare(
    "SELECT coalesce(max(sequence),0) AS sequence FROM nathan_gateway_logout_receipts"
  ).first<number>("sequence");
  const flow: Flow = {
    state: randomId(), nonce: randomId(), verifier: randomId(),
    returnTo: safeReturnPath(url.searchParams.get("returnTo") || "/"),
    expiresAt: Date.now() + FLOW_SECONDS * 1000, logoutSequence: logoutSequence ?? 0
  };
  const loginUrl = await authorizeUrl(env, meta, flow.state, flow.nonce, flow.verifier);
  const response = redirectWithCookies(loginUrl, 302,
    [makeCookie(FLOW_COOKIE, await seal(flow, env.SESSION_ENCRYPTION_KEY), { maxAge: FLOW_SECONDS })]);
  return secureResponse(response);
}
async function completeLogin(url: URL, request: Request, env: GatewayEnv): Promise<Response> {
  const encrypted = parseCookie(request.headers.get("Cookie"), FLOW_COOKIE);
  const flow = encrypted && await unseal<Flow>(encrypted, env.SESSION_ENCRYPTION_KEY);
  if (!flow || !Number.isSafeInteger(flow.expiresAt) || flow.expiresAt < Date.now()
      || !constantTimeEqual(url.searchParams.get("state") || "", flow.state))
    return cleared(errorResponse(400, "Login state invalid or expired. Please try again.", request, loginRetry()));
  if (url.searchParams.has("error")) return cleared(errorResponse(401, "Identity provider rejected login", request, loginRetry(flow.returnTo)));
  const code = url.searchParams.get("code");
  if (!code || code.length > 4096) return cleared(errorResponse(400, "Missing authorization code", request, loginRetry(flow.returnTo)));
  try {
    const meta = await discover(env);
    const token = await exchangeCode(env, meta, code, flow.verifier);
    const id = await verifyIdToken(env, meta, token.id_token, flow.nonce);
    const handle = randomId();
    const hash = await sha256(handle);
    const requestedTtl = Number(env.SESSION_TTL_SECONDS || "28800");
    if (!Number.isSafeInteger(requestedTtl) || requestedTtl < 300 || requestedTtl > 28800)
      throw new Error("Invalid gateway session lifetime");
    const ttl = requestedTtl;
    const expiresAt = Math.floor(Date.now() / 1000) + ttl;
    const issuedAt = id.iat ?? (flow.expiresAt / 1000 - FLOW_SECONDS);
    if (!Number.isFinite(issuedAt) || issuedAt < 0) throw Error("Invalid ID token issue time");
    // If logout committed first, the guarded write cannot restore access. If this write
    // committed first, the logout transaction sees this row and deletes it.
    const inserted = await env.SESSIONS.prepare(`
      INSERT INTO nathan_gateway_sessions(id_hash,subject,email,issuer,client_id,acr,auth_time,sid,expires_at,issued_at)
      SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 WHERE ?11>unixepoch('subsec')*1000
      AND NOT EXISTS (
        SELECT 1 FROM nathan_gateway_logout_receipts WHERE issuer=?4 AND client_id=?5 AND sid=?8 AND exp>unixepoch()
      )
      AND NOT EXISTS (
        SELECT 1 FROM nathan_gateway_logout_receipts WHERE issuer=?4 AND client_id=?5 AND sid IS NULL
        AND subject=?2 AND exp>unixepoch() AND (event_time>=?10 OR (event_time IS NULL AND sequence>?12))
      )
    `).bind(hash, id.sub, id.email_verified === true && typeof id.email === "string" ? id.email : null, meta.issuer, env.OIDC_CLIENT_ID,
      typeof id.acr === "string" ? id.acr : null, typeof id.auth_time === "number" ? id.auth_time : null, typeof id.sid === "string" ? id.sid : null,
      expiresAt, Math.floor(issuedAt), flow.expiresAt, flow.logoutSequence ?? 0).run();
    if (inserted.meta.changes !== 1)
      return cleared(errorResponse(401, "This sign-in has ended. Please try again.", request, loginRetry(flow.returnTo)));
    const response = redirectWithCookies(origin(env) + flow.returnTo, 303, [makeCookie(SESSION_COOKIE, handle, { maxAge: ttl })]);
    return cleared(response);
  } catch {
    return cleared(errorResponse(401, "Login validation failed. Please retry or contact your administrator.", request, loginRetry(flow.returnTo)));
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
/**
 * NATH-13: effective access for a session, resolved by the identity Worker's evaluator over the
 * NATHAN service binding and reused for at most ACCESS_CACHE_TTL_SECONDS (<= 60) in this isolate,
 * so a revoked grant, blocked user or disabled app takes effect within that window.
 */
const accessCache = new Map<string, { expiresAt: number; decision: AccessDecision }>();
const ACCESS_CACHE_LIMIT = 5000;
function accessTtl(env: GatewayEnv): number {
  const ttl = Number(env.ACCESS_CACHE_TTL_SECONDS ?? "30");
  if (!Number.isSafeInteger(ttl) || ttl < 0 || ttl > 60) throw Error("ACCESS_CACHE_TTL_SECONDS must be 0..60");
  return ttl;
}
async function resolveAccess(env: GatewayEnv, session: StoredSession): Promise<AccessDecision> {
  if (!env.NATHAN) throw Error("NATHAN service binding missing");
  const ttl = accessTtl(env);
  const key = env.APPLICATION_ID + "|" + session.sessionIdHash;
  const now = Date.now();
  const cached = accessCache.get(key);
  if (cached && cached.expiresAt > now) return cached.decision;
  accessCache.delete(key);
  const result = await env.NATHAN.resolveAccess({ applicationId: env.APPLICATION_ID, subject: session.subject });
  // The binding must be pinned to this gateway's application (props.applicationId); otherwise every
  // answer is a deny. Surface that misconfiguration as 503 rather than a silent 403 for everyone.
  if (result?.reason === "binding_not_pinned" || result?.reason === "application_mismatch")
    throw Error("NATHAN binding is not pinned to APPLICATION_ID");
  const decision: AccessDecision = {
    allowed: result?.allowed === true,
    roles: Array.isArray(result?.roles) ? [...result.roles] : [],
    permissions: Array.isArray(result?.permissions) ? [...result.permissions] : []
  };
  if (ttl > 0) {
    if (accessCache.size >= ACCESS_CACHE_LIMIT) accessCache.delete(accessCache.keys().next().value as string);
    accessCache.set(key, { expiresAt: now + ttl * 1000, decision });
  }
  return decision;
}
async function upstream(request: Request, env: GatewayEnv, session: StoredSession): Promise<Response> {
  // Configuration is checked before any decision, so a misconfigured gateway is a 503 for everyone.
  if (!env.NATHAN_PRINCIPAL_KEY) throw Error("NATHAN_PRINCIPAL_KEY missing");
  principalKey(env.NATHAN_PRINCIPAL_KEY);
  const access = await resolveAccess(env, session);
  if (!access.allowed) return errorResponse(403, "Access denied. Ask an administrator for a role in this application.", request);
  const principal = await signPrincipal({
    sub: session.subject, email: session.email, app: env.APPLICATION_ID, roles: access.roles, permissions: access.permissions
  }, { key: env.NATHAN_PRINCIPAL_KEY, issuer: origin(env) });
  const headers = new Headers(request.headers);
  for (const key of [...headers.keys()]) {
    if (key.toLowerCase().startsWith("x-nathan-") || key.toLowerCase().startsWith("cf-access-")) headers.delete(key);
  }
  headers.delete("Cookie");
  headers.delete("Authorization");
  headers.set("X-Nathan-Subject", session.subject);
  if (session.email) headers.set("X-Nathan-Email", session.email);
  headers.set("X-Nathan-Application", env.APPLICATION_ID);
  // The only header upstreams should trust: verify it with the SDK's nathan(request, env).
  headers.set(PRINCIPAL_HEADER, principal);
  const proxied = new Request(request, { headers });
  // The upstream Worker must have no public routes, workers.dev hostname or preview URL.
  const upstreamResponse=await env.UPSTREAM.fetch(proxied);
  const response=new Response(upstreamResponse.body,upstreamResponse);
  response.headers.set("Cache-Control","private, no-store");
  response.headers.set("Referrer-Policy","same-origin");
  response.headers.set("X-Content-Type-Options","nosniff");
  return response;
}
export default {
  async fetch(request: Request, env: GatewayEnv): Promise<Response> {
    try {
      const expected = origin(env);
      const url = new URL(request.url);
      if (url.origin !== expected) return errorResponse(421, "Misdirected request");
      if (url.pathname === "/__nathan/health") return Response.json({ ok: true });
      // NATH-32: the gateway's own Kumo pages load their hashed assets from here, never the upstream.
      const uiAsset = serveUiAsset(request);
      if (uiAsset) return uiAsset;
      if (url.pathname === "/__nathan/login" && request.method === "GET") return await beginLogin(url, env);
      if (url.pathname === "/__nathan/callback" && request.method === "GET") return completeLogin(url, request, env);
      if (url.pathname === "/__nathan/logout" && request.method === "POST") return logout(request, env);
      if (url.pathname === "/__nathan/backchannel" && request.method === "POST") return handleBackchannelLogout(request, env);
      if (url.pathname.startsWith("/__nathan/")) return errorResponse(404, "Not found", request);
      if (!isAllowedUnsafeRequest(request.method,request.headers.get("Origin"),expected,request.headers.get("Sec-Fetch-Site")))
        return errorResponse(403, "Cross-origin state-changing request denied");
      const session = await currentSession(request, env);
      if (!session) {
        if (needsRedirect(request)) return Response.redirect(expected + "/__nathan/login?returnTo=" + encodeURIComponent(url.pathname + url.search), 302);
        return errorResponse(401, "Authentication required");
      }
      if (env.REQUIRE_AAL2 === "true" && !(env.ACCEPTED_ACRS || "").split(",").includes(session.acr || "")) {
        return errorResponse(403, "Insufficient authentication assurance", request, loginRetry(url.pathname + url.search));
      }
      // Awaited so that any failure (RPC, signing, upstream) fails closed with the 503 below.
      return await upstream(request, env, session);
    } catch {
      const { pathname, search } = new URL(request.url);
      return errorResponse(503, "Access verification temporarily unavailable", request,
        pathname.startsWith("/__nathan/") ? undefined : pathname + search);
    }
  },
  async scheduled(_event: ScheduledEvent, env: GatewayEnv): Promise<void> {
    await env.SESSIONS.batch([
      env.SESSIONS.prepare("DELETE FROM nathan_gateway_sessions WHERE expires_at <= unixepoch()"),
      env.SESSIONS.prepare("DELETE FROM nathan_gateway_logout_jti WHERE exp <= unixepoch()"),
      env.SESSIONS.prepare("DELETE FROM nathan_gateway_logout_receipts WHERE exp <= unixepoch()")
    ]);
  }
};
