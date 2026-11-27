/**
 * NATH-14: Nathan's authorization server for remote MCP servers (MCP authorization 2025-11-25),
 * modeled on ForgeGraph FORGE-396/FORGE-401.
 *
 * Why Nathan-owned and not Better Auth's oauth-provider (1.7.14): its scope list is static
 * configuration validated at authorize and registration; /oauth2/consent accepts only a subset of
 * the originally requested scopes (a user cannot add one); a refresh `scope` outside the grant is an
 * error instead of an intersection, and `resource` is optional on refresh; there is no hook to cap
 * the issued `scope` by the user's current app permissions; and Client ID Metadata Documents need
 * the separate @better-auth/cimd plugin. Its DB-backed resources can hold per-app audiences, but
 * not per-app scope catalogs with consent semantics. So this layer owns clients, consent, grants,
 * codes and refresh tokens, and issues access tokens with Better Auth's JWT plugin keys as Nathan's
 * token issuer (`<origin>/api/auth`), so they are the same NATH-15 RFC 9068 tokens Gatekeeper and
 * every Nathan SDK already verify (principal_kind `agent`).
 *
 * Endpoints (issuer `<origin>/mcp-oauth`):
 *   GET  /.well-known/oauth-authorization-server/mcp-oauth  RFC 8414 metadata
 *   POST /mcp-oauth/register     RFC 7591 public-client registration (rate-limited, expiring)
 *   GET  /mcp-oauth/authorize    validation, sign-in, script-free consent page with a single-use ticket
 *   POST /mcp-oauth/authorize    consent answer (same-origin, ticket bound to the browser session)
 *   POST /mcp-oauth/token        authorization_code (S256 PKCE) and rotating refresh_token; resource required
 *   POST /mcp-oauth/revoke       RFC 7009; revokes the whole grant
 *   POST /mcp-oauth/grant        token-authenticated grant check for Workers without a service binding
 *   GET/POST /connections        the user's MCP connections: edit scopes, disconnect
 */
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { signJWT } from "better-auth/plugins/jwt";
import type { AuthEnv } from "./env";
import { audit, isAdminPrincipal } from "./admin-service";
import { allowRequests } from "./request-limit";
import { resolveAccess } from "./rbac";
import { rolesClaim, validateAudience } from "../shared/token-claims.mjs";
import { planMcpRegister, planMcpStatus, committedStatements } from "../shared/admin-ops.mjs";
import { makeCookie, parseCookie, safeReturnPath, constantTimeEqual, redirectWithCookies } from "../shared/security.mjs";
import {
  buildCatalog, parseRequestedScopes, concreteScopes, parseGrant, offeredScopes, selectScopes, effectiveScopes,
  scopeString, narrowScopes, parseRegistration, ScopeError,
  MCP_ACCESS_TOKEN_SECONDS, MCP_GRANT_SECONDS, MCP_CODE_SECONDS, MCP_TICKET_SECONDS, MCP_CLIENT_SECONDS,
  MCP_UNUSED_CLIENT_SECONDS, MCP_UNUSED_CLIENT_LIMIT, MCP_DAILY_REGISTRATIONS_PER_ADDRESS
} from "../shared/mcp-scopes.mjs";
import { consentPage, connectionsPage, mcpErrorPage } from "./mcp-pages.tsx";

export const MCP_AS_PATH = "/mcp-oauth";
const METADATA_PATH = "/.well-known/oauth-authorization-server" + MCP_AS_PATH;
const RETURN_COOKIE = "__Host-nathan-mcp-return";
const JSON_HEADERS = { "Cache-Control": "no-store", Pragma: "no-cache", "X-Content-Type-Options": "nosniff" };

type Catalog = ReturnType<typeof buildCatalog>;
type ResourceRow = { identifier: string; app_id: string; name: string; full_scope: string | null; aliases: string; enabled: number };
type ClientRow = { client_id: string; client_name: string; redirect_uris: string; expires_at: number };
type GrantRow = { id: string; user_id: string; client_id: string; resource: string; scope: string; created_at: number; expires_at: number };

const originOf = (env: AuthEnv) => new URL(env.NATHAN_ISSUER).origin;
export const mcpIssuer = (env: AuthEnv) => originOf(env) + MCP_AS_PATH;
const tokenIssuer = (env: AuthEnv) => originOf(env) + "/api/auth";
const nowSeconds = () => Math.floor(Date.now() / 1000);

class OAuthFail extends Error {
  constructor(readonly error: string, message: string, readonly status = 400, readonly headers: Record<string, string> = {}) { super(message); }
}
function oauthJson(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(body, { status, headers: { ...JSON_HEADERS, ...extra } });
}
function oauthErrorResponse(e: unknown) {
  if (e instanceof OAuthFail) return oauthJson({ error: e.error, error_description: e.message }, e.status, e.headers);
  if (e instanceof ScopeError) return oauthJson({ error: (e as any).code ?? "invalid_scope", error_description: e.message }, 400);
  return oauthJson({ error: "server_error", error_description: "Request failed" }, 500);
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
async function sha256(value: string) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
const pkceChallenge = sha256;

const allow = (env: AuthEnv, name: string, subject: string, limit: number, windowSeconds = 60) =>
  allowRequests(env, "mcp-oauth:" + name, subject, limit, windowSeconds);
const clientIp = (request: Request) => request.headers.get("cf-connecting-ip") ?? "unknown";
function tooMany() { return oauthJson({ error: "slow_down", error_description: "Too many requests" }, 429, { "Retry-After": "60" }); }

/** Form body with every parameter exactly once (duplicates never let parser order decide). */
async function formParams(request: Request, max = 16384) {
  if (request.headers.get("Content-Type")?.split(";")[0].trim() !== "application/x-www-form-urlencoded")
    throw new OAuthFail("invalid_request", "Use application/x-www-form-urlencoded");
  const raw = await request.text();
  if (raw.length > max) throw new OAuthFail("invalid_request", "Request too large");
  return new URLSearchParams(raw);
}
function single(params: URLSearchParams, allowRepeated: string[] = []) {
  for (const key of new Set(params.keys()))
    if (!allowRepeated.includes(key) && params.getAll(key).length !== 1) throw new OAuthFail("invalid_request", "Duplicate parameter " + key.slice(0, 40));
}
function required(params: URLSearchParams, name: string, max = 2048) {
  const value = params.get(name);
  if (!value || value.length > max) throw new OAuthFail("invalid_request", "Missing or invalid " + name);
  return value;
}

// ---- storage -------------------------------------------------------------------------------------

async function loadResource(env: AuthEnv, identifier: unknown): Promise<ResourceRow | null> {
  if (typeof identifier !== "string" || identifier.length > 512) return null;
  return env.DB.prepare("SELECT identifier, app_id, name, full_scope, aliases, enabled FROM nathan_mcp_resources WHERE identifier=? LIMIT 1")
    .bind(identifier).first<ResourceRow>();
}
async function loadCatalog(env: AuthEnv, resource: ResourceRow): Promise<Catalog> {
  const [permissions, metadata] = (await env.DB.batch([
    env.DB.prepare("SELECT key, description FROM nathan_rbac_permissions WHERE app_id=? ORDER BY key LIMIT 500").bind(resource.app_id),
    env.DB.prepare("SELECT scope, label, description, group_key AS \"group\", requires, sensitive, admin_only AS adminOnly FROM nathan_mcp_scopes WHERE resource=?").bind(resource.identifier)
  ])).map(r => (r.results ?? []) as any[]);
  let aliases: Record<string, string[]> = {};
  try { aliases = JSON.parse(resource.aliases || "{}"); } catch { aliases = {}; }
  return buildCatalog({
    full: resource.full_scope, aliases, permissions,
    metadata: metadata.map(m => {
      let requires: string[] = [];
      try { requires = JSON.parse(m.requires || "[]"); } catch { requires = []; }
      return { scope: m.scope, label: m.label, description: m.description, group: m.group, requires, sensitive: m.sensitive === 1, adminOnly: m.adminOnly === 1 };
    })
  });
}
async function loadClient(env: AuthEnv, clientId: unknown): Promise<(ClientRow & { redirects: string[] }) | null> {
  if (typeof clientId !== "string" || !/^nmcp_[A-Za-z0-9_-]{20,80}$/.test(clientId)) return null;
  const row = await env.DB.prepare("SELECT client_id, client_name, redirect_uris, expires_at FROM nathan_mcp_clients WHERE client_id=? AND expires_at>unixepoch() LIMIT 1")
    .bind(clientId).first<ClientRow>();
  if (!row) return null;
  let redirects: string[] = [];
  try { redirects = JSON.parse(row.redirect_uris); } catch { return null; }
  return { ...row, redirects };
}
/** The user's permissions on the resource's app now (NATH-13 evaluator), and administrator status when it matters. */
async function userPermissions(env: AuthEnv, catalog: Catalog, appId: string, userId: string) {
  const access = await resolveAccess(env, appId, userId);
  let admin = false;
  if (access.allowed && catalog.entries.some(e => e.adminOnly)) {
    const u = await env.DB.prepare('SELECT "id","email","emailVerified","role","banned" FROM "user" WHERE "id"=? LIMIT 1')
      .bind(userId).first<{ id: string; email: string; emailVerified: number; role: string; banned: number }>();
    admin = Boolean(u && u.banned !== 1 && await isAdminPrincipal({ id: u.id, email: u.email, emailVerified: u.emailVerified === 1, role: u.role }, env));
  }
  return { access, permissions: new Set(access.allowed ? access.permissions : []), admin };
}
async function putArtifact(env: AuthEnv, secret: string, kind: string, data: unknown, seconds: number, grantId: string | null = null) {
  await env.DB.prepare("INSERT INTO nathan_mcp_artifacts(hash,kind,grant_id,data,expires_at) VALUES (?,?,?,?,?)")
    .bind(await sha256(secret), kind, grantId, JSON.stringify(data), nowSeconds() + seconds).run();
}
async function peekArtifact<T>(env: AuthEnv, secret: string, kind: string): Promise<(T & { grantId: string | null }) | null> {
  const row = await env.DB.prepare("SELECT grant_id, data FROM nathan_mcp_artifacts WHERE hash=? AND kind=? AND expires_at>unixepoch() LIMIT 1")
    .bind(await sha256(secret), kind).first<{ grant_id: string | null; data: string }>();
  return row ? { ...JSON.parse(row.data), grantId: row.grant_id } : null;
}
/** Atomic single use across isolates. */
async function takeArtifact(env: AuthEnv, secret: string, kind: string) {
  const row = await env.DB.prepare("DELETE FROM nathan_mcp_artifacts WHERE hash=? AND kind=? AND expires_at>unixepoch() RETURNING grant_id")
    .bind(await sha256(secret), kind).first<{ grant_id: string | null }>();
  return row !== null;
}
async function dropGrant(env: AuthEnv, grantId: string, actor: string, reason: string) {
  const row = await env.DB.prepare("DELETE FROM nathan_mcp_grants WHERE id=? RETURNING client_id, resource").bind(grantId).first<{ client_id: string; resource: string }>();
  if (row) await audit(env, actor, "mcp_grant_revoke", grantId + " client=" + row.client_id + " resource=" + row.resource + " reason=" + reason, "succeeded");
  return row !== null;
}

// ---- tokens --------------------------------------------------------------------------------------

async function signAccessToken(env: AuthEnv, auth: any, claims: { sub: string; clientId: string; resource: string; grantId: string; scope: string; roles?: string[] }) {
  const context = await auth.$context;
  const jwtPlugin = context.options.plugins?.find((p: any) => p.id === "jwt");
  if (!jwtPlugin) throw Error("JWT plugin unavailable");
  const iat = nowSeconds();
  return signJWT({ context } as any, {
    options: jwtPlugin.options,
    header: { typ: "at+jwt" },
    payload: {
      iss: tokenIssuer(env), sub: claims.sub, aud: claims.resource, client_id: claims.clientId, azp: claims.clientId,
      scope: claims.scope, iat, exp: iat + MCP_ACCESS_TOKEN_SECONDS, jti: randomToken(),
      principal_kind: "agent", nathan_grant: claims.grantId, ...(claims.roles ? { roles: claims.roles } : {})
    }
  } as any);
}
async function verifyAccessToken(env: AuthEnv, auth: any, token: unknown, resource: string, clockTolerance = 5) {
  if (typeof token !== "string" || token.length < 32 || token.length > 16000 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return null;
  const keys = await auth.api.getJwks();
  if (!keys || !Array.isArray(keys.keys)) return null;
  try {
    const { payload } = await jwtVerify(token, createLocalJWKSet(keys), {
      issuer: tokenIssuer(env), audience: resource, typ: "at+jwt", algorithms: ["EdDSA", "ES256", "RS256"],
      requiredClaims: ["sub", "exp", "iat", "jti", "client_id"], clockTolerance
    });
    if (payload.cnf !== undefined || payload.principal_kind !== "agent" || typeof payload.nathan_grant !== "string" ||
        typeof payload.client_id !== "string" || typeof payload.sub !== "string" || typeof payload.scope !== "string") return null;
    return payload as typeof payload & { sub: string; client_id: string; nathan_grant: string; scope: string };
  } catch { return null; }
}

type Access = Awaited<ReturnType<typeof userPermissions>>["access"];
/**
 * Signs an access token and mints the next refresh token for a grant, with scopes already capped by
 * current permissions. Nothing is stored here: the caller stores the refresh token in the same D1
 * batch that consumes the code or the previous refresh token, so a request either wins completely
 * or not at all.
 */
async function prepareTokens(env: AuthEnv, auth: any, grant: GrantRow, catalog: Catalog, scopes: Set<string>, access: Access) {
  if (!scopes.size) throw new OAuthFail("invalid_scope", "None of this connection's permissions is available to the user now");
  const scope = scopeString(catalog, scopes);
  const accessToken = await signAccessToken(env, auth, { sub: grant.user_id, clientId: grant.client_id, resource: grant.resource, grantId: grant.id, scope, roles: rolesClaim(access) });
  const refresh = "nmcp_rt_" + randomToken();
  return {
    refreshHash: await sha256(refresh),
    refreshData: JSON.stringify({ clientId: grant.client_id }),
    refreshExpires: nowSeconds() + Math.max(1, grant.expires_at - nowSeconds()),
    body: { access_token: accessToken, token_type: "Bearer", expires_in: MCP_ACCESS_TOKEN_SECONDS, refresh_token: refresh, scope }
  };
}
/** No usable scope now: never consume the code or refresh token for that. A ban is temporary, so retry later. */
function nothingUsable(access: Access): never {
  if (access.reason === "user_blocked")
    throw new OAuthFail("temporarily_unavailable", "The user cannot use this connection right now; try again later", 503, { "Retry-After": "300" });
  throw new OAuthFail("invalid_scope", "None of this connection's permissions is available to the user now");
}

async function liveGrant(env: AuthEnv, grantId: string | null) {
  if (!grantId) return null;
  return env.DB.prepare("SELECT g.id, g.user_id, g.client_id, g.resource, g.scope, g.created_at, g.expires_at FROM nathan_mcp_grants g " +
    "JOIN nathan_mcp_clients c ON c.client_id=g.client_id AND c.expires_at>unixepoch() WHERE g.id=? AND g.expires_at>unixepoch() LIMIT 1").bind(grantId).first<GrantRow>();
}
async function grantAccessNow(env: AuthEnv, grant: GrantRow, resource: ResourceRow, catalog: Catalog) {
  const { access, permissions, admin } = await userPermissions(env, catalog, resource.app_id, grant.user_id);
  return { access, scopes: effectiveScopes(catalog, parseGrant(catalog, grant.scope), permissions, { admin }) };
}
async function grantScopesNow(env: AuthEnv, grant: GrantRow, resource: ResourceRow, catalog: Catalog) {
  return (await grantAccessNow(env, grant, resource, catalog)).scopes;
}
/** A code or refresh token presented again (or by a request that lost the race for it) revokes the grant it produced. */
async function revokeOnReuse(env: AuthEnv, secret: string, kind: "used_code" | "used_refresh", clientId: string, reason: string) {
  const used = await peekArtifact<{ clientId: string }>(env, secret, kind);
  if (used?.grantId && used.clientId === clientId) await dropGrant(env, used.grantId, "mcp:" + clientId, reason);
}

async function tokenEndpoint(request: Request, env: AuthEnv, auth: any) {
  if (!await allow(env, "token", clientIp(request), 120)) return tooMany();
  const params = await formParams(request, 8192);
  single(params);
  if (params.has("client_secret") || request.headers.has("Authorization"))
    throw new OAuthFail("invalid_client", "Only public clients without a secret are supported", 401);
  const client = await loadClient(env, params.get("client_id"));
  if (!client) throw new OAuthFail("invalid_client", "Unknown or expired MCP client", 401);
  // RFC 8707: mandatory on every token request, including refresh.
  const resource = await loadResource(env, params.get("resource"));
  if (!resource || resource.enabled !== 1) throw new OAuthFail("invalid_target", "Name a registered MCP resource");
  const catalog = await loadCatalog(env, resource);
  const grantType = params.get("grant_type");

  if (grantType === "authorization_code") {
    const code = required(params, "code", 200);
    const pending = await peekArtifact<{ clientId: string; redirectUri: string; challenge: string; resource: string; userId: string; scope: string }>(env, code, "code");
    if (!pending) {
      // RFC 6749 §4.1.2: a replayed code revokes what it produced.
      await revokeOnReuse(env, code, "used_code", client.client_id, "code_replay");
      throw new OAuthFail("invalid_grant", "Invalid or used authorization code");
    }
    const verifier = params.get("code_verifier") ?? "";
    if (pending.clientId !== client.client_id || pending.redirectUri !== params.get("redirect_uri") || pending.resource !== resource.identifier ||
        !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || await pkceChallenge(verifier) !== pending.challenge)
      throw new OAuthFail("invalid_grant", "Invalid authorization code, redirect_uri, resource or PKCE verifier");
    const grant: GrantRow = { id: "nmcp_g_" + randomToken(), user_id: pending.userId, client_id: client.client_id, resource: resource.identifier,
      scope: pending.scope, created_at: nowSeconds(), expires_at: nowSeconds() + MCP_GRANT_SECONDS };
    // Permissions may have shrunk since consent; a grant that could do nothing is never created (and the code is not used up).
    const { scopes, access } = await grantAccessNow(env, grant, resource, catalog);
    if (!scopes.size) nothingUsable(access);
    const issued = await prepareTokens(env, auth, grant, catalog, scopes, access);
    // One atomic batch: the code turns into its used marker naming this request's grant, and the grant,
    // the refresh token and the audit row exist only if this request is the one that turned it.
    const codeHash = await sha256(code);
    const marker = JSON.stringify({ clientId: client.client_id, grantId: grant.id });
    const mine = "EXISTS (SELECT 1 FROM nathan_mcp_artifacts WHERE hash=? AND kind='used_code' AND data=?)";
    const created = "EXISTS (SELECT 1 FROM nathan_mcp_grants WHERE id=?)";
    const results = await env.DB.batch([
      env.DB.prepare("UPDATE nathan_mcp_artifacts SET kind='used_code', data=?, expires_at=? WHERE hash=? AND kind='code' AND expires_at>unixepoch()")
        .bind(marker, nowSeconds() + 86400, codeHash),
      env.DB.prepare("INSERT INTO nathan_mcp_grants(id,user_id,client_id,resource,scope,created_at,updated_at,expires_at) SELECT ?,?,?,?,?,?,?,? WHERE " + mine)
        .bind(grant.id, grant.user_id, grant.client_id, grant.resource, grant.scope, grant.created_at, grant.created_at, grant.expires_at, codeHash, marker),
      env.DB.prepare("UPDATE nathan_mcp_artifacts SET grant_id=? WHERE hash=? AND kind='used_code' AND data=? AND " + created)
        .bind(grant.id, codeHash, marker, grant.id),
      // From its first grant on, the client is no longer an unused registration (capped and pruned after a day).
      env.DB.prepare("UPDATE nathan_mcp_clients SET first_grant_at=unixepoch() WHERE client_id=? AND first_grant_at IS NULL AND " + created)
        .bind(client.client_id, grant.id),
      env.DB.prepare("INSERT INTO nathan_mcp_artifacts(hash,kind,grant_id,data,expires_at) SELECT ?,'refresh',?,?,? WHERE " + created)
        .bind(issued.refreshHash, grant.id, issued.refreshData, issued.refreshExpires, grant.id),
      env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) SELECT ?,?,?,?,? WHERE " + created)
        .bind(crypto.randomUUID(), grant.user_id, "mcp_grant_create", grant.id + " client=" + client.client_id + " resource=" + resource.identifier + " scope=" + grant.scope, "succeeded", grant.id)
    ]);
    if (results[1].meta.changes !== 1) {
      // Another request redeemed this code first (concurrently or before): that is a replay too.
      await revokeOnReuse(env, code, "used_code", client.client_id, "code_replay");
      throw new OAuthFail("invalid_grant", "Invalid or used authorization code");
    }
    return oauthJson(issued.body);
  }

  if (grantType === "refresh_token") {
    const token = required(params, "refresh_token", 200);
    const current = await peekArtifact<{ clientId: string }>(env, token, "refresh");
    if (!current) {
      // Rotation reuse detection: a consumed refresh token coming back revokes the grant.
      await revokeOnReuse(env, token, "used_refresh", client.client_id, "refresh_reuse");
      throw new OAuthFail("invalid_grant", "Invalid refresh token");
    }
    const grant = await liveGrant(env, current.grantId);
    if (!grant || current.clientId !== client.client_id || grant.client_id !== client.client_id) throw new OAuthFail("invalid_grant", "Invalid refresh token");
    if (grant.resource !== resource.identifier) throw new OAuthFail("invalid_target", "The refresh token belongs to another resource");
    // The grant's scopes now (the user may have edited them, or lost permissions), optionally narrowed.
    // Every refusal here comes before the refresh token is used up.
    const now = await grantAccessNow(env, grant, resource, catalog);
    if (!now.scopes.size) nothingUsable(now.access);
    let scopes = now.scopes;
    if (params.has("scope")) {
      const narrowed = narrowScopes(catalog, params.get("scope") ?? "", scopes);
      if (!narrowed) throw new OAuthFail("invalid_scope", "Unknown scope requested");
      if (!narrowed.size) throw new OAuthFail("invalid_scope", "The grant no longer holds any requested scope");
      scopes = narrowed;
    }
    const issued = await prepareTokens(env, auth, grant, catalog, scopes, now.access);
    // One atomic batch: the token turns into its used marker (unique to this request) and the next
    // refresh token exists only if this request is the one that turned it.
    const tokenHash = await sha256(token);
    const marker = JSON.stringify({ clientId: client.client_id, next: issued.refreshHash });
    const results = await env.DB.batch([
      env.DB.prepare("UPDATE nathan_mcp_artifacts SET kind='used_refresh', data=?, expires_at=? WHERE hash=? AND kind='refresh' AND expires_at>unixepoch()")
        .bind(marker, nowSeconds() + Math.max(1, grant.expires_at - nowSeconds()), tokenHash),
      env.DB.prepare("INSERT INTO nathan_mcp_artifacts(hash,kind,grant_id,data,expires_at) SELECT ?,'refresh',?,?,? " +
        "WHERE EXISTS (SELECT 1 FROM nathan_mcp_artifacts WHERE hash=? AND kind='used_refresh' AND data=?) AND EXISTS (SELECT 1 FROM nathan_mcp_grants WHERE id=?)")
        .bind(issued.refreshHash, grant.id, issued.refreshData, issued.refreshExpires, tokenHash, marker, grant.id)
    ]);
    if (results[1].meta.changes !== 1) {
      // Another request used this refresh token first (concurrently or before): reuse revokes the grant.
      await revokeOnReuse(env, token, "used_refresh", client.client_id, "refresh_reuse");
      throw new OAuthFail("invalid_grant", "Invalid refresh token");
    }
    return oauthJson(issued.body);
  }
  throw new OAuthFail("unsupported_grant_type", "Use authorization_code or refresh_token");
}

/**
 * The authoritative check behind a Worker's `user.can(scope)`: the token verifies, its grant is live,
 * and the scopes are the token's ∩ the grant's now ∩ the user's current permissions.
 */
export async function mcpGrantStatus(env: AuthEnv, auth: any, token: unknown, resourceId: unknown, pinnedApp?: string) {
  const inactive = { active: false as const };
  const resource = await loadResource(env, resourceId);
  if (!resource || resource.enabled !== 1 || (pinnedApp !== undefined && resource.app_id !== pinnedApp)) return inactive;
  const payload = await verifyAccessToken(env, auth, token, resource.identifier);
  if (!payload) return inactive;
  const grant = await liveGrant(env, payload.nathan_grant);
  if (!grant || grant.user_id !== payload.sub || grant.client_id !== payload.client_id || grant.resource !== resource.identifier) return inactive;
  const catalog = await loadCatalog(env, resource);
  const now = await grantScopesNow(env, grant, resource, catalog);
  const tokenScopes = new Set(payload.scope.split(" ").filter(Boolean));
  const scopes = new Set([...now].filter(s => tokenScopes.has(s)));
  if (!scopes.size) return inactive;
  return { active: true as const, sub: grant.user_id, clientId: grant.client_id, grantId: grant.id, resource: resource.identifier,
    scope: scopeString(catalog, scopes), scopes: scopeString(catalog, scopes).split(" "), exp: payload.exp, principalKind: "agent" };
}

// ---- browser flow --------------------------------------------------------------------------------

function errorRedirect(env: AuthEnv, redirectUri: string, state: string | null, error: string, description: string) {
  const target = new URL(redirectUri);
  target.searchParams.set("error", error);
  target.searchParams.set("error_description", description);
  if (state !== null) target.searchParams.set("state", state);
  target.searchParams.set("iss", mcpIssuer(env));
  return redirectWithCookies(target.href, 302);
}
function encodeReturn(path: string) { return btoa(path).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""); }
function signInRedirect(env: AuthEnv, returnPath: string) {
  return redirectWithCookies(originOf(env) + "/sign-in", 302, [makeCookie(RETURN_COOKIE, encodeReturn(returnPath), { maxAge: 600 })]);
}
/** After sign-in Nathan lands on `/`: continue a pending MCP authorization or the connections page. */
export async function mcpReturnRedirect(request: Request, env: AuthEnv, auth: any): Promise<Response | null> {
  const value = parseCookie(request.headers.get("Cookie"), RETURN_COOKIE);
  if (!value || !/^[A-Za-z0-9_-]{1,3000}$/.test(value)) return null;
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session?.user?.id) return null;
  let path = "/";
  try { path = safeReturnPath(atob(value.replaceAll("-", "+").replaceAll("_", "/"))); } catch { path = "/"; }
  const clear = makeCookie(RETURN_COOKIE, "", { deleteCookie: true });
  if (!path.startsWith(MCP_AS_PATH + "/authorize?") && path !== "/connections") return redirectWithCookies(originOf(env) + "/sign-in", 302, [clear]);
  return redirectWithCookies(originOf(env) + path, 302, [clear]);
}

type Ticket = { clientId: string; clientName: string; redirectUri: string; challenge: string; state: string | null; resource: string;
  requested: string[]; userId: string; sessionId: string };

async function consentView(env: AuthEnv, ticket: string, data: Ticket, email: string, checked: Set<string>, error?: string) {
  const resource = await loadResource(env, data.resource);
  if (!resource || resource.enabled !== 1) return null;
  const catalog = await loadCatalog(env, resource);
  const { permissions, admin } = await userPermissions(env, catalog, resource.app_id, data.userId);
  const offered = offeredScopes(catalog, permissions, { admin });
  const requested = new Set(data.requested);
  return {
    view: {
      ticket, clientName: data.clientName, clientId: data.clientId, redirectOrigin: new URL(data.redirectUri).origin,
      resourceName: resource.name, resource: resource.identifier, email, entries: catalog.entries, byScope: catalog.byScope,
      full: catalog.full, offered, checked: new Set([...checked].filter(s => offered.has(s) || s === catalog.full)),
      unavailable: [...requested].filter(s => !offered.has(s) && s !== catalog.full), error,
      issuer: new URL(env.NATHAN_ISSUER).host
    }, catalog, offered
  };
}

async function authorizeGet(request: Request, env: AuthEnv, auth: any, url: URL) {
  const params = url.searchParams;
  try { single(params); } catch { return mcpErrorPage("Invalid request", "Every authorization parameter must appear once."); }
  const client = await loadClient(env, params.get("client_id"));
  if (!client) return mcpErrorPage("Unknown client", "This MCP client is not registered or its registration expired.");
  const redirectUri = params.get("redirect_uri") ?? "";
  if (!client.redirects.includes(redirectUri)) return mcpErrorPage("Invalid redirect", "The redirect URI is not registered for this client.");
  // From here errors go back to the exact registered redirect URI (RFC 6749 §4.1.2.1).
  const state = params.get("state");
  if (state !== null && state.length > 2048) return errorRedirect(env, redirectUri, null, "invalid_request", "state too long");
  if (params.get("response_type") !== "code") return errorRedirect(env, redirectUri, state, "unsupported_response_type", "Only code is supported");
  const challenge = params.get("code_challenge") ?? "";
  if (params.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge))
    return errorRedirect(env, redirectUri, state, "invalid_request", "S256 PKCE is required");
  const resource = await loadResource(env, params.get("resource"));
  if (!resource || resource.enabled !== 1) return errorRedirect(env, redirectUri, state, "invalid_target", "Name a registered MCP resource");
  const catalog = await loadCatalog(env, resource);
  const requested = parseRequestedScopes(catalog, params.get("scope"));
  if (!requested) return errorRedirect(env, redirectUri, state, "invalid_scope", "A requested scope is not offered by this MCP server");

  const session = await auth.api.getSession({ headers: request.headers });
  if (!session?.user?.id || !session.session?.id) return signInRedirect(env, url.pathname + url.search);
  if (!await allow(env, "consent", session.user.id, 30)) return mcpErrorPage("Too many requests", "Wait a minute and try again.", 429);
  const { access, permissions, admin } = await userPermissions(env, catalog, resource.app_id, session.user.id);
  const offered = offeredScopes(catalog, permissions, { admin });
  if (!access.allowed || !offered.size) return errorRedirect(env, redirectUri, state, "access_denied", "The user has no permissions on this MCP server");

  const ticket = "nmcp_ct_" + randomToken();
  const data: Ticket = { clientId: client.client_id, clientName: client.client_name, redirectUri, challenge, state, resource: resource.identifier,
    requested: [...requested], userId: session.user.id, sessionId: session.session.id };
  await putArtifact(env, ticket, "consent", data, MCP_TICKET_SECONDS);
  const built = await consentView(env, ticket, data, session.user.email, requested);
  if (!built) return mcpErrorPage("Unavailable", "This MCP server is not available.");
  return consentPage(built.view);
}

async function authorizePost(request: Request, env: AuthEnv, auth: any) {
  const origin = originOf(env);
  if (request.headers.get("Origin") !== origin || request.headers.get("Sec-Fetch-Site") === "cross-site")
    return mcpErrorPage("Request refused", "Consent must be answered on this sign-in page.", 403);
  let form: URLSearchParams;
  try { form = await formParams(request); single(form, ["scope"]); } catch { return mcpErrorPage("Invalid request", "The consent form was malformed."); }
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session?.user?.id || !session.session?.id) return mcpErrorPage("Signed out", "Sign in again and restart the connection from your client.", 401);
  if (!await allow(env, "consent", session.user.id, 30)) return mcpErrorPage("Too many requests", "Wait a minute and try again.", 429);
  const ticket = form.get("ticket") ?? "";
  const data = /^nmcp_ct_[A-Za-z0-9_-]{43}$/.test(ticket) ? await peekArtifact<Ticket>(env, ticket, "consent") : null;
  // The ticket is single-use and bound to the user and browser session that saw the page.
  if (!data || data.userId !== session.user.id || data.sessionId !== session.session.id)
    return mcpErrorPage("Consent expired", "This consent page expired, was already answered, or belongs to another sign-in session.");
  const decision = form.get("decision");
  if (decision !== "allow" && decision !== "deny") return mcpErrorPage("Invalid request", "Choose Allow or Deny.");
  if (decision === "deny") {
    if (!await takeArtifact(env, ticket, "consent")) return mcpErrorPage("Consent expired", "This consent page was already answered.");
    return errorRedirect(env, data.redirectUri, data.state, "access_denied", "The user denied access");
  }
  const chosen = form.getAll("scope");
  const built = await consentView(env, ticket, data, session.user.email, new Set(chosen));
  if (!built) return mcpErrorPage("Unavailable", "This MCP server is not available.");
  let stored: string;
  try { stored = selectScopes(built.catalog, chosen, built.offered).stored; }
  catch (e) {
    // An empty or invalid selection re-renders the page and keeps the ticket usable.
    return consentPage({ ...built.view, error: e instanceof Error ? e.message : "Invalid scope selection" }, 400);
  }
  const code = "nmcp_ac_" + randomToken();
  const approval = { clientId: data.clientId, redirectUri: data.redirectUri, challenge: data.challenge,
    resource: data.resource, userId: data.userId, scope: stored };
  // A promotion or sign-out during the consent form cannot leave a new code for the retired session.
  const issued = await env.DB.prepare("UPDATE nathan_mcp_artifacts SET hash=?,kind='code',data=?,expires_at=? " +
    "WHERE hash=? AND kind='consent' AND expires_at>unixepoch() AND EXISTS(SELECT 1 FROM session WHERE id=? AND userId=?)")
    .bind(await sha256(code), JSON.stringify(approval), nowSeconds() + MCP_CODE_SECONDS, await sha256(ticket), data.sessionId, data.userId).run();
  if (!issued.meta.changes) return mcpErrorPage("Consent expired", "This consent page expired or was already answered.");
  await audit(env, data.userId, "mcp_consent", "client=" + data.clientId + " resource=" + data.resource + " scope=" + stored, "succeeded");
  const target = new URL(data.redirectUri);
  target.searchParams.set("code", code);
  if (data.state !== null) target.searchParams.set("state", data.state);
  target.searchParams.set("iss", mcpIssuer(env));
  return redirectWithCookies(target.href, 303);
}

// ---- registration, revocation, metadata ----------------------------------------------------------

async function knownScopes(env: AuthEnv) {
  const [perms, resources] = (await env.DB.batch([
    env.DB.prepare("SELECT p.key FROM nathan_rbac_permissions p JOIN nathan_mcp_resources r ON r.app_id=p.app_id LIMIT 5000"),
    env.DB.prepare("SELECT full_scope, aliases FROM nathan_mcp_resources LIMIT 500")
  ])).map(r => (r.results ?? []) as any[]);
  const out = new Set<string>(perms.map(p => p.key));
  for (const r of resources) {
    if (r.full_scope) out.add(r.full_scope);
    try { for (const a of Object.keys(JSON.parse(r.aliases || "{}"))) out.add(a); } catch {}
  }
  return out;
}
/** Deletes registrations that never obtained a grant within a day (at most `limit` per call). */
function pruneUnusedClients(env: AuthEnv, limit: number) {
  return env.DB.prepare("DELETE FROM nathan_mcp_clients WHERE client_id IN (SELECT client_id FROM nathan_mcp_clients " +
    "WHERE first_grant_at IS NULL AND created_at<? LIMIT ?)").bind(nowSeconds() - MCP_UNUSED_CLIENT_SECONDS, limit);
}
async function register(request: Request, env: AuthEnv) {
  // Every attempt counts against its address (20 a minute), valid or not.
  if (!await allow(env, "register", clientIp(request), 20)) return tooMany();
  if (request.headers.get("Content-Type")?.split(";")[0].trim() !== "application/json")
    throw new OAuthFail("invalid_client_metadata", "Send JSON client metadata");
  const raw = await request.text();
  if (raw.length > 8192) throw new OAuthFail("invalid_client_metadata", "Client metadata too large");
  let body: unknown;
  try { body = JSON.parse(raw); } catch { throw new OAuthFail("invalid_client_metadata", "Invalid JSON"); }
  const parsed = parseRegistration(body, await knownScopes(env));
  // Rotating addresses cannot fill D1: registrations without a grant are pruned after a day (here
  // opportunistically, and by the scheduled handler) and capped in number while they exist.
  const [, unused] = await env.DB.batch([
    pruneUnusedClients(env, 100),
    env.DB.prepare("SELECT count(*) AS n FROM nathan_mcp_clients WHERE first_grant_at IS NULL")
  ]);
  const waiting = Number((unused.results?.[0] as { n?: number } | undefined)?.n ?? 0);
  if (waiting >= MCP_UNUSED_CLIENT_LIMIT) {
    if (await allow(env, "register-full-audit", "all", 1, 3600))
      await audit(env, "mcp:registration", "mcp_client_register", "registry_full unused=" + waiting + " limit=" + MCP_UNUSED_CLIENT_LIMIT, "refused");
    return oauthJson({ error: "temporarily_unavailable", error_description: "Too many registered MCP clients are waiting for a first connection; try again later" },
      503, { "Retry-After": "3600" });
  }
  // The global ceiling and the per-address daily cap count only registrations about to be stored.
  // With unused clients pruned after a day, one address can hold at most 50 of the 1,000 slots.
  if (!await allow(env, "register-day", clientIp(request), MCP_DAILY_REGISTRATIONS_PER_ADDRESS, 86400)) return tooMany();
  if (!await allow(env, "register-all", "all", 300)) return tooMany();
  const clientId = "nmcp_" + randomToken();
  const issuedAt = nowSeconds();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO nathan_mcp_clients(client_id,client_name,redirect_uris,scope,created_at,expires_at) VALUES (?,?,?,?,?,?)")
      .bind(clientId, parsed.client_name, JSON.stringify(parsed.redirect_uris), parsed.scope ?? null, issuedAt, issuedAt + MCP_CLIENT_SECONDS),
    env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(), "mcp:registration", "mcp_client_register", clientId + " name=" + parsed.client_name.slice(0, 60), "succeeded")
  ]);
  return oauthJson({ client_id: clientId, client_id_issued_at: issuedAt, client_name: parsed.client_name, redirect_uris: parsed.redirect_uris,
    token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
    ...(parsed.scope ? { scope: parsed.scope } : {}) }, 201);
}
async function revoke(request: Request, env: AuthEnv, auth: any) {
  if (!await allow(env, "token", clientIp(request), 120)) return tooMany();
  const params = await formParams(request, 20000);
  single(params);
  const client = await loadClient(env, params.get("client_id"));
  if (!client) throw new OAuthFail("invalid_client", "Unknown or expired MCP client", 401);
  const token = required(params, "token", 16000);
  let grantId: string | null = null;
  if (token.startsWith("nmcp_rt_")) {
    const refresh = await peekArtifact<{ clientId: string }>(env, token, "refresh");
    if (refresh?.clientId === client.client_id) grantId = refresh.grantId;
  } else {
    let audience: unknown = null;
    try { audience = decodeJwt(token).aud; } catch { audience = null; }
    const resource = typeof audience === "string" ? await loadResource(env, audience) : null;
    // Expired access tokens can still be revoked; the signature, issuer and audience must verify.
    const payload = resource ? await verifyAccessToken(env, auth, token, resource.identifier, MCP_GRANT_SECONDS) : null;
    if (payload?.client_id === client.client_id) grantId = payload.nathan_grant;
  }
  if (grantId) await dropGrant(env, grantId, "mcp:" + client.client_id, "client_revocation");
  // RFC 7009: unknown tokens succeed without revealing anything.
  return new Response(null, { status: 200, headers: JSON_HEADERS });
}
export function mcpAuthorizationServerMetadata(env: AuthEnv) {
  const issuer = mcpIssuer(env);
  return {
    issuer,
    authorization_endpoint: issuer + "/authorize",
    token_endpoint: issuer + "/token",
    registration_endpoint: issuer + "/register",
    revocation_endpoint: issuer + "/revoke",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: false,
    // Access tokens are RFC 9068 JWTs signed by Nathan's token issuer, verifiable with these keys.
    jwks_uri: tokenIssuer(env) + "/jwks"
  };
}

// ---- connections page ----------------------------------------------------------------------------

async function connectionsCsrf(env: AuthEnv, sessionId: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.BETTER_AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("nathan-mcp-connections:" + sessionId)));
  return btoa(String.fromCharCode(...mac)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
async function connectionViews(env: AuthEnv, userId: string) {
  const grants = (await env.DB.prepare("SELECT g.id, g.client_id, g.resource, g.scope, g.created_at, g.expires_at, c.client_name, r.name AS resource_name " +
    "FROM nathan_mcp_grants g JOIN nathan_mcp_clients c ON c.client_id=g.client_id JOIN nathan_mcp_resources r ON r.identifier=g.resource " +
    "WHERE g.user_id=? AND g.expires_at>unixepoch() AND c.expires_at>unixepoch() ORDER BY g.created_at DESC LIMIT 100").bind(userId).all<any>()).results ?? [];
  const views = [];
  for (const g of grants) {
    const resource = await loadResource(env, g.resource);
    if (!resource) continue;
    const catalog = await loadCatalog(env, resource);
    const { permissions, admin } = await userPermissions(env, catalog, resource.app_id, userId);
    const offered = offeredScopes(catalog, permissions, { admin });
    const stored = new Set<string>(String(g.scope).split(" ").filter(Boolean));
    const effective = effectiveScopes(catalog, parseGrant(catalog, g.scope), permissions, { admin });
    views.push({ grantId: g.id, clientName: g.client_name, clientId: g.client_id, resourceName: g.resource_name, resource: g.resource,
      createdAt: g.created_at, expiresAt: g.expires_at, entries: catalog.entries, byScope: catalog.byScope, full: catalog.full, offered,
      checked: new Set([...concreteScopes(catalog, stored), ...(catalog.full && stored.has(catalog.full) ? [catalog.full] : [])]),
      effective: scopeString(catalog, effective).split(" ").filter(Boolean), catalog });
  }
  return views;
}
async function connections(request: Request, env: AuthEnv, auth: any) {
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session?.user?.id || !session.session?.id) {
    if (request.method === "GET") return signInRedirect(env, "/connections");
    return mcpErrorPage("Signed out", "Sign in again.", 401);
  }
  const csrf = await connectionsCsrf(env, session.session.id);
  const render = async (notice?: { ok: boolean; message: string }, status = 200) =>
    connectionsPage(session.user.email, csrf, await connectionViews(env, session.user.id), notice, status);
  if (request.method === "GET") {
    const done = new URL(request.url).searchParams.get("done");
    return render(done === "saved" ? { ok: true, message: "Permissions saved." } : done === "disconnected" ? { ok: true, message: "Disconnected." } : undefined);
  }
  if (request.headers.get("Origin") !== originOf(env) || request.headers.get("Sec-Fetch-Site") === "cross-site")
    return mcpErrorPage("Request refused", "Change connections on this page only.", 403);
  let form: URLSearchParams;
  try { form = await formParams(request); single(form, ["scope"]); } catch { return render({ ok: false, message: "The form was malformed." }, 400); }
  if (!constantTimeEqual(form.get("csrf") ?? "", csrf)) return mcpErrorPage("Request refused", "This page expired; reload it.", 403);
  if (!await allow(env, "connections", session.user.id, 30)) return render({ ok: false, message: "Too many changes; wait a minute." }, 429);
  const grantId = form.get("grant") ?? "";
  const grant = await env.DB.prepare("SELECT id, user_id, resource, scope FROM nathan_mcp_grants WHERE id=? AND user_id=? LIMIT 1")
    .bind(grantId, session.user.id).first<{ id: string; user_id: string; resource: string; scope: string }>();
  // Another user's grant looks exactly like a missing one.
  if (!grant) return render({ ok: false, message: "Connection not found." }, 404);
  const action = form.get("action");
  if (action === "disconnect") {
    await dropGrant(env, grant.id, session.user.id, "user_disconnect");
    return redirectWithCookies(originOf(env) + "/connections?done=disconnected", 303);
  }
  if (action !== "save") return render({ ok: false, message: "Choose Save or Disconnect." }, 400);
  const resource = await loadResource(env, grant.resource);
  if (!resource) return render({ ok: false, message: "Connection not found." }, 404);
  const catalog = await loadCatalog(env, resource);
  const { permissions, admin } = await userPermissions(env, catalog, resource.app_id, session.user.id);
  let stored: string;
  try { stored = selectScopes(catalog, form.getAll("scope"), offeredScopes(catalog, permissions, { admin })).stored; }
  catch (e) { return render({ ok: false, message: e instanceof Error ? e.message : "Invalid scope selection" }, 400); }
  await env.DB.batch([
    env.DB.prepare("UPDATE nathan_mcp_grants SET scope=?, updated_at=unixepoch() WHERE id=? AND user_id=?").bind(stored, grant.id, session.user.id),
    env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(), session.user.id, "mcp_grant_update", grant.id + " scope=" + stored, "succeeded")
  ]);
  return redirectWithCookies(originOf(env) + "/connections?done=saved", 303);
}

// ---- routing -------------------------------------------------------------------------------------

export function isMcpOAuthPath(pathname: string) {
  return pathname === METADATA_PATH || pathname.startsWith(MCP_AS_PATH + "/") || pathname === "/connections";
}
export async function handleMcpOAuth(request: Request, env: AuthEnv, auth: any): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (url.pathname === METADATA_PATH && (request.method === "GET" || request.method === "HEAD"))
      return oauthJson(mcpAuthorizationServerMetadata(env), 200, { "Cache-Control": "public, max-age=300" });
    if (url.pathname === "/connections" && (request.method === "GET" || request.method === "POST")) return await connections(request, env, auth);
    if (url.pathname === MCP_AS_PATH + "/authorize" && request.method === "GET") return await authorizeGet(request, env, auth, url);
    if (url.pathname === MCP_AS_PATH + "/authorize" && request.method === "POST") return await authorizePost(request, env, auth);
    // Server-to-server endpoints. Browsers' cross-origin fetches get no CORS grant.
    if (request.method === "POST" && url.pathname === MCP_AS_PATH + "/register") return await register(request, env);
    if (request.method === "POST" && url.pathname === MCP_AS_PATH + "/token") return await tokenEndpoint(request, env, auth);
    if (request.method === "POST" && url.pathname === MCP_AS_PATH + "/revoke") return await revoke(request, env, auth);
    if (request.method === "POST" && url.pathname === MCP_AS_PATH + "/grant") {
      if (!await allow(env, "grant", clientIp(request), 600)) return tooMany();
      const header = request.headers.get("Authorization") ?? "";
      const params = await formParams(request, 2048);
      single(params);
      return oauthJson(await mcpGrantStatus(env, auth, header.startsWith("Bearer ") ? header.slice(7) : null, params.get("resource")));
    }
    return oauthJson({ error: "not_found" }, 404);
  } catch (e) {
    return oauthErrorResponse(e);
  }
}

/** Scheduled cleanup; expiry is enforced on every read regardless. */
export async function pruneMcp(env: AuthEnv) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM nathan_mcp_artifacts WHERE expires_at < unixepoch()"),
    env.DB.prepare("DELETE FROM nathan_mcp_grants WHERE expires_at < unixepoch()"),
    env.DB.prepare("DELETE FROM nathan_mcp_clients WHERE expires_at < unixepoch()"),
    pruneUnusedClients(env, 100000)
  ]);
}

// ---- Identity Studio (admin-only, checked by the caller) -----------------------------------------

export async function mcpOverview(env: AuthEnv) {
  const resources = (await env.DB.prepare("SELECT identifier, app_id, name, full_scope, aliases, enabled FROM nathan_mcp_resources ORDER BY identifier LIMIT 200").all<ResourceRow>()).results ?? [];
  const out = [];
  for (const r of resources) {
    const catalog = await loadCatalog(env, r);
    out.push({ identifier: r.identifier, app: r.app_id, name: r.name, enabled: r.enabled === 1, full: catalog.full,
      aliases: Object.fromEntries(catalog.aliases), scopes: catalog.entries });
  }
  const grants = (await env.DB.prepare("SELECT g.id, g.resource, g.scope, g.created_at AS createdAt, g.expires_at AS expiresAt, g.client_id AS clientId, " +
    'c.client_name AS clientName, u."email" AS email FROM nathan_mcp_grants g JOIN nathan_mcp_clients c ON c.client_id=g.client_id ' +
    'LEFT JOIN "user" u ON u."id"=g.user_id WHERE g.expires_at>unixepoch() ORDER BY g.created_at DESC LIMIT 500').all()).results ?? [];
  return { issuer: mcpIssuer(env), metadata: mcpAuthorizationServerMetadata(env), resources: out, grants };
}

export const MCP_OPERATIONS = ["resource.register", "resource.status", "resource.remove", "grant.revoke"];
export async function applyMcpOperation(env: AuthEnv, body: any, actor: string) {
  const op = body?.op;
  if (!MCP_OPERATIONS.includes(op)) throw Error("Unknown MCP operation");
  const origin = originOf(env);
  if (op === "grant.revoke") {
    if (typeof body.grantId !== "string" || !/^nmcp_g_[A-Za-z0-9_-]{43}$/.test(body.grantId)) throw Error("Invalid grant id");
    if (body.confirm !== "CONFIRM REVOKE " + body.grantId) throw Error("Explicit confirmation required");
    if (!await dropGrant(env, body.grantId, actor, "admin_revocation")) throw Error("Unknown grant");
    return { grantId: body.grantId, revoked: true };
  }
  if (op === "resource.remove") {
    const identifier = validateAudience(body.identifier, origin);
    if (!await loadResource(env, identifier)) throw Error("Unknown MCP resource");
    if (body.confirm !== "CONFIRM REMOVE MCP " + identifier) throw Error("Explicit confirmation required");
    // Cascades to the MCP resource, its metadata and every grant (and so every token of it).
    await env.DB.batch([
      env.DB.prepare("DELETE FROM nathan_token_audiences WHERE identifier=?").bind(identifier),
      env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
        .bind(crypto.randomUUID(), actor, "mcp_resource_remove", identifier, "succeeded")
    ]);
    return { identifier, removed: true };
  }
  // resource.status and resource.register are shared with the account-token CLI (`nathan mcp status|register`):
  // the same identifier and audience rules, catalog validation, statements and audit row (src/shared/admin-ops.mjs).
  const reader = { all: async (sql: string, params: unknown[]) => ((await env.DB.prepare(sql).bind(...params).all()).results ?? []) as any[] };
  const plan = op === "resource.status" ? await planMcpStatus(reader, body, origin) : await planMcpRegister(reader, body, origin, actor);
  await env.DB.batch(committedStatements(plan, actor).map(s => env.DB.prepare(s.sql).bind(...s.params)));
  if (op === "resource.status") return plan.result;
  const { created: _created, ...registered } = plan.result as Record<string, unknown> & { identifier: string };
  return { ...registered, protectedResourceMetadata: { resource: registered.identifier, authorization_servers: [mcpIssuer(env)] } };
}
