/**
 * Nathan remote MCP SDK for Workers (NATH-14).
 *
 *   const mcp = nathanMcp(env, { resource: "https://notes.example.com/mcp", scopes: ["notes:read", "notes:write"] });
 *   export default { fetch: request => mcp.handle(request, async user => {
 *     const denied = user.require("notes:write"); if (denied) return denied;
 *     ...
 *   }) };
 *
 * - Serves RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource` and at the
 *   path-specific URL for the resource, naming Nathan's MCP authorization server.
 * - Answers requests without a usable token with an RFC 6750 401 challenge carrying `resource_metadata`,
 *   and `require(scope)` with a 403 `insufficient_scope` challenge.
 * - `user.can(scope)` reads the effective scopes Nathan reports for this token now: the token's scopes ∩
 *   the live grant (which the user may edit or revoke) ∩ the user's current permissions on the app.
 *
 * Revocation and grant edits reach the Worker within 60 s: every token is checked with Nathan, and an
 * answer is cached for at most 30 s per token. Access tokens themselves live 300 s. The check uses the
 * `NATHAN` service binding (entrypoint `NathanVerifier`) when present, otherwise
 * `POST <issuer origin>/mcp-oauth/grant` authenticated with the token itself. If Nathan cannot be
 * reached the request fails closed with 503.
 */
import { createRemoteJWKSet, jwtVerify } from "jose";
import { fetchNoRedirect } from "../shared/security.mjs";

const MAX_CACHE_SECONDS = 30;
const MAX_CACHE_ENTRIES = 1000;
const ALGORITHMS = ["EdDSA", "ES256", "RS256"];
/** @type {Map<string, ReturnType<typeof createRemoteJWKSet>>} */
const keySets = new Map();

/**
 * @typedef {{ active: boolean, sub?: string, clientId?: string, grantId?: string, scopes?: string[], exp?: number }} GrantStatus
 * @typedef {{ mcpGrant(input: { token: string, resource: string }): Promise<GrantStatus> }} NathanMcpBinding
 * @typedef {{ NATHAN_ISSUER?: string, NATHAN?: Partial<NathanMcpBinding> }} NathanMcpEnv
 * @typedef {{ resource: string, scopes?: string[], resourceName?: string, authorizationServer?: string, cacheSeconds?: number, documentation?: string }} NathanMcpOptions
 * @typedef {{
 *   authenticated: boolean, sub: string|null, clientId: string|null, grantId: string|null,
 *   scopes: readonly string[], principalKind: "agent"|null,
 *   can(scope: string): boolean, require(scope: string): Response|null
 * }} NathanMcpUser
 */

/** @param {unknown} value */
function exactHttpsUrl(value) {
  if (typeof value !== "string" || /[\s#?%]/.test(value)) throw Error("nathanMcp: resource must be an exact https URL");
  let url;
  try { url = new URL(value); } catch { throw Error("nathanMcp: resource must be an exact https URL"); }
  if (url.protocol !== "https:" || url.username || url.password || (url.href !== value && url.href !== value + "/"))
    throw Error("nathanMcp: resource must be an exact https URL");
  return url;
}
const quote = value => '"' + String(value).replace(/[\\"]/g, "") + '"';
async function digest(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * @param {NathanMcpEnv} env
 * @param {NathanMcpOptions} options
 */
export function nathanMcp(env, options) {
  const resourceUrl = exactHttpsUrl(options?.resource);
  const resource = /** @type {string} */ (options.resource);
  if (!env?.NATHAN_ISSUER) throw Error("nathanMcp: set NATHAN_ISSUER (https://<nathan host>/api/auth)");
  const issuer = new URL(env.NATHAN_ISSUER);
  if (issuer.protocol !== "https:") throw Error("nathanMcp: NATHAN_ISSUER must be https");
  const tokenIssuer = issuer.origin + issuer.pathname.replace(/\/$/, "");
  const authorizationServer = options.authorizationServer ?? issuer.origin + "/mcp-oauth";
  const cacheSeconds = Math.max(0, Math.min(MAX_CACHE_SECONDS, Number.isFinite(options.cacheSeconds) ? Number(options.cacheSeconds) : MAX_CACHE_SECONDS));
  const scopes = Array.isArray(options.scopes) ? options.scopes.filter(s => typeof s === "string" && /^[a-z][a-z0-9_.:-]{0,127}$/.test(s)) : [];
  const path = resourceUrl.pathname.replace(/\/$/, "");
  const metadataPaths = new Set(["/.well-known/oauth-protected-resource", ...(path ? ["/.well-known/oauth-protected-resource" + path] : [])]);
  const metadataUrl = resourceUrl.origin + "/.well-known/oauth-protected-resource" + path;
  /** @type {Map<string, { until: number, status: GrantStatus }>} */
  const cache = new Map();

  const metadata = () => ({
    resource, authorization_servers: [authorizationServer], bearer_methods_supported: ["header"],
    ...(scopes.length ? { scopes_supported: scopes } : {}),
    ...(options.resourceName ? { resource_name: options.resourceName } : {}),
    ...(options.documentation ? { resource_documentation: options.documentation } : {})
  });
  const headers = { "Cache-Control": "no-store", "Content-Type": "application/json" };
  const challenge = (error, description) => new Response(JSON.stringify({ error: error ?? "unauthorized" }), {
    status: 401,
    headers: { ...headers, "WWW-Authenticate": "Bearer " + [
      ...(error ? ["error=" + quote(error), "error_description=" + quote(description ?? "")] : []),
      "resource_metadata=" + quote(metadataUrl), ...(scopes.length ? ["scope=" + quote(scopes.join(" "))] : [])
    ].join(", ") }
  });
  const insufficient = scope => new Response(JSON.stringify({ error: "insufficient_scope", scope }), {
    status: 403,
    headers: { ...headers, "WWW-Authenticate": "Bearer error=\"insufficient_scope\", scope=" + quote(scope) + ", resource_metadata=" + quote(metadataUrl) }
  });

  /** @param {GrantStatus|null} status @returns {Readonly<NathanMcpUser>} */
  function makeUser(status) {
    const active = status?.active === true;
    const granted = Object.freeze(active && Array.isArray(status?.scopes) ? status.scopes.filter(s => typeof s === "string") : []);
    return Object.freeze({
      authenticated: active, sub: active ? status?.sub ?? null : null, clientId: active ? status?.clientId ?? null : null,
      grantId: active ? status?.grantId ?? null : null, scopes: granted, principalKind: active ? "agent" : null,
      can: scope => granted.includes(scope),
      require: scope => granted.includes(scope) ? null : active ? insufficient(scope) : challenge("invalid_token", "Sign in again")
    });
  }

  /** The authoritative check with Nathan; throws when Nathan is unreachable. @param {string} token */
  async function check(token) {
    if (typeof env.NATHAN?.mcpGrant === "function") return env.NATHAN.mcpGrant({ token, resource });
    // Without a binding, verify locally first so garbage never costs a round trip.
    let set = keySets.get(tokenIssuer);
    if (!set) { set = createRemoteJWKSet(new URL(tokenIssuer + "/jwks")); keySets.set(tokenIssuer, set); }
    try {
      const { payload } = await jwtVerify(token, set, { issuer: tokenIssuer, audience: resource, typ: "at+jwt", algorithms: ALGORITHMS, clockTolerance: 5 });
      if (payload.principal_kind !== "agent" || typeof payload.nathan_grant !== "string" || payload.cnf !== undefined) return { active: false };
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && String(error.code).startsWith("ERR_JW")) return { active: false };
      throw error;
    }
    const response = await fetchNoRedirect(issuer.origin + "/mcp-oauth/grant", {
      method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ resource }).toString()
    });
    if (!response.ok) throw Error("Nathan grant check failed with " + response.status);
    return response.json();
  }

  /** @param {Request} request @returns {Promise<Readonly<NathanMcpUser> | Response>} a user, or a 503 when Nathan cannot answer */
  async function authenticate(request) {
    const authorization = request.headers.get("Authorization");
    if (!authorization?.startsWith("Bearer ")) return makeUser(null);
    const token = authorization.slice(7).trim();
    if (token.length < 32 || token.length > 16000 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return makeUser(null);
    const key = await digest(token);
    const hit = cache.get(key);
    if (hit && hit.until > Date.now()) return makeUser(hit.status);
    let status;
    try { status = await check(token); }
    catch { return new Response(JSON.stringify({ error: "temporarily_unavailable" }), { status: 503, headers: { ...headers, "Retry-After": "5" } }); }
    const until = Date.now() + Math.min(cacheSeconds * 1000, Math.max(0, ((status?.exp ?? 0) * 1000) - Date.now()));
    if (cacheSeconds > 0) {
      if (cache.size >= MAX_CACHE_ENTRIES) cache.delete(/** @type {string} */ (cache.keys().next().value));
      cache.set(key, { until, status });
    }
    return makeUser(status);
  }

  return Object.freeze({
    resource, metadataUrl, authorizationServer, metadata,
    /** @param {Request} request */
    isMetadataRequest: request => (request.method === "GET" || request.method === "HEAD") && metadataPaths.has(new URL(request.url).pathname),
    metadataResponse: () => Response.json(metadata(), { headers: { "Cache-Control": "public, max-age=300" } }),
    authenticate,
    challenge: () => challenge(),
    /**
     * Serves metadata, rejects requests without an active grant (401), and otherwise calls `handler`.
     * @param {Request} request @param {(user: Readonly<NathanMcpUser>) => Response | Promise<Response>} handler
     */
    async handle(request, handler) {
      if ((request.method === "GET" || request.method === "HEAD") && metadataPaths.has(new URL(request.url).pathname))
        return Response.json(metadata(), { headers: { "Cache-Control": "public, max-age=300" } });
      const user = await authenticate(request);
      if (user instanceof Response) return user;
      if (!user.authenticated)
        return request.headers.has("Authorization") ? challenge("invalid_token", "The access token is invalid, expired or revoked") : challenge();
      return handler(user);
    }
  });
}
