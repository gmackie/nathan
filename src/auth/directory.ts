/**
 * NATH-13 directory read API for Gatekeeper's policy-information point (PIP).
 *
 *   GET /directory/v1/principal?subject=<issuer>#<sub>   groups, grants and effective roles per app
 *   GET /directory/v1/changes?cursor=<n>&limit=<1..500>   ordered grant/membership/role change feed
 *
 * Authentication: a Nathan JWT access token (typ at+jwt) for the resource <origin>/directory with
 * scope nathan:directory.read, obtained with the OAuth client-credentials grant by a confidential
 * client an administrator registered for this purpose. The client is re-checked online on every
 * request, so disabling it in Identity Studio cuts access immediately. This is the only way to read
 * the directory: the app-scoped NathanVerifier binding deliberately has no directory methods.
 * Reads are not audited; every write that changes them is.
 */
import { createLocalJWKSet, jwtVerify } from "jose";
import type { AuthEnv } from "./env";
import { directoryPrincipal, directoryChanges, issuerOf } from "./rbac";
import { audit } from "./admin-service";

export const DIRECTORY_SCOPE = "nathan:directory.read";
/** Gatekeeper's AUTHORITY_MAX_AGE_MS is 30 s; responses say how fresh they are and must not be cached longer. */
export const DIRECTORY_MAX_AGE_SECONDS = 30;
export function directoryResource(env: AuthEnv) {
  return new URL(env.NATHAN_ISSUER).origin + "/directory";
}

const HEADERS = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Type": "application/json; charset=utf-8" };
const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...extra } });
function unauthorized(env: AuthEnv, error = "invalid_token") {
  return json(401, { error }, {
    "WWW-Authenticate": 'Bearer error="' + error + '", scope="' + DIRECTORY_SCOPE + '", resource="' + directoryResource(env) + '"'
  });
}

/** Returns the authenticated machine client id, or null. */
export async function authenticateDirectoryClient(request: Request, env: AuthEnv, auth: any): Promise<string | null> {
  const header = request.headers.get("Authorization");
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7);
  if (token.length < 32 || token.length > 16000 || !/^[-._~+/=A-Za-z0-9]+$/.test(token)) return null;
  try {
    const keys = await auth.api.getJwks();
    if (!keys || !Array.isArray(keys.keys)) return null;
    const { payload } = await jwtVerify(token, createLocalJWKSet(keys), {
      issuer: issuerOf(env), audience: directoryResource(env), typ: "at+jwt",
      algorithms: ["RS256", "ES256", "EdDSA"], clockTolerance: 30, requiredClaims: ["sub", "exp"]
    });
    if (payload.cnf) return null; // DPoP-bound tokens need their proof; not supported here
    const scopes = typeof payload.scope === "string" ? payload.scope.split(/\s+/) : [];
    if (!scopes.includes(DIRECTORY_SCOPE)) return null;
    // Only a machine client (client-credentials: sub is the client itself), never a user's delegated token.
    const clientId = payload.client_id;
    if (typeof clientId !== "string" || payload.sub !== clientId || clientId.length > 200) return null;
    const client = await env.DB.prepare('SELECT "disabled" AS disabled, "clientCredentialsScopes" AS scopes FROM "oauthClient" WHERE "clientId"=? LIMIT 1')
      .bind(clientId).first<{ disabled: number | null; scopes: string | null }>();
    if (!client || client.disabled === 1) return null;
    let allowed: unknown = [];
    try { allowed = JSON.parse(client.scopes || "[]"); } catch { return null; }
    return Array.isArray(allowed) && allowed.includes(DIRECTORY_SCOPE) ? clientId : null;
  } catch {
    return null;
  }
}

export async function handleDirectory(request: Request, env: AuthEnv, auth: any): Promise<Response> {
  const url = new URL(request.url);
  if (request.method !== "GET") return json(405, { error: "method_not_allowed" }, { Allow: "GET" });
  if (!["/directory/v1/principal", "/directory/v1/changes"].includes(url.pathname)) return json(404, { error: "not_found" });
  if (!await authenticateDirectoryClient(request, env, auth)) return unauthorized(env);
  try {
    if (url.pathname === "/directory/v1/principal") {
      const subject = url.searchParams.get("subject");
      const view = await directoryPrincipal(env, subject);
      if (!view) return json(404, { error: "unknown_subject", subject, observedAt: new Date().toISOString() });
      return json(200, { ...view, maxAgeSeconds: DIRECTORY_MAX_AGE_SECONDS });
    }
    let page;
    try { page = await directoryChanges(env, url.searchParams.get("cursor"), url.searchParams.get("limit")); }
    catch { return json(400, { error: "invalid_request" }); }
    return json("resync" in page ? 410 : 200, page);
  } catch {
    return json(503, { error: "temporarily_unavailable" }, { "Retry-After": "5" });
  }
}

/**
 * Registers a confidential machine client for Gatekeeper's PIP: client-credentials only, limited to
 * nathan:directory.read for the directory resource. The secret is returned once. Admin-only (checked
 * by the caller) and audited.
 */
export async function createDirectoryClient(auth: any, env: AuthEnv, headers: Headers, input: any, actor: string) {
  const name = typeof input?.name === "string" ? input.name.trim() : "";
  const refuse = async (message: string) => {
    await audit(env, actor, "directory_client_create", name.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 100) || "-", "rejected").catch(() => {});
    return Error(message);
  };
  if (!name || name.length > 100 || /[\x00-\x1f\x7f]/.test(name)) throw await refuse("Invalid client name");
  if (input?.confirm !== "CONFIRM DIRECTORY CLIENT " + name) throw await refuse("Explicit confirmation required");
  await audit(env, actor, "directory_client_create", name, "attempted");
  try {
    const client = await auth.api.adminCreateOAuthClient({
      headers,
      body: {
        client_name: name,
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_basic",
        client_credentials_scopes: [DIRECTORY_SCOPE],
        resources: [directoryResource(env)],
        skip_consent: false
      }
    });
    await audit(env, actor, "directory_client_create", String(client?.client_id ?? name), "succeeded");
    return { ...client, tokenRequest: { grant_type: "client_credentials", scope: DIRECTORY_SCOPE, resource: directoryResource(env) },
      note: "Store the client secret now; it is not shown again. Disable the client in Registered applications to cut access immediately." };
  } catch (error) {
    await audit(env, actor, "directory_client_create", name, "failed");
    throw error;
  }
}
