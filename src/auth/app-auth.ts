import { WorkerEntrypoint } from "cloudflare:workers";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createLocalJWKSet, jwtVerify } from "jose";
import { isAllowedUnsafeRequest } from "../shared/security.mjs";
import { resolveAccess } from "./rbac";
import { recordAppRpSession } from "./app-rp-session";
import { pinnedApplication, type BindingProps } from "./app-binding";
import { readBoundedText } from "./bounded-body.mjs";
import { emailSignIn } from "./email-sign-in";
import { normalizeEmail } from "./admission-policy.mjs";
import { createAuth } from "./instance";
import { standaloneOrigins } from "./management-ingress";
import type { AuthEnv } from "./env";

const prefix = "/api/auth";
const metadata = prefix + "/.well-known/openid-configuration";
const authorize = prefix + "/oauth2/authorize", consent = prefix + "/oauth2/consent";
const token = prefix + "/oauth2/token", revoke = prefix + "/oauth2/revoke", userinfo = prefix + "/oauth2/userinfo";
const getRoutes = new Set([metadata, prefix + "/jwks", authorize, userinfo]);
const postRoutes = new Set([token, revoke, consent, prefix + "/sign-out", "/sign-in/context", "/sign-in/email/request", "/sign-in/email/verify"]);
const json = (body: object, status = 200) => Response.json(body, {status, headers:{"Cache-Control":"no-store"}});
const error = (status: number, code: string) => json({error:code},status);
const browserScopes = new Set(["openid","email","profile","offline_access"]);
const one = (params: URLSearchParams, key: string) => params.getAll(key).length === 1 ? params.get(key) : null;

async function clientForResource(env: AuthEnv, app: string, clientId: string | null, resource: string) {
  if (!clientId || clientId.length > 200) return null;
  return env.DB.prepare('SELECT c.name FROM "oauthClient" c JOIN "oauthClientResource" l ON l.clientId=c.clientId ' +
    'JOIN "oauthResource" r ON r.identifier=l.resourceId JOIN nathan_token_audiences a ON a.identifier=r.identifier ' +
    'WHERE c.clientId=? AND r.identifier=? AND a.app_id=? AND COALESCE(c.disabled,0)=0 AND COALESCE(r.disabled,0)=0')
    .bind(clientId,resource,app).first<{name:string|null}>();
}

/** The exact audience is registered by the operator. Better Auth checks the registered redirect,
 * PKCE, state, consent and confidential-client credentials at its own endpoints. */
async function authorizationContext(env: AuthEnv, app: string, params: URLSearchParams) {
  const resource = env.NATHAN_ISSUER + "/api";
  const scopes = one(params,"scope")?.split(" ");
  if (one(params,"resource") !== resource || !scopes?.includes("openid") || scopes.some(s => !browserScopes.has(s)) ||
      one(params,"response_type") !== "code" || one(params,"code_challenge_method") !== "S256" ||
      !one(params,"code_challenge") || !one(params,"redirect_uri") || !one(params,"state") || !one(params,"nonce")) return null;
  const client = await clientForResource(env, app, one(params,"client_id"), resource);
  if (!client) return null;
  return {clientName:client.name || app, scopes, loginHint:normalizeEmail(one(params,"login_hint")), enterpriseSso:env.ENTERPRISE_SSO === "true"};
}

async function signedContext(env: AuthEnv, app: string, query: unknown) {
  if (typeof query !== "string" || query.length > 16384 || !await verifyOAuthQueryParams(query, env.BETTER_AUTH_SECRET)) return null;
  return authorizationContext(env, app, new URLSearchParams(query));
}

function credentialsClient(request: Request, params: URLSearchParams) {
  const header = request.headers.get("Authorization");
  if (params.getAll("client_id").length > 1) return null;
  const inBody = params.get("client_id");
  if (!header) return inBody;
  if (!header.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice(6)), colon = decoded.indexOf(":");
    if (colon < 1) return null;
    const id = decodeURIComponent(decoded.slice(0,colon).replaceAll("+"," "));
    return inBody && inBody !== id ? null : id;
  } catch { return null; }
}

function applicationHeaders(request: Request) {
  const result = new Headers();
  for (const name of ["Authorization","Accept","Content-Type","Origin","Sec-Fetch-Site","Sec-Fetch-Mode","CF-Connecting-IP","DPoP"]) {
    const value = request.headers.get(name);
    if (value !== null) result.set(name,value);
  }
  const cookies = (request.headers.get("Cookie") ?? "").split(";").map(c=>c.trim())
    .filter(c => /^(?:__Secure-nathan\.[\w.-]+|__Host-nathan-email)=/.test(c));
  if (cookies.length) result.set("Cookie",cookies.join("; "));
  return result;
}

function publicDiscovery(document: Record<string, unknown>) {
  // Advertise only the operations this binding actually serves. ClassCheck owns sign-out UI.
  const {introspection_endpoint, introspection_endpoint_auth_methods_supported, introspection_endpoint_auth_signing_alg_values_supported,
    token_endpoint_auth_signing_alg_values_supported, revocation_endpoint_auth_signing_alg_values_supported,
    end_session_endpoint, registration_endpoint, pushed_authorization_request_endpoint, device_authorization_endpoint, ...supported} = document;
  return {...supported,scopes_supported:[...browserScopes,"nathan:api"],response_types_supported:["code"],
    token_endpoint_auth_methods_supported:["client_secret_basic","client_secret_post","none"],
    revocation_endpoint_auth_methods_supported:["client_secret_basic","client_secret_post","none"],
    code_challenge_methods_supported:["S256"],grant_types_supported:["authorization_code","refresh_token","client_credentials"]};
}

async function appFetch(request: Request, env: AuthEnv, ctx: ExecutionContext, app: string) {
  const url = new URL(request.url), path = url.pathname, resource = env.NATHAN_ISSUER + "/api";
  if (!getRoutes.has(path) && !postRoutes.has(path)) return error(404,"not_found");
  if (request.method !== (getRoutes.has(path) ? "GET" : "POST")) return error(405,"method_not_allowed");
  if (request.method === "POST" && !(path === token || path === revoke) &&
      !isAllowedUnsafeRequest(request.method, request.headers.get("Origin"), env.NATHAN_ISSUER, request.headers.get("Sec-Fetch-Site")))
    return error(403,"invalid_origin");
  const enabled = await env.DB.prepare("SELECT 1 FROM nathan_applications WHERE id=? AND hostname=? AND enabled=1")
    .bind(app,url.hostname).first();
  if (!enabled) return error(403,"application_unavailable");

  const headers = applicationHeaders(request);
  let raw: string | undefined;
  if (request.method === "POST") {
    const data = await readBoundedText(request, 16384);
    if (data === null) return error(413,"request_too_large");
    raw = data;
  }
  const forward = () => new Request(request.url,{method:request.method,headers,body:raw,redirect:"manual"});
  if (path === token || path === revoke) {
    if (headers.get("Content-Type")?.split(";")[0] !== "application/x-www-form-urlencoded") return error(415,"invalid_request");
    const params = new URLSearchParams(raw);
    if (path === token && (one(params,"resource") !== resource || !["authorization_code","refresh_token","client_credentials"].includes(one(params,"grant_type") ?? "")))
      return error(400,"invalid_target");
    if (!await clientForResource(env,app,credentialsClient(request,params),resource)) return error(401,"invalid_client");
    headers.delete("Cookie");
  }
  const auth = createAuth(env);
  if ((path === authorize || path === consent) && headers.has("Cookie")) {
    const current = await auth.api.getSession({headers});
    if (current && !(await resolveAccess(env,app,current.user.id)).allowed) return error(403,"access_denied");
  }
  if (path === authorize && !await authorizationContext(env,app,url.searchParams)) return error(400,"invalid_request");
  if (path === consent || path.startsWith("/sign-in/")) {
    if (headers.get("Content-Type")?.split(";")[0] !== "application/json") return error(415,"invalid_request");
    let input;
    try { input = JSON.parse(raw!); } catch { return error(400,"invalid_request"); }
    if (!input || typeof input !== "object" || Array.isArray(input)) return error(400,"invalid_request");
    if (path !== "/sign-in/email/verify") {
      const context = await signedContext(env,app,input.oauth_query);
      if (!context) return error(400,"invalid_request");
      if (path === "/sign-in/context") return json(context);
    }
    if (path === "/sign-in/email/request" || path === "/sign-in/email/verify")
      return emailSignIn(forward(),env,ctx,path.endsWith("/request") ? "request" : "verify",
        async query => Boolean(await signedContext(env,app,query)));
  }
  if (path === userinfo) {
    const bearer = headers.get("Authorization")?.match(/^(?:Bearer|DPoP) (\S+)$/i)?.[1];
    if (!bearer || bearer.length > 16384) return error(401,"invalid_token");
    // Management and the app share one installation, including its key store. Scope UserInfo to an
    // app-issued resource token and a currently registered client before Better Auth releases claims.
    const keys = createLocalJWKSet(await auth.api.getJwks());
    try {
      const {payload} = await jwtVerify(bearer,keys,{issuer:env.NATHAN_ISSUER + prefix,audience:resource,
        algorithms:["EdDSA"],typ:"at+jwt",requiredClaims:["exp","sub","client_id"]});
      if (payload.principal_kind !== "user" || typeof payload.sub !== "string" || typeof payload.client_id !== "string" ||
          !await clientForResource(env,app,payload.client_id,resource) || !(await resolveAccess(env,app,payload.sub)).allowed)
        return error(401,"invalid_token");
    } catch { return error(401,"invalid_token"); }
    headers.delete("Cookie");
  }
  const response = await auth.handler(forward());
  if (path === token && response.ok) {
    try { await recordAppRpSession(env,response); } catch { return error(503,"temporarily_unavailable"); }
  }
  if (path === metadata && response.ok) return json(publicDiscovery(await response.json() as Record<string,unknown>));
  if (response.headers.get("Content-Type")?.includes("text/html")) return error(response.ok ? 400 : response.status,"invalid_request");
  return response;
}

/** A dedicated installation exports customer protocol operations only through this named binding.
 * The default export separately authenticates the Cloudflare Access-protected management surface. */
export class NathanAppAuth extends WorkerEntrypoint<AuthEnv,BindingProps> {
  async fetch(request: Request) {
    const origins = standaloneOrigins(this.env), app = pinnedApplication(this.ctx.props);
    if (!origins || !app || app !== this.env.NATHAN_APP_ID || this.env.NATHAN_INSTALL_ACTIVE !== "true") return error(403,"binding_unavailable");
    if (new URL(request.url).origin !== origins.app) return error(421,"misdirected_request");
    return appFetch(request,{...this.env,NATHAN_ISSUER:origins.app,ENABLE_PASSWORD:"false"},this.ctx,app);
  }
}
