/**
 * Nathan Worker SDK (NATH-13).
 *
 *   const user = await nathan(request, env);
 *   const denied = user.require("invoices:write"); if (denied) return denied;
 *
 * Two ways in, one answer:
 * - Gateway mode: the Nathan gateway forwards a short-lived HS256 principal in X-Nathan-Principal.
 *   Needs NATHAN_PRINCIPAL_KEY (shared with the gateway) and NATHAN_APPLICATION_ID. Optional
 *   NATHAN_GATEWAY_ORIGIN pins the gateway that signed it.
 * - API mode: a bearer JWT access token from Nathan (typ at+jwt), verified against Nathan's JWKS
 *   for NATHAN_ISSUER and NATHAN_AUDIENCE. Roles come from the identity Worker's evaluator through
 *   the NATHAN service binding (entrypoint NathanVerifier), or from `options.resolve`.
 *
 * A present but invalid principal header never falls back to a bearer token. Anything that cannot
 * be verified is an anonymous user that can do nothing.
 */
import { createRemoteJWKSet, jwtVerify } from "jose";
import { verifyPrincipal, PRINCIPAL_HEADER } from "../shared/principal.mjs";
import { isPermissionKey, isRoleKey } from "../shared/policy.mjs";

/**
 * @typedef {{ allowed: boolean, reason?: string, roles: string[], permissions: string[], email?: string|null }} AccessDecision
 * @typedef {{ resolveAccess(input: { applicationId: string, subject: string }): Promise<AccessDecision> }} NathanAccessBinding
 * @typedef {{
 *   NATHAN_PRINCIPAL_KEY?: string, NATHAN_APPLICATION_ID?: string, NATHAN_GATEWAY_ORIGIN?: string,
 *   NATHAN_ISSUER?: string, NATHAN_AUDIENCE?: string, NATHAN?: NathanAccessBinding
 * }} NathanEnv
 * @typedef {{ resolve?: (subject: string, payload: Record<string, unknown>) => Promise<AccessDecision> }} NathanOptions
 * @typedef {{
 *   authenticated: boolean, allowed: boolean, via: "gateway"|"token"|null,
 *   sub: string|null, email: string|null, app: string|null,
 *   roles: readonly string[], permissions: readonly string[],
 *   hasRole(role: string): boolean, can(permission: string): boolean,
 *   forbidden(): Response, require(permission: string): Response|null, requireRole(role: string): Response|null
 * }} NathanUser
 */

const ACCESS_TOKEN_ALGORITHMS = ["RS256", "ES256", "EdDSA"];
/** @type {Map<string, ReturnType<typeof createRemoteJWKSet>>} */
const keySets = new Map();

/** @param {unknown} value */
const stringList = (value, check) => Array.isArray(value) && value.every(check) ? Object.freeze([...value]) : Object.freeze([]);

/** @param {{ authenticated: boolean, allowed: boolean, via: NathanUser["via"], sub?: string|null, email?: string|null, app?: string|null, roles?: unknown, permissions?: unknown }} state
 * @returns {Readonly<NathanUser>} */
function makeUser(state) {
  const allowed = state.authenticated && state.allowed;
  const roles = allowed ? stringList(state.roles, isRoleKey) : Object.freeze([]);
  const permissions = allowed ? stringList(state.permissions, isPermissionKey) : Object.freeze([]);
  const json = (status, body, headers = {}) => Response.json(body, { status, headers: { "Cache-Control": "no-store", ...headers } });
  const forbidden = (detail = {}) => state.authenticated
    ? json(403, { error: "forbidden", ...detail })
    : json(401, { error: "unauthorized" }, state.via === "token" || state.via === null ? { "WWW-Authenticate": 'Bearer error="invalid_token"' } : {});
  /** @type {NathanUser} */
  const user = {
    authenticated: state.authenticated, allowed, via: state.via,
    sub: state.sub ?? null, email: state.email ?? null, app: state.app ?? null,
    roles, permissions,
    hasRole: role => roles.includes(role),
    can: permission => permissions.includes(permission),
    forbidden: () => forbidden(),
    require: permission => permissions.includes(permission) ? null : forbidden({ permission }),
    requireRole: role => roles.includes(role) ? null : forbidden({ role })
  };
  return Object.freeze(user);
}
const anonymous = () => makeUser({ authenticated: false, allowed: false, via: null });

/** @param {string} issuer */
function keySet(issuer) {
  let set = keySets.get(issuer);
  if (!set) {
    const url = new URL(issuer);
    if (url.protocol !== "https:") throw Error("NATHAN_ISSUER must be HTTPS");
    set = createRemoteJWKSet(new URL(url.origin + url.pathname.replace(/\/$/, "") + "/jwks"));
    keySets.set(issuer, set);
  }
  return set;
}

/**
 * @param {Request} request
 * @param {NathanEnv} env
 * @param {NathanOptions} [options]
 * @returns {Promise<Readonly<NathanUser>>}
 */
export async function nathan(request, env, options = {}) {
  const app = env?.NATHAN_APPLICATION_ID;
  const principalHeader = request.headers.get(PRINCIPAL_HEADER);
  if (principalHeader !== null) {
    if (!env?.NATHAN_PRINCIPAL_KEY || !app) return anonymous();
    const principal = await verifyPrincipal(principalHeader, {
      key: env.NATHAN_PRINCIPAL_KEY, app, ...(env.NATHAN_GATEWAY_ORIGIN ? { issuer: env.NATHAN_GATEWAY_ORIGIN } : {})
    });
    if (!principal) return anonymous();
    return makeUser({ authenticated: true, allowed: true, via: "gateway", ...principal });
  }

  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ") || !env?.NATHAN_ISSUER || !env.NATHAN_AUDIENCE || !app) return anonymous();
  const token = authorization.slice(7);
  if (token.length < 16 || token.length > 16000) return anonymous();
  let payload;
  try {
    ({ payload } = await jwtVerify(token, keySet(env.NATHAN_ISSUER), {
      issuer: env.NATHAN_ISSUER, audience: env.NATHAN_AUDIENCE, typ: "at+jwt",
      algorithms: ACCESS_TOKEN_ALGORITHMS, clockTolerance: 30, requiredClaims: ["sub", "exp"]
    }));
  } catch { return anonymous(); }
  // A DPoP-bound token is not a bearer token; accepting it without its proof would defeat binding.
  if (payload.cnf || typeof payload.sub !== "string" || payload.sub.length > 256) return anonymous();
  const subject = payload.sub;
  /** @type {AccessDecision|null} */
  let decision = null;
  try {
    if (options.resolve) decision = await options.resolve(subject, payload);
    else if (env.NATHAN)
      decision = await env.NATHAN.resolveAccess({ applicationId: app, subject });
  } catch { decision = null; }
  // Extension point (NATH-15): token role claims are hints only and are never read here.
  return makeUser({
    authenticated: true, allowed: decision?.allowed === true, via: "token", sub: subject, app,
    email: typeof decision?.email === "string" ? decision.email : null,
    roles: decision?.roles, permissions: decision?.permissions
  });
}

/**
 * Convenience guard: `const denied = await requirePermission(request, env, "invoices:write"); if (denied) return denied;`
 * @param {Request} request @param {NathanEnv} env @param {string} permission @param {NathanOptions} [options]
 */
export async function requirePermission(request, env, permission, options) {
  return (await nathan(request, env, options)).require(permission);
}

export { PRINCIPAL_HEADER };
