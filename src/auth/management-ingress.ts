import { createRemoteJWKSet, jwtVerify } from "jose";
import { sha256 } from "../gateway/crypto";
import { isAppId } from "../shared/policy.mjs";
import { normalizeEmail } from "./admission-policy.mjs";
import { openConfigSecret, sealConfigSecret } from "./config-crypto.mjs";
import { managementEmail, type AuthEnv } from "./env";
import { ownerSetup } from "./owner-setup";

type Handler = (request: Request, env: AuthEnv, ctx: ExecutionContext) => Promise<Response>;
const managementPrefix = "__Host-management-";
const nathanCookie = /^(?:__Secure-nathan\.[\w.-]+|__Host-nathan-[\w-]+)$/;
const teamDomain = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/;
const denied = (status: number, error: string) => Response.json({ error }, { status, headers: { "Cache-Control": "no-store" } });

function exactHttpsOrigin(value?: string): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin === value ? value : null;
  } catch { return null; }
}

/** Both entrypoints validate the same standalone configuration before serving either origin. */
export function standaloneOrigins(env: AuthEnv) {
  const management = exactHttpsOrigin(env.NATHAN_ISSUER);
  const app = exactHttpsOrigin(env.NATHAN_APP_ORIGIN);
  if (!management || !app || management === app || !isAppId(env.NATHAN_APP_ID) || !teamDomain.test(env.NATHAN_ACCESS_TEAM_DOMAIN ?? "") ||
      !/^[a-f0-9]{64}$/.test(env.NATHAN_ACCESS_AUD ?? "") || !/^[A-Za-z0-9_-]{43}$/.test(env.NATHAN_CONFIG_KEY ?? "") ||
      env.NATHAN_BOOTSTRAP_REQUIRED !== "true" || env.NATHAN_ADMIN_STEPUP_REQUIRED !== "true") return null;
  return { management, app };
}

let accessKeys: { issuer: string; keys: ReturnType<typeof createRemoteJWKSet> } | undefined;
async function accessIdentity(request: Request, env: AuthEnv) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token || token.length > 16384) return null;
  const issuer = "https://" + env.NATHAN_ACCESS_TEAM_DOMAIN;
  if (accessKeys?.issuer !== issuer) {
    accessKeys = { issuer, keys: createRemoteJWKSet(new URL(issuer + "/cdn-cgi/access/certs")) };
  }
  try {
    const { payload } = await jwtVerify(token, accessKeys.keys, {
      algorithms: ["RS256"], issuer, audience: env.NATHAN_ACCESS_AUD, requiredClaims: ["exp", "sub", "email", "type"]
    });
    const email = normalizeEmail(payload.email);
    if (payload.type !== "app" || !email || typeof payload.sub !== "string" || !payload.sub || payload.sub.length > 256) return null;
    return { email, binding: JSON.stringify([env.NATHAN_ISSUER, issuer, env.NATHAN_ACCESS_AUD, payload.sub, email]) };
  } catch { return null; }
}

// Only the Studio and its operator sign-in, enrollment and account pages run on this host.
const managementPaths = new Set([
  "/", "/healthz", "/studio", "/security", "/sign-in", "/sign-in/sso/start", "/api/auth/error",
  "/security/setup-owner", "/api/auth/sign-in/social", "/api/auth/sign-in/email", "/api/auth/verify-email",
  "/api/auth/sign-out", "/api/auth/get-session", "/api/auth/sso/callback",
  "/api/auth/passkey/generate-register-options", "/api/auth/passkey/verify-registration",
  "/api/auth/passkey/generate-authenticate-options", "/api/auth/passkey/verify-authentication", "/api/auth/passkey/list-user-passkeys",
  "/api/auth/two-factor/enable", "/api/auth/two-factor/verify-totp"
]);
function managementPath(path: string) {
  return managementPaths.has(path) || path.startsWith("/studio/") || path.startsWith("/security/api/") || path.startsWith("/__nathan/ui/") ||
    /^\/api\/auth\/(?:callback|sso\/callback|sso\/saml2\/sp\/acs)\/[A-Za-z0-9_-]{1,128}$/.test(path);
}

// Better Auth owns its signed cookies and WebAuthn challenges. Encrypt those values at the
// HTTP management boundary so a session or challenge from the app binding cannot be moved
// here. The Access principal, issuer, audience and cookie name authenticate each envelope.
async function cookiePurpose(principal: string, name: string) {
  return "management-cookie:v1:" + await sha256(JSON.stringify([principal, name]));
}
async function openManagementCookies(request: Request, principal: string, key: string) {
  const outgoing = [];
  for (const pair of (request.headers.get("Cookie") ?? "").split(";")) {
    const item = pair.trim();
    if (!item.startsWith(managementPrefix)) continue;
    const index = item.indexOf("=");
    if (index < 0) continue;
    const name = item.slice(managementPrefix.length, index);
    if (!nathanCookie.test(name)) continue;
    try {
      const value = await openConfigSecret(await cookiePurpose(principal, name), item.slice(index + 1), key);
      outgoing.push(name + "=" + value);
    } catch { /* A stale or foreign cookie carries no authority. */ }
  }
  const headers = new Headers(request.headers);
  headers.delete("Cookie");
  headers.delete("Authorization");
  for (const name of [...headers.keys()]) if (name.startsWith("cf-access-")) headers.delete(name);
  if (outgoing.length) headers.set("Cookie", outgoing.join("; "));
  return new Request(request, { headers });
}

async function sealManagementResponse(response: Response, principal: string, key: string) {
  const headers = new Headers(response.headers);
  headers.delete("Set-Cookie");
  headers.set("Cache-Control", "private, no-store");
  for (const line of response.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(";");
    const index = pair.indexOf("=");
    const name = pair.slice(0, index);
    if (index <= 0 || !nathanCookie.test(name)) continue;
    const value = pair.slice(index + 1);
    // Empty values expire the same __Host- cookie using Better Auth's Max-Age/Expires.
    const sealed = value ? await sealConfigSecret(await cookiePurpose(principal, name), value, key) : "";
    const preserved = attrs.filter(attr => !/^\s*(?:domain=|path=|secure\s*$|httponly\s*$)/i.test(attr));
    headers.append("Set-Cookie", [managementPrefix + name + "=" + sealed, " Path=/", " Secure", " HttpOnly", ...preserved].join(";"));
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export async function managementIngress(request: Request, env: AuthEnv, ctx: ExecutionContext, handle: Handler) {
  if (env.NATHAN_APP_ID === undefined && env.NATHAN_APP_ORIGIN === undefined &&
      env.NATHAN_ACCESS_TEAM_DOMAIN === undefined && env.NATHAN_ACCESS_AUD === undefined) {
    return handle(request, env, ctx);
  }
  const origins = standaloneOrigins(env);
  if (!origins) return denied(503, "Management configuration incomplete");
  const url = new URL(request.url);
  if (url.origin !== origins.management) return denied(421, "Misdirected request");
  const identity = await accessIdentity(request, env);
  if (!identity) return denied(403, "Cloudflare Access required");
  if (!managementPath(url.pathname)) return denied(404, "Not found");
  const key = env.NATHAN_CONFIG_KEY!;
  const inner = await openManagementCookies(request, identity.binding, key);
  const management: AuthEnv = { ...env, [managementEmail]: identity.email, ENABLE_EMAIL_OTP: "false" };
  const response = await ownerSetup(inner, management) ?? await handle(inner, management, ctx);
  return sealManagementResponse(response, identity.binding, key);
}
