/**
 * The gateway-signed principal (NATH-13): a compact JWS (HS256) the Nathan gateway attaches to
 * every request it forwards to the private upstream Worker in the X-Nathan-Principal header.
 * The gateway and its upstream share NATHAN_PRINCIPAL_KEY; the upstream verifies with the SDK.
 * Lifetime is at most 60 seconds, the audience is the application id, and the issuer is the
 * gateway's public origin.
 */
import { SignJWT, jwtVerify } from "jose";
import { isAppId, isPermissionKey, isRoleKey, isSubjectId } from "./policy.mjs";

export const PRINCIPAL_HEADER = "X-Nathan-Principal";
export const PRINCIPAL_TYPE = "nathan-principal+jwt";
export const MAX_PRINCIPAL_LIFETIME = 60;
const MAX_TOKEN_LENGTH = 16384;
const MAX_ROLES = 64;
const MAX_PERMISSIONS = 512;
const CLOCK_TOLERANCE = 5;

/**
 * Decodes NATHAN_PRINCIPAL_KEY: at least 32 random bytes, base64url without padding.
 * @param {unknown} encoded @returns {Uint8Array}
 */
export function principalKey(encoded) {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{43,172}$/.test(encoded))
    throw Error("NATHAN_PRINCIPAL_KEY must be at least 32 random bytes, base64url encoded");
  const binary = atob(encoded.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - encoded.length % 4) % 4));
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  if (bytes.byteLength < 32) throw Error("NATHAN_PRINCIPAL_KEY must be at least 32 random bytes, base64url encoded");
  return bytes;
}

/**
 * @typedef {{ sub: string, email: string|null, app: string, roles: string[], permissions: string[] }} PrincipalClaims
 * @typedef {PrincipalClaims & { iss: string, iat: number, exp: number }} VerifiedPrincipal
 */

/** @param {any} value @returns {value is PrincipalClaims} */
function validClaims(value) {
  return Boolean(value) && isSubjectId(value.sub) && isAppId(value.app)
    && (value.email === null || (typeof value.email === "string" && value.email.length <= 320))
    && Array.isArray(value.roles) && value.roles.length <= MAX_ROLES && value.roles.every(isRoleKey)
    && Array.isArray(value.permissions) && value.permissions.length <= MAX_PERMISSIONS && value.permissions.every(isPermissionKey);
}

/**
 * Signs the principal the gateway forwards. Throws on invalid claims, never signs them.
 * @param {{ sub: string, email?: string|null, app: string, roles: string[], permissions: string[] }} principal
 * @param {{ key: string, issuer: string, lifetime?: number }} options
 */
export async function signPrincipal(principal, { key, issuer, lifetime = MAX_PRINCIPAL_LIFETIME }) {
  const claims = { sub: principal.sub, email: principal.email ?? null, app: principal.app, roles: principal.roles, permissions: principal.permissions };
  if (!validClaims(claims)) throw Error("Invalid principal claims");
  if (!Number.isSafeInteger(lifetime) || lifetime < 1) throw Error("Invalid principal lifetime");
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT({ email: claims.email, app: claims.app, roles: claims.roles, permissions: claims.permissions })
    .setProtectedHeader({ alg: "HS256", typ: PRINCIPAL_TYPE })
    .setIssuer(issuer).setAudience(claims.app).setSubject(claims.sub)
    .setIssuedAt(iat).setExpirationTime(iat + lifetime)
    .sign(principalKey(key));
}

/**
 * Verifies a gateway principal. Returns null for anything forged, unsigned, expired, longer
 * lived than 60 s, for another application or (when given) another gateway origin.
 * @param {unknown} token
 * @param {{ key: string, app: string, issuer?: string }} options
 * @returns {Promise<Readonly<VerifiedPrincipal>|null>}
 */
export async function verifyPrincipal(token, { key, app, issuer }) {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_LENGTH || !isAppId(app)) return null;
  try {
    const { payload } = await jwtVerify(token, principalKey(key), {
      algorithms: ["HS256"], typ: PRINCIPAL_TYPE, audience: app,
      ...(issuer ? { issuer } : {}),
      requiredClaims: ["iss", "sub", "iat", "exp"], clockTolerance: CLOCK_TOLERANCE
    });
    const now = Math.floor(Date.now() / 1000);
    const iat = Number(payload.iat), exp = Number(payload.exp);
    if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) || exp <= iat || exp - iat > MAX_PRINCIPAL_LIFETIME) return null;
    if (iat > now + CLOCK_TOLERANCE) return null;
    const claims = { sub: payload.sub, email: payload.email ?? null, app: payload.app, roles: payload.roles, permissions: payload.permissions };
    if (!validClaims(claims) || claims.app !== app) return null;
    return Object.freeze({ ...claims, roles: Object.freeze([...claims.roles]), permissions: Object.freeze([...claims.permissions]), iss: String(payload.iss), iat, exp });
  } catch {
    return null;
  }
}
