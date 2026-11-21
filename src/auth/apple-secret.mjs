/**
 * Sign in with Apple client secret (NATH-9).
 *
 * Apple has no static client secret: the relying party signs an ES256 JWT with its .p8 key
 * (iss = Team ID, sub = Services ID, aud = https://appleid.apple.com, kid = Key ID). Nathan
 * mints it at runtime from the encrypted .p8 key, keeps it only in this isolate's memory, and
 * never persists it. Lifetime is one hour; a cached JWT is reused only while it has more than
 * ten minutes left, so a token handed to Better Auth never expires mid-flow.
 */
import { SignJWT, importPKCS8 } from "jose";
import { inputError } from "../shared/providers.mjs";

export const APPLE_AUDIENCE = "https://appleid.apple.com";
const LIFETIME = 3600, MIN_REMAINING = 600, MAX_ENTRIES = 8;
const cache = new Map();

export function clearAppleSecretCache() { cache.clear(); }

async function cacheKey(c) {
  const digest = await crypto.subtle.digest("SHA-256",
    new TextEncoder().encode([c.teamId, c.clientId, c.keyId, c.privateKey].join("\u0000")));
  let raw = ""; for (const b of new Uint8Array(digest)) raw += String.fromCharCode(b);
  return btoa(raw);
}

/**
 * @param {{clientId:string,teamId:string,keyId:string,privateKey:string}} credentials
 * @param {number} [now] unix seconds (tests)
 * @returns {Promise<string>} compact JWS
 */
export async function mintAppleClientSecret(credentials, now = Math.floor(Date.now() / 1000)) {
  const { clientId, teamId, keyId, privateKey } = credentials || {};
  if (![clientId, teamId, keyId, privateKey].every(v => typeof v === "string" && v.length > 0))
    throw Error("Apple Services ID, Team ID, Key ID and private key are required");
  const id = await cacheKey(credentials);
  const hit = cache.get(id);
  if (hit && hit.iat <= now && hit.exp - now > MIN_REMAINING) return hit.token;
  let key;
  try { key = await importPKCS8(privateKey, "ES256"); }
  catch { throw inputError("Apple private key is not a valid ES256 (P-256) PKCS#8 .p8 key"); }
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: keyId })
    .setIssuer(teamId).setSubject(clientId).setAudience(APPLE_AUDIENCE)
    .setIssuedAt(now).setExpirationTime(now + LIFETIME)
    .sign(key);
  if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value);
  cache.set(id, { token, iat: now, exp: now + LIFETIME });
  return token;
}
