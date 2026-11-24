/**
 * NATH-51: "Sign in with Nathan". A parent Nathan instance as an upstream OIDC provider of this
 * (child) instance, registered through Better Auth's first-party genericOAuth plugin.
 *
 * - Endpoints come only from the configured issuer's discovery document. The discovered issuer must
 *   equal the configured one exactly, and the authorization, token and JWKS endpoints must be HTTPS
 *   on the issuer's own origin, so a discovery document can never send the client secret or the
 *   browser anywhere else. Discovery is cached per isolate (10 minutes; a failure for 1 minute).
 * - The flow is authorization code + PKCE (S256) with state (Better Auth keeps it in D1, bound to a
 *   signed cookie), a nonce, the RFC 9207 `iss` check, and client_secret_basic at the token endpoint.
 * - The ID token is required and verified here, not decoded: signature against the parent's JWKS,
 *   an allowed asymmetric algorithm from discovery, iss, aud (and azp for several audiences), exp,
 *   iat and the nonce bound to this authorization. A client-submitted ID token (direct sign-in or
 *   linking with `idToken`) is never accepted.
 * - A Nathan parent (Better Auth oauth-provider) puts the email and profile claims only in UserInfo,
 *   as OIDC Core 5.4 allows for the code flow. They are read from the discovered UserInfo endpoint
 *   with the access token from the same exchange, and used only when UserInfo's `sub` equals the
 *   verified ID token's `sub` (OIDC Core 5.3.2).
 * - Email trust: an account is created or linked only for an address whose email_verified claim is
 *   exactly `true`, and only while an administrator has marked this parent trusted (same owner).
 *   Account creation then follows the installation's admission policy like every other method.
 * - Only email, name and picture are taken from the parent. Its amr/acr (and any nathan_* evidence
 *   claims) are ignored: the parent's MFA is never local MFA or administrator assurance.
 * - Account ids are issuer-qualified (`<issuer>#<sub>`), so re-pointing the provider at another
 *   issuer can never sign in to accounts the previous issuer created.
 */
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import { NATHAN_UPSTREAM_ID, inputError, signInLabel } from "../shared/providers.mjs";

export const UPSTREAM_SCOPES = Object.freeze(["openid", "email", "profile"]);
/** Asymmetric JWS algorithms only. A Nathan parent signs ID tokens with EdDSA (Ed25519). */
export const ALLOWED_ID_TOKEN_ALGS = Object.freeze(["EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]);
const DISCOVERY_TTL_MS = 10 * 60 * 1000, FAILURE_TTL_MS = 60 * 1000, DISCOVERY_TIMEOUT_MS = 5000, MAX_DISCOVERY_BYTES = 64 * 1024;
const CLOCK_TOLERANCE_SECONDS = 30;

/** A discovery failure with a reason code that is safe to show and audit. */
export class DiscoveryError extends Error {
  constructor(code, issuer) {
    super("Nathan upstream discovery failed (" + code + ") for " + issuer);
    this.code = code;
    this.publicMessage = "Could not use the parent's discovery document at " + discoveryUrl(issuer) + " (" + code + "). " +
      "Check the issuer: it must be exactly the issuer the parent publishes, e.g. https://id.gmac.io/api/auth.";
  }
}

/** OIDC Discovery 1.0 §4: the issuer with /.well-known/openid-configuration appended. */
export function discoveryUrl(issuer) {
  return String(issuer) + "/.well-known/openid-configuration";
}

function sameOriginHttps(value, origin) {
  if (typeof value !== "string" || value.length > 2000) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== "https:" || url.origin !== origin || url.username || url.password || url.hash) return null;
  return url.href;
}

/**
 * Validates a parent's discovery document against the configured issuer. Pure; throws a
 * DiscoveryError with a reason code.
 * @returns {{issuer: string, authorizationEndpoint: string, tokenEndpoint: string, userinfoEndpoint: string, jwksUri: string, algorithms: string[]}}
 */
export function validateDiscovery(issuer, doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new DiscoveryError("discovery_invalid", issuer);
  if (doc.issuer !== issuer) throw new DiscoveryError("issuer_mismatch", issuer);
  const origin = new URL(issuer).origin;
  const authorizationEndpoint = sameOriginHttps(doc.authorization_endpoint, origin);
  const tokenEndpoint = sameOriginHttps(doc.token_endpoint, origin);
  const userinfoEndpoint = sameOriginHttps(doc.userinfo_endpoint, origin);
  const jwksUri = sameOriginHttps(doc.jwks_uri, origin);
  if (!authorizationEndpoint || !tokenEndpoint || !userinfoEndpoint || !jwksUri) throw new DiscoveryError("endpoint_not_on_issuer_origin", issuer);
  const offered = Array.isArray(doc.id_token_signing_alg_values_supported) ? doc.id_token_signing_alg_values_supported : [];
  const algorithms = ALLOWED_ID_TOKEN_ALGS.filter(a => offered.includes(a));
  if (!algorithms.length) throw new DiscoveryError("no_supported_id_token_algorithm", issuer);
  if (Array.isArray(doc.response_types_supported) && !doc.response_types_supported.includes("code"))
    throw new DiscoveryError("code_flow_unsupported", issuer);
  if (Array.isArray(doc.code_challenge_methods_supported) && !doc.code_challenge_methods_supported.includes("S256"))
    throw new DiscoveryError("pkce_s256_unsupported", issuer);
  if (Array.isArray(doc.token_endpoint_auth_methods_supported) && !doc.token_endpoint_auth_methods_supported.includes("client_secret_basic"))
    throw new DiscoveryError("client_secret_basic_unsupported", issuer);
  return { issuer, authorizationEndpoint, tokenEndpoint, userinfoEndpoint, jwksUri, algorithms };
}

const discoveryCache = new Map();
/** Test hook: forget cached discovery documents and JWKS. */
export function clearUpstreamCaches() { discoveryCache.clear(); jwksCache.clear(); }

async function fetchDiscovery(issuer, fetcher) {
  let response;
  try {
    response = await fetcher(discoveryUrl(issuer), {
      headers: { Accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS)
    });
  } catch { throw new DiscoveryError("discovery_unreachable", issuer); }
  if (response.status !== 200) throw new DiscoveryError("discovery_status_" + response.status, issuer);
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > MAX_DISCOVERY_BYTES) throw new DiscoveryError("discovery_too_large", issuer);
  const text = await response.text().catch(() => "");
  if (text.length > MAX_DISCOVERY_BYTES) throw new DiscoveryError("discovery_too_large", issuer);
  let doc;
  try { doc = JSON.parse(text); } catch { throw new DiscoveryError("discovery_invalid", issuer); }
  return validateDiscovery(issuer, doc);
}

/**
 * The parent's validated discovery, cached in this isolate. Concurrent callers share one fetch.
 * @param {string} issuer
 * @param {{fetch?: typeof fetch, now?: number, fresh?: boolean}} [options] `fresh` skips the cache (Studio save).
 */
export async function discoverUpstream(issuer, options = {}) {
  const now = options.now ?? Date.now();
  const fetcher = options.fetch || ((input, init) => fetch(input, init));
  const cached = discoveryCache.get(issuer);
  if (!options.fresh && cached && cached.expires > now) {
    const settled = await cached.promise;
    if (settled.ok) return settled.value;
    throw settled.error;
  }
  const promise = fetchDiscovery(issuer, fetcher).then(value => ({ ok: true, value }), error => ({ ok: false, error }));
  const entry = { promise, expires: now + DISCOVERY_TTL_MS };
  discoveryCache.set(issuer, entry);
  const settled = await promise;
  if (!settled.ok) { entry.expires = now + FAILURE_TTL_MS; throw settled.error; }
  return settled.value;
}

/**
 * Configured values → what Better Auth needs, after discovery. Refuses an untrusted parent and a
 * parent that is this very instance (a sign-in loop).
 * @param {Record<string,string>} values validated registry fields
 * @param {{selfIssuer?: string, fetch?: typeof fetch, fresh?: boolean}} [options]
 */
export async function resolveUpstream(values, options = {}) {
  if (values?.trustEmailVerified !== "true") throw inputError("The Nathan upstream must be marked trusted for email verification");
  if (options.selfIssuer && new URL(values.issuer).origin === new URL(options.selfIssuer).origin)
    throw inputError("The Nathan upstream cannot be this instance itself");
  const discovery = await discoverUpstream(values.issuer, options);
  return { clientId: values.clientId, clientSecret: values.clientSecret, issuer: values.issuer,
    displayName: values.displayName, trustEmailVerified: "true", discovery };
}

const jwksCache = new Map();
function jwksFor(uri) {
  let set = jwksCache.get(uri);
  if (!set) {
    set = createRemoteJWKSet(new URL(uri), { timeoutDuration: DISCOVERY_TIMEOUT_MS, cooldownDuration: 30_000, cacheMaxAge: DISCOVERY_TTL_MS });
    jwksCache.set(uri, set);
  }
  return set;
}

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,253}$/;
/** Account id for a parent subject: issuer-qualified, so a different issuer never matches it. */
export function accountSubject(issuer, sub) {
  return issuer + "#" + sub;
}
function audienceOk(claims, clientId) {
  const aud = claims?.aud;
  if (typeof aud === "string") return aud === clientId;
  if (!Array.isArray(aud) || !aud.includes(clientId)) return false;
  // OIDC Core 3.1.3.7: with several audiences the authorized party must be this client.
  return aud.length === 1 || claims.azp === clientId;
}

/**
 * The account the parent's (already verified) ID token claims describe, or why it is refused.
 * Takes only sub, email, name and picture; never amr, acr or any evidence claim.
 * @returns {{ok: true, profile: {id: string, sub: string, email: string, emailVerified: true, name: string, image?: string}} | {ok: false, reason: string}}
 */
export function upstreamProfile(claims, { issuer, clientId, trusted }) {
  if (trusted !== true) return { ok: false, reason: "untrusted_upstream" };
  if (!claims || typeof claims !== "object") return { ok: false, reason: "invalid_claims" };
  if (claims.iss !== issuer || !audienceOk(claims, clientId)) return { ok: false, reason: "invalid_claims" };
  const sub = claims.sub;
  if (typeof sub !== "string" || !sub.length || sub.length > 255 || /[\u0000-\u001f\u007f]/.test(sub)) return { ok: false, reason: "invalid_claims" };
  if (claims.email_verified !== true) return { ok: false, reason: "email_unverified" };
  const email = typeof claims.email === "string" ? claims.email.trim().toLowerCase() : "";
  if (email.length > 254 || !EMAIL.test(email)) return { ok: false, reason: "email_unverified" };
  const name = typeof claims.name === "string" ? claims.name.slice(0, 200) : "";
  let image;
  if (typeof claims.picture === "string" && claims.picture.length <= 2000) {
    try { if (new URL(claims.picture).protocol === "https:") image = claims.picture; } catch {}
  }
  return { ok: true, profile: { id: accountSubject(issuer, sub), sub, email, emailVerified: true, name, ...(image ? { image } : {}) } };
}

/**
 * The parent's UserInfo for this exchange's access token, without redirects and size-bounded.
 * Returns null on any failure.
 */
export async function fetchUserInfo(endpoint, accessToken, fetcher = (input, init) => fetch(input, init)) {
  if (typeof accessToken !== "string" || !accessToken) return null;
  try {
    const response = await fetcher(endpoint, { headers: { Authorization: "Bearer " + accessToken, Accept: "application/json" },
      redirect: "manual", signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS) });
    if (response.status !== 200) return null;
    const text = await response.text();
    if (text.length > MAX_DISCOVERY_BYTES) return null;
    const body = JSON.parse(text);
    return body && typeof body === "object" && !Array.isArray(body) ? body : null;
  } catch { return null; }
}

/**
 * Claims for upstreamProfile: iss, aud, azp and sub from the verified ID token; email,
 * email_verified, name and picture from UserInfo, only when UserInfo is about the same subject.
 * Returns null when they disagree.
 */
export function mergeClaims(idClaims, userinfo) {
  if (!idClaims || !userinfo || typeof userinfo.sub !== "string" || userinfo.sub !== idClaims.sub) return null;
  return { iss: idClaims.iss, aud: idClaims.aud, azp: idClaims.azp, sub: idClaims.sub,
    email: userinfo.email, email_verified: userinfo.email_verified, name: userinfo.name, picture: userinfo.picture };
}

/**
 * The ID-token verifier given to Better Auth (provider.idToken.verify). Better Auth calls it in the
 * redirect callback with the nonce stored in this authorization's state, and no request context.
 * A request context means a client-submitted ID token (direct sign-in or linking), which is refused.
 */
export function idTokenVerifier({ issuer, clientId, algorithms, jwks, onRefused }) {
  return async (token, nonce, ctx) => {
    const refuse = async reason => { await onRefused?.(reason); return false; };
    if (ctx !== undefined) return refuse("client_id_token");
    if (typeof token !== "string" || token.split(".").length !== 3) return refuse("id_token_invalid");
    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwks, {
        issuer, audience: clientId, algorithms, requiredClaims: ["iss", "sub", "aud", "exp", "iat"], clockTolerance: CLOCK_TOLERANCE_SECONDS
      }));
    } catch { return refuse("id_token_invalid"); }
    if (typeof nonce !== "string" || !nonce || payload.nonce !== nonce) return refuse("id_token_nonce");
    if (!audienceOk(payload, clientId)) return refuse("id_token_invalid");
    return true;
  };
}

/**
 * Better Auth plugin for a resolved Nathan upstream (resolveUpstream's result, as built by
 * buildSocialProviders). `hooks.onRefused(reason)` audits a refused sign-in; `hooks.onVerified(email)`
 * runs for an accepted, verified address before Better Auth looks it up (invitee supersession).
 * @param {{clientId: string, clientSecret: string, issuer: string, displayName?: string, trustEmailVerified: string,
 *   discovery: {authorizationEndpoint: string, tokenEndpoint: string, jwksUri: string, algorithms: string[]}}} config
 * @param {{onRefused?: (reason: string) => Promise<void>|void, onVerified?: (email: string) => Promise<void>|void, jwks?: any, fetch?: typeof fetch}} [hooks]
 */
export function nathanUpstreamPlugin(config, hooks = {}) {
  const { clientId, clientSecret, issuer, discovery } = config;
  const trusted = config.trustEmailVerified === "true";
  const plugin = genericOAuth({
    config: [{
      providerId: NATHAN_UPSTREAM_ID,
      name: signInLabel(NATHAN_UPSTREAM_ID, config.displayName),
      clientId, clientSecret,
      authorizationUrl: discovery.authorizationEndpoint,
      tokenUrl: discovery.tokenEndpoint,
      scopes: [...UPSTREAM_SCOPES],
      pkce: true,
      authentication: "basic",
      accountSubject: ({ profile }) => (profile && typeof profile.id === "string" ? profile.id : ""),
      // Runs after Better Auth verified the ID token through provider.idToken (set below).
      getUserInfo: async tokens => {
        if (typeof tokens?.idToken !== "string") { await hooks.onRefused?.("id_token_missing"); return null; }
        let idClaims;
        try { idClaims = decodeJwt(tokens.idToken); } catch { await hooks.onRefused?.("id_token_invalid"); return null; }
        if (!trusted) { await hooks.onRefused?.("untrusted_upstream"); return null; }
        const userinfo = await fetchUserInfo(discovery.userinfoEndpoint, tokens.accessToken, hooks.fetch);
        const claims = mergeClaims(idClaims, userinfo);
        if (!claims) { await hooks.onRefused?.(userinfo ? "userinfo_subject_mismatch" : "userinfo_unavailable"); return null; }
        const result = upstreamProfile(claims, { issuer, clientId, trusted });
        if (!result.ok) { await hooks.onRefused?.(result.reason); return null; }
        await hooks.onVerified?.(result.profile.email);
        return result.profile;
      }
    }]
  });
  const init = plugin.init;
  plugin.init = async ctx => {
    const result = await init(ctx);
    const provider = result?.context?.socialProviders?.find(p => p.id === NATHAN_UPSTREAM_ID);
    if (!provider) throw Error("Nathan upstream provider was not registered");
    // genericOAuth only builds an ID-token verifier from its own discovery fetch. Nathan discovers
    // (and caches) itself, so it supplies the verifier, the issuer for the RFC 9207 `iss` check, and
    // requires a nonce: Better Auth then stores one in state and refuses a callback without it.
    provider.issuer = issuer;
    provider.idToken = { verify: idTokenVerifier({ issuer, clientId, algorithms: discovery.algorithms,
      jwks: hooks.jwks ?? jwksFor(discovery.jwksUri), onRefused: hooks.onRefused }) };
    provider.requiresIdTokenNonce = true;
    return result;
  };
  return plugin;
}
