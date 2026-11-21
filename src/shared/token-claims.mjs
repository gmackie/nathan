/**
 * NATH-15 Gatekeeper-ready access-token profile: the pure decisions behind the claims Nathan adds
 * to Better Auth's RFC 9068 JWT access tokens. No I/O here; src/auth/tokens.ts reads D1 and calls
 * these, and tests call them directly.
 *
 * Better Auth 1.7.14 already stamps `typ: at+jwt`, iss, sub, aud, exp, iat, jti, client_id, azp,
 * scope and (for session-backed grants) sid. It reserves `acr`, `amr` and `auth_time` for the
 * authorization server and strips them from every claim source, and it never sets them on access
 * tokens. Nathan therefore reports its own verified evidence under `nathan_*` names, and never
 * under names a verifier could read as AAL or MFA.
 */

/** Gatekeeper's default and maximum lifetime for OIDC access tokens. Nathan caps every access token here. */
export const MAX_ACCESS_TOKEN_SECONDS = 900;
/** Scope for client-credentials (machine and agent) tokens to APIs and Gatekeeper. Never user-delegated. */
export const API_SCOPE = "nathan:api";
/** Values of the `principal_kind` claim. */
export const PRINCIPAL_KINDS = Object.freeze(["user", "machine", "agent"]);
/** Admin-set client attribute values (nathan_client_principals.principal_kind). Unset means "classify by grant". */
export const CLIENT_KINDS = Object.freeze(["agent"]);
/** `nathan_acr` value: this session was created by a verified passkey (WebAuthn) assertion. Not MFA, not AAL2. */
export const PASSKEY_ACR = "urn:nathan:acr:passkey";

/**
 * Who the token speaks for. An administrator-marked agent/MCP client is always `agent`. Otherwise a
 * grant that carries a user (authorization code, or a refresh token descended from one) is `user`,
 * and anything else (client credentials) is `machine`. Unknown or malformed input is never `user`.
 */
export function principalKind({ hasUser, clientKind } = {}) {
  if (clientKind === "agent") return "agent";
  return hasUser === true ? "user" : "machine";
}

/**
 * Authentication-method claims from evidence Nathan holds: a nathan_admin_assurance row, written
 * only after Better Auth verified a passkey assertion and created this session. Enrollment alone
 * never produces a row. Returns {} without matching evidence.
 * - nathan_amr ["pop"]: proof of possession of a key (RFC 8176). Not "hwk" (synced passkeys are not
 *   hardware-bound) and not "user"/"mfa" (Nathan asks for user verification as "preferred" only).
 * - nathan_acr PASSKEY_ACR, nathan_auth_time: when the assertion was verified (seconds).
 */
export function evidenceClaims(row, { userId, sessionId } = {}) {
  if (!row || typeof row !== "object" || typeof userId !== "string" || typeof sessionId !== "string") return {};
  if (row.session_id !== sessionId || row.user_id !== userId || row.method !== "passkey") return {};
  if (!Number.isSafeInteger(row.verified_at) || row.verified_at <= 0) return {};
  return { nathan_amr: ["pop"], nathan_acr: PASSKEY_ACR, nathan_auth_time: row.verified_at };
}

/** Roles hint from NATH-13's evaluator: only for an allowed principal that has roles; sorted. */
export function rolesClaim(access) {
  if (!access || access.allowed !== true || !Array.isArray(access.roles) || access.roles.length === 0) return undefined;
  if (access.roles.some(r => typeof r !== "string" || !r)) return undefined;
  return [...access.roles].sort();
}

/** The single application bound to a token's requested audiences, or null when none or ambiguous. */
export function audienceApp(rows) {
  if (!Array.isArray(rows)) return null;
  const apps = new Set(rows.map(r => r?.app_id).filter(a => typeof a === "string" && a));
  return apps.size === 1 ? [...apps][0] : null;
}

/**
 * An RFC 8707 resource identifier Nathan issues tokens for: an exact, canonical HTTPS URL without
 * credentials, query or fragment, and not one of Nathan's own resources or endpoints.
 */
export function validateAudience(value, issuerOrigin) {
  // No percent-encoding: Better Auth decodes the identifier when it is a path parameter.
  if (typeof value !== "string" || value.length < 9 || value.length > 512 || /[\s\x00-\x1f\x7f%]/.test(value))
    throw Error("Invalid audience: use an exact https URL");
  let url;
  try { url = new URL(value); } catch { throw Error("Invalid audience: use an exact https URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || value.includes("#") || value.includes("?"))
    throw Error("Invalid audience: https only, without credentials, query or fragment");
  if (url.href !== value && url.href !== value + "/")
    throw Error("Invalid audience: use the canonical form " + url.href);
  if (url.origin === issuerOrigin && (["/mcp", "/directory"].includes(url.pathname) || url.pathname.startsWith("/api/auth")))
    throw Error("Invalid audience: reserved by Nathan");
  return value;
}
