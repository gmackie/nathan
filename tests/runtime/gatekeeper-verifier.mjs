/**
 * A line-by-line mirror of Gatekeeper's OIDC access-token rules (packages/identity/jwt.ts,
 * createIdentityResolver, `kind: "oidc"` branch) so Nathan's runtime tests can check its tokens
 * against a provider entry without Gatekeeper's build. Keep it in step with Gatekeeper; the
 * contract test also runs Gatekeeper's own resolver when its checkout is available.
 */
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { readFileSync } from "node:fs";

const claimText = value => typeof value === "string" && value.length > 0 && value.length <= 512;
const invalid = reason => { throw Object.assign(Error("InvalidCredentials: " + reason), { code: "InvalidCredentials" }); };

/** The ```json block after `<!-- gatekeeper-provider-entry -->` in docs/gatekeeper.md, parsed. */
export function providerEntryFromDocs(path = "docs/gatekeeper.md") {
  const text = readFileSync(path, "utf8");
  const at = text.indexOf("<!-- gatekeeper-provider-entry -->");
  if (at < 0) throw Error("docs/gatekeeper.md has no gatekeeper-provider-entry marker");
  const block = /```json\n([\s\S]*?)\n```/.exec(text.slice(at));
  if (!block) throw Error("no json block after the marker");
  return JSON.parse(block[1]);
}

export async function verifyLikeGatekeeper(token, provider, jwks, now = Date.now()) {
  if (provider.kind !== "oidc") throw Error("only oidc providers are mirrored");
  if (token.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) invalid("compact");
  const hint = decodeJwt(token);
  if (hint.iss !== provider.issuer) invalid("issuer not configured");
  let verified;
  try {
    verified = await jwtVerify(token, createLocalJWKSet(jwks), {
      issuer: provider.issuer, audience: provider.audience, algorithms: [...provider.algorithms],
      requiredClaims: ["iss", "aud", "sub", "iat", "exp"], currentDate: new Date(now), clockTolerance: 5
    });
  } catch (error) { invalid("jose: " + error.code); }
  const { payload, protectedHeader } = verified;
  if (protectedHeader.jku || protectedHeader.jwk || protectedHeader.x5u || payload.cnf !== undefined || payload.act !== undefined) invalid("header/cnf/act");
  const issued = payload.iat, expires = payload.exp;
  if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires) || issued < 0 || expires <= issued ||
      expires - issued > (provider.maxTokenLifetimeSeconds ?? 900) ||
      issued * 1000 > now + 5000 || expires * 1000 <= now ||
      (payload.nbf !== undefined && (!Number.isSafeInteger(payload.nbf) || payload.nbf * 1000 > now))) invalid("lifetime");
  const audiences = typeof payload.aud === "string" ? [payload.aud] : payload.aud;
  if (!Array.isArray(audiences) || audiences.length > 32 || audiences.some(a => !claimText(a))) invalid("aud");
  const profile = provider.accessTokenProfile;
  if (profile.kind === "rfc9068") {
    if (!["at+jwt", "application/at+jwt"].includes(protectedHeader.typ?.toLowerCase() ?? "") || !claimText(payload.client_id) || !claimText(payload.jti)) invalid("rfc9068 profile");
  } else if (payload[profile.markerClaim] !== profile.markerValue) invalid("marker");
  if (payload.nonce !== undefined || !claimText(payload.sub)) invalid("nonce/sub");
  if (payload.client_id !== undefined && !claimText(payload.client_id)) invalid("client_id");
  if (provider.allowedClientIds && (!payload.client_id || !provider.allowedClientIds.includes(payload.client_id))) invalid("client not allowed");
  let scopes = [];
  if (payload.scope !== undefined) {
    if (typeof payload.scope !== "string" || payload.scope.length > 8192) invalid("scope");
    scopes = payload.scope.split(" ").filter(Boolean);
  }
  const raw = provider.kindClaim ? payload[provider.kindClaim.name] : undefined;
  const kind = provider.kindClaim && typeof raw === "string" && Object.hasOwn(provider.kindClaim.values, raw) ? provider.kindClaim.values[raw] : "unknown";
  const mfa = kind === "human" && !!provider.mfa && typeof payload.acr === "string" && provider.mfa.acrValues.includes(payload.acr);
  return { issuer: provider.issuer, subject: payload.sub, kind, mfa, clientId: payload.client_id, scopes, audiences, expiresAt: expires * 1000 };
}
