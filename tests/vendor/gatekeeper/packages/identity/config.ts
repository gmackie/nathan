import { GatekeeperError, record } from "../core/model.ts";
import { boundedJson, httpsUrl } from "../net/bounded.ts";
import type { PrincipalKind } from "../principal/model.ts";
export type SigningAlgorithm = "RS256" | "ES256" | "EdDSA";
interface BaseProvider {
  readonly id: string;
  readonly issuer: string;
  readonly audience: string;
  readonly maxTokenLifetimeSeconds?: number;
  /** Claim surfaced as `principal.handle` for operator role matching and display (e.g. "email"). Never an authorization input. */
  readonly handleClaim?: string;
}
export interface OidcProviderConfig extends BaseProvider {
  readonly kind: "oidc";
  readonly jwksUri: string;
  readonly algorithms: readonly SigningAlgorithm[];
  readonly accessTokenProfile:
    | {readonly kind: "rfc9068"}
    | {readonly kind: "jwt-access-token"; readonly markerClaim: string; readonly markerValue: string};
  /** Claim must be set by trusted issuer logic, not user-editable profile metadata. */
  readonly kindClaim?: {readonly name: string; readonly values: Readonly<Record<string, Exclude<PrincipalKind, "anonymous" | "unknown">>>};
  readonly allowedClientIds?: readonly string[];
  /** No assurance upgrade by default. auth_time must also be present and recent. */
  readonly mfa?: {readonly acrValues: readonly string[]; readonly maxAgeSeconds: number};
}
export interface CloudflareAccessConfig extends BaseProvider { readonly kind: "cloudflare-access" }
export type IdentityProviderConfig = OidcProviderConfig | CloudflareAccessConfig;
function fail(): never { throw new GatekeeperError("InvalidIdentityConfiguration", "Invalid identity-provider configuration"); }
const text = (x: unknown, max = 512): x is string => typeof x === "string" && x.length > 0 && x.length <= max;
const strings = (x: unknown, max = 32): x is string[] => Array.isArray(x) && x.length > 0 && x.length <= max && x.every(v => text(v)) && new Set(x).size === x.length;
/** These are operator configuration, never a browser-supplied provider registration endpoint. */
export function parseIdentityProviders(value: unknown): readonly IdentityProviderConfig[] {
  boundedJson(value, {bytes: 65536, nodes: 2000, depth: 8});
  if (!Array.isArray(value) || value.length > 32) fail();
  const ids = new Set<string>(), issuers = new Set<string>();
  for (const p of value) {
    if (!record(p) || !text(p.id,64) || !/^[a-zA-Z0-9._-]+$/.test(p.id) || !text(p.issuer) || !text(p.audience) || ids.has(p.id)) fail();
    const issuer = httpsUrl(p.issuer);
    if (issuer.search) fail();
    const routeKey = JSON.stringify([p.kind, p.issuer]);
    if (issuers.has(routeKey)) fail();
    ids.add(p.id); issuers.add(routeKey);
    if (p.maxTokenLifetimeSeconds !== undefined && (!Number.isInteger(p.maxTokenLifetimeSeconds) || Number(p.maxTokenLifetimeSeconds) < 1 || Number(p.maxTokenLifetimeSeconds) > 86400)) fail();
    if (p.handleClaim !== undefined && (!text(p.handleClaim, 128) || !/^[a-zA-Z_][a-zA-Z0-9_.-]*$/.test(p.handleClaim))) fail();
    if (p.kind === "oidc") {
      httpsUrl(p.jwksUri);
      if (!strings(p.algorithms,3) || p.algorithms.some(a => !["RS256","ES256","EdDSA"].includes(a)) || !record(p.accessTokenProfile)) fail();
      const profile = p.accessTokenProfile;
      if (profile.kind === "jwt-access-token") {
        if (!text(profile.markerClaim,128) || !text(profile.markerValue,128) ||
          ["iss","sub","aud","exp","iat","nbf","nonce","auth_time","azp","amr","acr","email","scope","client_id","name"].includes(profile.markerClaim)) fail();
      } else if (profile.kind !== "rfc9068") fail();
      if (p.allowedClientIds !== undefined && !strings(p.allowedClientIds,128)) fail();
      if (p.kindClaim !== undefined) {
        if (!record(p.kindClaim) || !text(p.kindClaim.name,128) || !record(p.kindClaim.values) || !Object.keys(p.kindClaim.values).length ||
          Object.keys(p.kindClaim.values).length > 16 || Object.values(p.kindClaim.values).some(k => typeof k !== "string" || !["human","service","agent"].includes(k))) fail();
      }
      if (p.mfa !== undefined && (!record(p.mfa) || !strings(p.mfa.acrValues) || !Number.isInteger(p.mfa.maxAgeSeconds) || Number(p.mfa.maxAgeSeconds) < 1 || Number(p.mfa.maxAgeSeconds) > 3600)) fail();
    } else if (p.kind === "cloudflare-access") {
      if (!/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer.hostname) || issuer.port || issuer.pathname !== "/" || p.issuer.endsWith("/")) fail();
    } else fail();
  }
  return JSON.parse(JSON.stringify(value)) as IdentityProviderConfig[];
}
