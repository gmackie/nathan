import { createRemoteJWKSet, customFetch, decodeJwt, jwtVerify, type JWTPayload } from "jose";
import { GatekeeperError, record } from "../core/model.ts";
import { anonymous, principalId, type Principal, type PrincipalKind } from "../principal/model.ts";
import { readBoundedJson } from "../net/bounded.ts";
import { parseIdentityProviders, type IdentityProviderConfig, type OidcProviderConfig } from "./config.ts";
const invalid = (): never => { throw new GatekeeperError("InvalidCredentials", "Credentials could not be verified"); };
const claimText = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 512;
function compactToken(value: string): string {
  if (value.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) invalid();
  return value;
}
function subjectKind(p: OidcProviderConfig, payload: JWTPayload): PrincipalKind {
  if (!p.kindClaim) return "unknown";
  const v = payload[p.kindClaim.name];
  return typeof v === "string" && Object.hasOwn(p.kindClaim.values, v) ? p.kindClaim.values[v] : "unknown";
}
export interface IdentityResolver { resolve(request: Request): Promise<Principal> }
/** Construct once per environment/runtime. JWKS caches are provider-scoped, bounded and reused.
 * The unverified issuer is used only to choose an existing configuration; it never chooses a URL. */
export function createIdentityResolver(configuration: readonly IdentityProviderConfig[], options: {fetcher?: typeof fetch; now?: () => number} = {}): IdentityResolver {
  const providers = parseIdentityProviders(configuration), now = options.now ?? Date.now;
  const lookup = new Map<string, {config: IdentityProviderConfig; keys: ReturnType<typeof createRemoteJWKSet>}>();
  for (const config of providers) {
    const uri = config.kind === "oidc" ? config.jwksUri : `${config.issuer}/cdn-cgi/access/certs`;
    const pinned = new URL(uri);
    const keys = createRemoteJWKSet(pinned, {
      timeoutDuration: 3000, cooldownDuration: 30000, cacheMaxAge: 300000,
      [customFetch]: async (url, init) => {
        if (new URL(url).href !== pinned.href) throw new GatekeeperError("UntrustedJwksOrigin", "JWKS request escaped configured endpoint");
        const signal = AbortSignal.timeout(3000);
        const response = await (options.fetcher ?? fetch)(url, {...init, redirect: "manual", signal});
        const raw = await readBoundedJson(response);
        if (!record(raw) || !Array.isArray(raw.keys) || raw.keys.length < 1 || raw.keys.length > 64) throw new GatekeeperError("InvalidJwks", "Invalid key set");
        return Response.json(raw);
      },
    });
    lookup.set(JSON.stringify([config.kind, config.issuer]), {config, keys});
  }
  return {async resolve(request): Promise<Principal> {
    const bearer = request.headers.get("authorization"), access = request.headers.get("cf-access-jwt-assertion");
    if (bearer !== null && access !== null) throw new GatekeeperError("AmbiguousCredentials", "Choose one credential transport");
    if (bearer === null && access === null) {
      if (request.headers.has("cf-access-client-id") || request.headers.has("cf-access-client-secret") || /(?:^|;\s*)CF_Authorization=/.test(request.headers.get("cookie") ?? "")) invalid();
      return anonymous();
    }
    try {
      let token: string;
      if (bearer !== null) {
        const match = /^Bearer ([A-Za-z0-9_.-]+)$/i.exec(bearer);
        if (!match) return invalid();
        token = compactToken(match[1]);
      } else token = compactToken(access!);
      const hint = decodeJwt(token);
      const selected = lookup.get(JSON.stringify([bearer !== null ? "oidc" : "cloudflare-access", hint.iss]));
      if (!selected) return invalid();
      const {config, keys} = selected;
      const timestamp = now();
      if (!Number.isFinite(timestamp) || timestamp < 0) return invalid();
      const {payload, protectedHeader} = await jwtVerify(token, keys, {
        issuer: config.issuer, audience: config.audience,
        algorithms: config.kind === "oidc" ? [...config.algorithms] : ["RS256"],
        requiredClaims: ["iss", "aud", "sub", "iat", "exp"],
        currentDate: new Date(timestamp), clockTolerance: 5,
      });
      if (protectedHeader.jku || protectedHeader.jwk || protectedHeader.x5u || payload.cnf !== undefined || payload.act !== undefined) return invalid();
      const issued = payload.iat!, expires = payload.exp!, current = now();
      if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires) || issued < 0 || expires <= issued ||
          expires - issued > (config.maxTokenLifetimeSeconds ?? (config.kind === "oidc" ? 900 : 86400)) ||
          issued * 1000 > current + 5000 || expires * 1000 <= current ||
          (payload.nbf !== undefined && (!Number.isSafeInteger(payload.nbf) || payload.nbf * 1000 > current))) return invalid();
      const audiences = typeof payload.aud === "string" ? [payload.aud] : payload.aud!;
      if (!Array.isArray(audiences) || audiences.length > 32 || audiences.some(a => !claimText(a))) return invalid();
      let subject: string, namespace: Principal["subjectNamespace"] = "sub", kind: PrincipalKind, mfa = false;
      let clientId: string | undefined;
      let scopes: string[] = [];
      if (config.kind === "oidc") {
        const profile = config.accessTokenProfile;
        if (profile.kind === "rfc9068") {
          if (!["at+jwt", "application/at+jwt"].includes(protectedHeader.typ?.toLowerCase() ?? "") || !claimText(payload.client_id) || !claimText(payload.jti)) return invalid();
        } else if (payload[profile.markerClaim] !== profile.markerValue) return invalid();
        if (payload.nonce !== undefined || !claimText(payload.sub)) return invalid();
        subject = payload.sub;
        if (payload.client_id !== undefined && !claimText(payload.client_id)) return invalid();
        clientId = payload.client_id as string | undefined;
        if (config.allowedClientIds && (!clientId || !config.allowedClientIds.includes(clientId))) return invalid();
        if (payload.scope !== undefined) {
          if (typeof payload.scope !== "string" || payload.scope.length > 8192) return invalid();
          scopes = payload.scope.split(" ").filter(Boolean);
          if (scopes.length > 256 || scopes.some(s => !/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/.test(s))) return invalid();
        }
        kind = subjectKind(config, payload);
        const assurance = config.mfa, authTime = payload.auth_time;
        mfa = kind === "human" && !!assurance && typeof payload.acr === "string" && assurance.acrValues.includes(payload.acr) &&
          typeof authTime === "number" && Number.isSafeInteger(authTime) && authTime * 1000 <= current &&
          current - authTime * 1000 < assurance.maxAgeSeconds * 1000;
      } else {
        if (payload.type !== "app") return invalid();
        if (claimText(payload.sub) && payload.common_name === undefined) {subject = payload.sub; kind = "human";}
        else if (payload.sub === "" && claimText(payload.common_name)) {subject = payload.common_name; namespace = "access-service-token"; kind = "service"; clientId = subject;}
        else return invalid();
      }
      const handle = config.handleClaim && typeof payload[config.handleClaim] === "string" && (payload[config.handleClaim] as string).length <= 320 ? payload[config.handleClaim] as string : undefined;
      return {id: principalId(config.issuer, subject, namespace), providerId: config.id, issuer: config.issuer,
        subject, subjectNamespace: namespace, kind, expiresAt: expires * 1000, mfa, ...(handle ? {handle} : {}),
        authentication: {credentialType: config.kind === "oidc" ? "oauth-access-token" : "cloudflare-access", issuedAt: issued * 1000,
          audiences, scopes, ...(clientId ? {clientId} : {})}};
    } catch (e) {
      if (e instanceof GatekeeperError && ["UpstreamUnavailable", "InvalidJwks", "InvalidDocument", "InputBudgetExceeded"].includes(e.code))
        throw new GatekeeperError("IdentityUnavailable", "Identity key service unavailable");
      if (!(e instanceof GatekeeperError) && (!record(e) || typeof e.code !== "string" || e.code === "ERR_JWKS_TIMEOUT"))
        throw new GatekeeperError("IdentityUnavailable", "Identity key service unavailable");
      return invalid();
    }
  }};
}
