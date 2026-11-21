import { fetchNoRedirect } from "../shared/security.mjs";

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;
const noRedirect: Fetch = (url, init) => fetchNoRedirect(url, init);

/**
 * Confirms a freshly installed identity Worker is live and issuing for the expected issuer.
 * Better Auth serves OIDC discovery under the issuer path (/api/auth), per OIDC Discovery §4,
 * and the JWKS location must come from that document rather than be guessed.
 */
export async function verifyIdentityHostname(hostname: string, fetcher: Fetch = noRedirect): Promise<void> {
  const origin = "https://" + hostname;
  const issuer = origin + "/api/auth";
  const get = (url: string) => fetcher(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(7000) });
  const [health, discovery] = await Promise.all([get(origin + "/healthz"), get(issuer + "/.well-known/openid-configuration")]);
  if (!health.ok) throw Error("Identity hostname not healthy yet (" + health.status + "); check route, secrets and DNS propagation");
  const status = await health.json() as { active?: boolean };
  if (status.active !== true) throw Error("Identity Worker is reachable but not activated");
  if (!discovery.ok) throw Error("OIDC discovery unavailable (" + discovery.status + ") at " + issuer + "/.well-known/openid-configuration");
  const metadata = await discovery.json() as { issuer?: string; jwks_uri?: string };
  if (metadata.issuer !== issuer) throw Error("OIDC issuer mismatch: expected " + issuer);
  if (typeof metadata.jwks_uri !== "string") throw Error("OIDC discovery has no jwks_uri");
  const jwksUrl = new URL(metadata.jwks_uri);
  if (jwksUrl.protocol !== "https:" || jwksUrl.origin !== origin) throw Error("JWKS must be served by the identity hostname");
  const jwks = await get(jwksUrl.href);
  if (!jwks.ok) throw Error("JWKS unavailable (" + jwks.status + ")");
  const keys = await jwks.json() as { keys?: unknown[] };
  if (!Array.isArray(keys.keys) || keys.keys.length === 0) throw Error("JWKS has no signing keys yet");
}
