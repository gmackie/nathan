/** NATH-24 Studio API v1: instance status and the candidate plugin catalog (reads). */
import type { AuthEnv } from "../env";
import { providerStatus } from "../provider-store";
import { bootstrapStatus } from "../bootstrap";
import pluginCatalog from "../../../plugins/catalog.json" with { type: "json" };
import type { StudioRoute } from "./router";
import { noInput } from "./schemas";

/** The Studio status summary (shared with the legacy GET /studio/api/status). */
export async function studioStatus(env: AuthEnv) {
  const issuer = new URL(env.NATHAN_ISSUER);
  return {
    issuer: issuer.origin + "/api/auth",
    providers: Object.fromEntries((await providerStatus(env)).map(p => [p.id, p.enabled])),
    features: { oidcProvider: true, passkeys: true, totp: true, enterpriseSso: env.ENTERPRISE_SSO === "true", password: env.ENABLE_PASSWORD === "true", scimDirectory: Boolean(env.SCIM_DIRECTORY) },
    note: "Authentication assurance level enforcement and guided plugin installation are not yet available"
  };
}

export { pluginCatalog };

export const routes: StudioRoute[] = [
  { method: "GET", path: "/status", action: "status.read", input: noInput, run: ({ env }) => studioStatus(env) },
  { method: "GET", path: "/plugins", action: "plugins.read", input: noInput, run: async () => pluginCatalog },
  // NATH-39: the Studio Overview's admin setup card. The administrator's own bootstrap and
  // authenticator enrollment state (counts and flags only; the same object GET
  // /security/api/bootstrap returns to the account page), behind the full admin authorization.
  { method: "GET", path: "/bootstrap", action: "bootstrap.read", input: noInput, run: ({ env, principal }) => bootstrapStatus(env, principal.userId) }
];
