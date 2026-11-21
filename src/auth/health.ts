/**
 * GET /healthz. `ok` and `active` are what the hosted installer checks (src/installer/verify-idp.ts).
 * NATH-17: `detail.socialProviders.unavailableCount` is how many configured, enabled social
 * providers have credentials that cannot be used. /healthz is public, so it says nothing about which
 * providers or why: Identity Studio (GET /studio/api/providers) shows the provider ids and reason
 * codes to administrators. The Worker itself stays healthy: other sign-in methods keep working while
 * one provider is off, so monitor the count rather than `ok`.
 */
import type { AuthEnv } from "./env";
import { loadSocialProviderState } from "./provider-config.mjs";

export async function healthResponse(env: AuthEnv): Promise<Response> {
  let socialProviders: { unavailableCount: number | null; error?: string };
  try {
    const { unavailable } = await loadSocialProviderState(env) as { unavailable: unknown[] };
    socialProviders = { unavailableCount: unavailable.length };
  } catch {
    socialProviders = { unavailableCount: null, error: "Provider status unavailable" };
  }
  return Response.json({ ok: true, system: "nathan", active: env.NATHAN_INSTALL_ACTIVE !== "false", detail: { socialProviders } },
    { headers: { "Cache-Control": "no-store" } });
}
