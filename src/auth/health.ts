/**
 * GET /healthz. `ok` and `active` are what the hosted installer checks (src/installer/verify-idp.ts).
 * NATH-17: `detail.socialProviders.unavailable` lists configured, enabled social providers whose
 * credentials cannot be used, as provider id and reason code only (never a client id or secret).
 * The Worker itself stays healthy: other sign-in methods keep working while one provider is off.
 */
import type { AuthEnv } from "./env";
import { loadSocialProviderState } from "./provider-config.mjs";

export async function healthResponse(env: AuthEnv): Promise<Response> {
  let socialProviders: { unavailable: { id: string; reason: string }[] | null; error?: string };
  try {
    const { unavailable } = await loadSocialProviderState(env) as { unavailable: { id: string; reason: string }[] };
    socialProviders = { unavailable: unavailable.map(({ id, reason }) => ({ id, reason })) };
  } catch {
    socialProviders = { unavailable: null, error: "Provider status unavailable" };
  }
  return Response.json({ ok: true, system: "nathan", active: env.NATHAN_INSTALL_ACTIVE !== "false", detail: { socialProviders } },
    { headers: { "Cache-Control": "no-store" } });
}
