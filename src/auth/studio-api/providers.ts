/** NATH-24 Studio API v1: social sign-in providers (encrypted D1 credentials, enable, test sign-in). */
import { providerStatus, upsertSocialProvider, setSocialProviderEnabled, beginProviderTest } from "../provider-store";
import type { StudioRoute } from "./router";
import { rejected } from "./http";
import { noInput, providerUpsertInput, providerStatusInput, providerTestInput } from "./schemas";

/** Only registry/rule errors carry a publicMessage; they never contain submitted values. */
export function providerRefusalMessage(error: unknown) {
  const safe = (error as { publicMessage?: unknown })?.publicMessage;
  return typeof safe === "string" ? safe : "Provider update denied. Check configuration encryption key and remaining login/recovery methods.";
}
const refusal = (error: unknown) => rejected(providerRefusalMessage(error));

export const routes: StudioRoute[] = [
  { method: "GET", path: "/providers", action: "providers.read", input: noInput, run: async ({ env }) => ({ providers: await providerStatus(env) }) },
  { method: "POST", path: "/providers", action: "providers.upsert", input: providerUpsertInput, maxBytes: 16384, refusal,
    run: ({ env, actor }, body) => upsertSocialProvider(env, body, actor) },
  { method: "POST", path: "/providers/status", action: "providers.status", input: providerStatusInput, maxBytes: 16384, refusal,
    run: ({ env, actor }, body) => setSocialProviderEnabled(env, body, actor) },
  { method: "POST", path: "/providers/test", action: "providers.test", input: providerTestInput, maxBytes: 16384, refusal,
    run: ({ env, actor }, body) => beginProviderTest(env, body, actor) }
];
