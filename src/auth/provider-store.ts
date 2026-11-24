import type { AuthEnv } from "./env";
import { audit, isAdminPrincipal } from "./admin-service";
import { buildSocialProviders, PROVIDER_IDS, signInLabel } from "../shared/providers.mjs";
import * as config from "./provider-config.mjs";

/** Better Auth `socialProviders` built from the shared registry (NATH-9). */
export type SocialCredentials = Record<string, any>;
export type ProviderId = typeof PROVIDER_IDS[number];

/** Read on every auth request: provider disable and rotation take effect immediately. */
export async function loadSocialCredentials(env: AuthEnv): Promise<SocialCredentials> {
  const resolved = await config.loadSocialProviderCredentials(env) as Record<string, { clientId: string; clientSecret: string }>;
  return buildSocialProviders(resolved);
}
/** Enabled provider ids in registry order (sign-in page buttons). */
export function enabledProviderIds(providers: SocialCredentials): string[] {
  return PROVIDER_IDS.filter(id => Boolean(providers[id]));
}
/** Sign-in button text per enabled provider; the Nathan upstream uses its configured name (NATH-51). */
export function providerLabels(providers: SocialCredentials): Record<string, string> {
  return Object.fromEntries(enabledProviderIds(providers).map(id => [id, signInLabel(id, providers[id]?.displayName)]));
}
/** Audit sink and the authoritative admin predicate (also used for the last-login-method rule). */
function deps(env: AuthEnv) {
  return { audit, isAdmin: (user: unknown) => isAdminPrincipal(user, env) };
}
export async function providerStatus(env: AuthEnv) {
  return config.providerStatus(env, deps(env));
}
export async function upsertSocialProvider(env: AuthEnv, input: any, actor: string) {
  return config.upsertSocialProvider(env, input, actor, deps(env));
}
export async function setSocialProviderEnabled(env: AuthEnv, input: any, actor: string) {
  return config.setSocialProviderEnabled(env, input, actor, deps(env));
}
export async function beginProviderTest(env: AuthEnv, input: any, actor: string) {
  return config.beginProviderTest(env, input, actor, deps(env));
}
export async function completeProviderTest(env: AuthEnv, ticket: string | null, session: { sessionId: string; userId: string } | null) {
  return config.completeProviderTest(env, ticket, session, deps(env));
}
export async function recordProviderSignIn(env: AuthEnv, evidence: { providerId: string; sessionId: string; userId: string }) {
  return config.recordProviderSignIn(env, evidence);
}
