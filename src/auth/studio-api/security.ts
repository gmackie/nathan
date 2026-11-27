/** NATH-24 Studio API v1: the effective admin security policy (read, tighten only). */
import { effectiveAdminPolicy, tightenAdminPolicy } from "../security-policy";
import type { StudioRoute } from "./router";
import { noInput, securityPolicyTightenInput } from "./schemas";

export const routes: StudioRoute[] = [
  { method: "GET", path: "/security-policy", action: "security-policy.read", input: noInput, run: ({ env }) => effectiveAdminPolicy(env) },
  { method: "POST", path: "/security-policy/tighten", action: "security-policy.tighten", input: securityPolicyTightenInput, maxBytes: 2048,
    fallback: "Verify the required authenticator first. A passkey-only policy requires the owner and every enabled administrator to have a passkey.",
    // Tightening checks the administrator's own recent passkey session, so it needs a Nathan session.
    run: ({ env, actor, principal }, body) => tightenAdminPolicy(env, body, actor, principal.sessionId) }
];
