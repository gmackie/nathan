/**
 * NATH-13 security review: the NathanVerifier service binding is app-scoped.
 *
 * Gateways and API Workers bind the identity Worker's NathanVerifier entrypoint. Each binding pins
 * the one application it may ask about in its binding props, which the account owner sets in the
 * calling Worker's wrangler config and which the caller's code cannot change at runtime:
 *
 *   "services": [{ "binding": "NATHAN", "service": "nathan-auth", "entrypoint": "NathanVerifier",
 *                  "props": { "applicationId": "billing" } }]
 *
 * A binding answers only for that application. A binding without a valid pinned application, or a
 * request for any other application, is denied with no roles, permissions or profile data. The
 * directory (every principal and the change feed) is not reachable over this binding at all; it is
 * served only by the authenticated GET /directory/v1/* API (nathan:directory.read client credentials).
 */
import { isAppId } from "../shared/policy.mjs";

export type BindingProps = { applicationId?: unknown } | undefined | null;
export type ScopedApplication = { ok: true; app: string } | { ok: false; reason: "binding_not_pinned" | "application_mismatch" };

/** The application a binding is pinned to, or null when its props do not name a valid one. */
export function pinnedApplication(props: BindingProps): string | null {
  const app = props && typeof props === "object" ? props.applicationId : undefined;
  return isAppId(app) ? app as string : null;
}

/**
 * The application a call may be answered for. `requested` may be omitted (the pinned app is used);
 * when given it must equal the pinned app exactly.
 */
export function scopedApplication(props: BindingProps, requested: unknown): ScopedApplication {
  const app = pinnedApplication(props);
  if (!app) return { ok: false, reason: "binding_not_pinned" };
  if (requested !== undefined && requested !== null && requested !== app) return { ok: false, reason: "application_mismatch" };
  return { ok: true, app };
}

/** The answer for a call outside the binding's scope: nothing allowed, nothing disclosed. */
export function outOfScope(reason: string) {
  return { allowed: false, reason, roles: [] as string[], permissions: [] as string[], email: null, observedAt: new Date().toISOString() };
}
