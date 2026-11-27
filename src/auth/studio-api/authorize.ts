/**
 * NATH-24: the single authorization decision for the Studio API v1.
 *
 * Today there is one principal kind, `nathan-admin`: a Nathan session whose user is a verified,
 * explicitly granted administrator (isAdminPrincipal) and who passes the admin assurance policy
 * (adminAssurance = mayAdminister: completed bootstrap, enrolled authenticators and, when the policy
 * requires it, a passkey verification in the last 15 minutes). These are the exact checks the legacy
 * `/studio/api/*` routes make; this function only reports which one failed.
 *
 * Planned principal kinds plug in here and nowhere else:
 *   - NATH-25: Cloudflare Access admin mode (Access JWT verified in-Worker + email allowlist).
 *   - NATH-27: a parent Nathan's scoped client_credentials token (fleet management).
 * Each route passes its `action`, so a scoped principal can be limited to named actions.
 */
import { browserOrigin, type AuthEnv } from "../env";
import { isAdminPrincipal } from "../admin-service";
import { adminAssurance } from "../bootstrap";
import { StudioApiError, studioError } from "./http";

export type NathanAdminPrincipal = { kind: "nathan-admin"; userId: string; email: string; sessionId: string };
/** Discriminated by `kind`; NATH-25 and NATH-27 add members. */
export type StudioPrincipal = NathanAdminPrincipal;

/**
 * Step-up requirement of a route. `admin-policy` is the deployment and runtime admin policy
 * (effectiveAdminPolicy): what every Studio route requires today.
 */
export type StudioStepUp = "admin-policy";

export type StudioAuthorizeOptions = { action: string; write: boolean; stepUp: StudioStepUp };
export type StudioAuthorization = { ok: true; principal: StudioPrincipal } | { ok: false; error: StudioApiError };

/** The audit actor for a principal: the administrator's user id, as on the legacy routes. */
export function auditActor(principal: StudioPrincipal): string {
  return principal.userId;
}

/**
 * Same-origin checks for writes run first (before any session lookup), as on the legacy routes:
 * the Origin must be the issuer origin, Sec-Fetch-Site must not be cross-site, and the body JSON.
 */
export async function authorizeStudioRequest(request: Request, env: AuthEnv, auth: any, options: StudioAuthorizeOptions): Promise<StudioAuthorization> {
  const deny = (status: number, code: StudioApiError["code"], message: string) => ({ ok: false as const, error: studioError(status, code, message) });
  if (options.write) {
    if (request.headers.get("Origin") !== browserOrigin(env) || request.headers.get("Sec-Fetch-Site") === "cross-site")
      return deny(403, "cross_origin", "Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json")
      return deny(415, "unsupported_media_type", "JSON required");
  }
  const session = await auth.api.getSession({ headers: request.headers });
  const user = session?.user, sessionId = session?.session?.id;
  if (!user || typeof user.id !== "string" || typeof sessionId !== "string")
    return deny(401, "unauthenticated", "Sign in to Nathan first");
  if (!await isAdminPrincipal(user, env))
    return deny(403, "not_admin", "Verified administrator required");
  if (options.stepUp !== "admin-policy") return deny(403, "step_up_required", "Unknown step-up requirement");
  const assurance = await adminAssurance(env, user.id, sessionId);
  if (!assurance.ok && assurance.reason === "session_required")
    return deny(403, "not_admin", "Sign in with an administrator authenticator");
  if (!assurance.ok)
    return assurance.reason === "step_up_required"
      ? deny(403, "step_up_required", "Verify your administrator authenticator again to continue. Verification lasts 15 minutes.")
      : deny(403, "enrollment_incomplete", "Complete admin setup and authenticator enrollment first");
  return { ok: true, principal: { kind: "nathan-admin", userId: user.id, email: user.email, sessionId } };
}
