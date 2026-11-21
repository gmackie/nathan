/**
 * NATH-16: Nathan policy for accounts created by enterprise OIDC SSO (@better-auth/sso,
 * /sso/callback/:providerId). Plain JS so it is unit-tested in Node and bundled into the Worker.
 *
 * Nathan runs the plugin with trustEmailVerified: false, so an IdP's email_verified claim is never
 * proof. Like SAML (saml-policy.mjs → samlUserCreateGuard), the only proof is the connection's
 * DNS-verified domain: an enterprise OIDC sign-in creates an account only for an address inside the
 * verified domain of the connection it came through, and that address then counts as verified (so
 * it can claim an invitation). Any other address, an unverified domain, a SAML connection reached
 * through the OIDC callback, or an /sso/ route this guard does not understand creates no account.
 */
import { emailInDomain } from "./saml-policy.mjs";

/** Better Auth endpoint path (route template) of the enterprise OIDC callback. */
export const OIDC_CALLBACK_ENDPOINT = "/sso/callback/:providerId";

/** True for Better Auth endpoint paths that belong to enterprise SSO but not to SAML. */
export function isEnterpriseOidcPath(path) {
  return typeof path === "string" && path.startsWith("/sso/") && !path.includes("/saml2/");
}

/**
 * databaseHooks.user.create.before for enterprise OIDC. Returns undefined for other flows (no
 * change), false to refuse the account, or `{ data: { emailVerified: true } }` for an address the
 * connection's verified domain proves.
 */
export async function enterpriseOidcUserCreateGuard(db, user, ctx) {
  const path = typeof ctx?.path === "string" ? ctx.path : "";
  if (!isEnterpriseOidcPath(path)) return undefined;
  if (path !== OIDC_CALLBACK_ENDPOINT) return false;
  const providerId = typeof ctx?.params?.providerId === "string" ? ctx.params.providerId : "";
  if (!/^[a-z][a-z0-9-]{1,62}$/.test(providerId)) return false;
  const row = await db.prepare(
    'SELECT "domain" AS domain, "domainVerified" AS verified FROM "ssoProvider" ' +
    'WHERE "providerId"=? AND "oidcConfig" IS NOT NULL AND "samlConfig" IS NULL LIMIT 1'
  ).bind(providerId).first();
  if (!row || Number(row.verified) !== 1) return false;
  if (!emailInDomain(user?.email, row.domain)) return false;
  return { data: { emailVerified: true } };
}
