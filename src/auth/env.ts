/** Request-local, verified Access email. A deployed binding cannot supply this symbol. */
export const managementEmail = Symbol("managementEmail");
export const ownerInvitation = Symbol("ownerInvitation");

export interface AuthEnv {
  [managementEmail]?: string;
  [ownerInvitation]?: string;
  DB: D1Database;
  SCIM_DIRECTORY?: DurableObjectNamespace;
  /** NATH-11: SCIM requests per minute per connection (default 600). */
  NATHAN_SCIM_RATE_LIMIT?: string;
  NATHAN_INSTALL_ACTIVE?: string;
  /** Dedicated application's ID, pinned separately in its service bindings. */
  NATHAN_APP_ID?: string;
  NATHAN_MCP_WRITE_ENABLED?: string;
  BETTER_AUTH_SECRET: string;
  NATHAN_CONFIG_KEY?: string;
  NATHAN_SECURITY_PROFILE?: "standard"|"business"|"high";
  NATHAN_BOOTSTRAP_REQUIRED?: string;
  NATHAN_ADMIN_STEPUP_REQUIRED?: string;
  NATHAN_ADMIN_STEPUP_METHOD?: string;
  NATHAN_ISSUER: string;
  /** Dedicated installation. NATHAN_ISSUER is the management origin; the named app binding serves NATHAN_APP_ORIGIN. */
  NATHAN_APP_ORIGIN?: string;
  /** Shared issuer's optional Access-protected Studio origin, https://admin.<issuer host>. */
  NATHAN_ADMIN_ORIGIN?: string;
  NATHAN_ACCESS_TEAM_DOMAIN?: string;
  NATHAN_ACCESS_AUD?: string;
  /** NATH-43: what users see this identity provider called (TOTP issuer, appName, passkey name); default "Nathan". */
  NATHAN_INSTANCE_NAME?: string;
  /** NATH-43: passkey relying-party display name override (defaults to NATHAN_INSTANCE_NAME); the rpID is the issuer hostname. */
  NATHAN_PASSKEY_RP_NAME?: string;
  NATHAN_REALM_APEX?: string;
  NATHAN_ADMIN_EMAILS: string;
  ENABLE_PASSWORD: string;
  /** NATH-49: "true" enables passwordless email sign-in codes (off by default; needs RESEND_API_KEY and EMAIL_FROM). */
  ENABLE_EMAIL_OTP?: string;
  /**
   * NATH-52: "single-app" lets the pinned app worker run email sign-in over the
   * service binding and draw its own UI. Unset on a shared IdP (id.gmac.io).
   */
  AUTH_MODE?: string;
  ENTERPRISE_SSO: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  // NATH-9: optional JSON credential bundles written by `nathan providers add <id> --apply`.
  NATHAN_PROVIDER_GOOGLE?: string;
  NATHAN_PROVIDER_GITHUB?: string;
  NATHAN_PROVIDER_APPLE?: string;
  NATHAN_PROVIDER_DISCORD?: string;
  NATHAN_PROVIDER_TWITCH?: string;
  NATHAN_PROVIDER_TWITTER?: string;
  NATHAN_APPEARANCE?: string;
  /** Operator-installed, sanitized PNGs keyed by validated appearance.logo id (base64). */
  NATHAN_EMAIL_LOGOS?: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  NATHAN_PAIRWISE_SECRET?: string;
}

/** Browser redirects and same-origin checks use the verified entrypoint. Protocol audiences
 * and downstream application configuration always use NATHAN_ISSUER. */
export function browserOrigin(env: AuthEnv): string {
  return new URL(env[managementEmail] && env.NATHAN_ADMIN_ORIGIN ? env.NATHAN_ADMIN_ORIGIN : env.NATHAN_ISSUER).origin;
}

/** Shared issuers allow self-service enrollment before an administrator grant. */
export function allowsAdminTotp(env: AuthEnv) {
  return env.NATHAN_APP_ID === undefined && env.NATHAN_APP_ORIGIN === undefined &&
    env.NATHAN_SECURITY_PROFILE === "standard" && env.NATHAN_ADMIN_STEPUP_REQUIRED === "true" &&
    env.NATHAN_ADMIN_STEPUP_METHOD === "passkey-or-totp";
}
