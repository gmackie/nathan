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
  NATHAN_ISSUER: string;
  /** Dedicated installation. NATHAN_ISSUER is the management origin; the named app binding serves NATHAN_APP_ORIGIN. */
  NATHAN_APP_ORIGIN?: string;
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
