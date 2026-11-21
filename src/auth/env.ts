export interface AuthEnv {
  DB: D1Database;
  SCIM_DIRECTORY?: DurableObjectNamespace;
  NATHAN_INSTALL_ACTIVE?: string;
  NATHAN_MCP_WRITE_ENABLED?: string;
  BETTER_AUTH_SECRET: string;
  NATHAN_CONFIG_KEY?: string;
  NATHAN_SECURITY_PROFILE?: "standard"|"business"|"high";
  NATHAN_BOOTSTRAP_REQUIRED?: string;
  NATHAN_ADMIN_STEPUP_REQUIRED?: string;
  NATHAN_ISSUER: string;
  NATHAN_REALM_APEX?: string;
  NATHAN_ADMIN_EMAILS: string;
  ENABLE_PASSWORD: string;
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
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  NATHAN_PAIRWISE_SECRET?: string;
}
