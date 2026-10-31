export interface GatewayEnv {
  SESSIONS: D1Database;
  UPSTREAM: Fetcher;
  NATHAN_ISSUER: string;
  PUBLIC_ORIGIN: string;
  APPLICATION_ID: string;
  OIDC_CLIENT_ID: string;
  OIDC_CLIENT_SECRET: string;
  SESSION_ENCRYPTION_KEY: string;
  SESSION_TTL_SECONDS?: string;
  REQUIRE_AAL2?: string;
  ACCEPTED_ACRS?: string;
}
