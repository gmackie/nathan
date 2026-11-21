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
  /** NATH-13: service binding to the identity Worker's NathanVerifier entrypoint. */
  NATHAN?: NathanAccessService;
  /** NATH-13: >= 32 random bytes base64url, shared only with this gateway's upstream Worker. */
  NATHAN_PRINCIPAL_KEY?: string;
  /** NATH-13: seconds to reuse a session's resolved access, 0..60 (default 30). */
  ACCESS_CACHE_TTL_SECONDS?: string;
}
export type AccessDecision = { allowed: boolean; reason?: string; roles: string[]; permissions: string[]; email?: string | null };
export interface NathanAccessService {
  resolveAccess(input: { applicationId: string; subject: string }): Promise<AccessDecision>;
}
