export interface AuthEnv {
  DB: D1Database;
  BETTER_AUTH_SECRET: string;
  NATHAN_ISSUER: string;
  NATHAN_ADMIN_EMAILS: string;
  ENABLE_PASSWORD: string;
  ENTERPRISE_SSO: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  NATHAN_PAIRWISE_SECRET?: string;
}
