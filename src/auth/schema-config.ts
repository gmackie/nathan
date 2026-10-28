/**
 * Build-time Better Auth configuration for reproducible SQL schema generation.
 * Must mirror the plugins used by src/auth/instance.ts.
 * Never deploy this Node.js-only file to Cloudflare Workers.
 */
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { admin, jwt, organization, twoFactor } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";
import { sso } from "@better-auth/sso";

export const auth = betterAuth({
  database: new DatabaseSync(":memory:"),
  baseURL: "https://auth.example.com",
  basePath: "/api/auth",
  secret: "SCHEMA_GENERATOR_ONLY_NOT_A_DEPLOYMENT_SECRET_123456789",
  emailAndPassword: { enabled: true, requireEmailVerification: true },
  plugins: [
    admin(),
    organization(),
    twoFactor(),
    passkey({ rpID: "auth.example.com", rpName: "Nathan" }),
    jwt(),
    oauthProvider({
      loginPage: "/sign-in", consentPage: "/consent",
      scopes: ["openid","profile","email","offline_access"],
      allowDynamicClientRegistration: false
    }),
    // Generate a superset schema even when SSO is disabled for a deployment.
    sso({ saml: { enableInResponseToValidation: true, allowIdpInitiated: false, requireTimestamps: true } })
  ]
});
