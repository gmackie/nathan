import { betterAuth } from "better-auth";
import { admin, jwt, organization, twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { sendAuthEmail } from "./email";
import type { AuthEnv } from "./env";

export function createAuth(env: AuthEnv) {
  const issuer = new URL(env.NATHAN_ISSUER);
  if (issuer.protocol !== "https:" && issuer.hostname !== "localhost")
    throw new Error("Nathan requires an HTTPS identity hostname");
  if (!env.BETTER_AUTH_SECRET || env.BETTER_AUTH_SECRET.length < 32)
    throw new Error("BETTER_AUTH_SECRET must have at least 32 characters");

  const socialProviders = {
    ...(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
      ? { google: { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET } } : {}),
    ...(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
      ? { github: { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET } } : {})
  };

  return betterAuth({
    baseURL: issuer.origin,
    basePath: "/api/auth",
    secret: env.BETTER_AUTH_SECRET,
    database: env.DB,
    trustedOrigins: [issuer.origin],
    socialProviders,
    emailAndPassword: {
      enabled: env.ENABLE_PASSWORD === "true",
      requireEmailVerification: true,
      sendResetPassword: async ({ user, url }) =>
        sendAuthEmail(env, user.email, "Reset your Nathan password", url)
    },
    emailVerification: {
      sendVerificationEmail: async ({ user, url }) =>
        sendAuthEmail(env, user.email, "Verify your Nathan email", url)
    },
    advanced: {
      database: { joins: false }
    },
    plugins: [
      admin(),
      organization(),
      twoFactor(),
      passkey({ rpID: issuer.hostname, rpName: "Nathan" }),
      jwt(),
      oauthProvider({
        loginPage: "/sign-in",
        consentPage: "/consent",
        scopes: ["openid", "profile", "email", "offline_access"],
        allowDynamicClientRegistration: false,
        allowUnauthenticatedClientRegistration: false,
        ...(env.NATHAN_PAIRWISE_SECRET ? { pairwiseSecret: env.NATHAN_PAIRWISE_SECRET } : {})
      }),
      ...(env.ENTERPRISE_SSO === "true" ? [sso({
        saml: {
          enableInResponseToValidation: true,
          allowIdpInitiated: false,
          requireTimestamps: true
        }
      })] : [])
    ]
  });
}
