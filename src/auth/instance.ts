import { betterAuth } from "better-auth";
import {createAuthMiddleware} from "better-auth/api";
import { admin, jwt, organization, twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { sendAuthEmail } from "./email";
import type { AuthEnv } from "./env";
import type { SocialCredentials } from "./provider-store";
import {mayAdminister} from "./bootstrap";
import {isAdminPrincipal} from "./admin-service";

export function createAuth(env: AuthEnv, resolvedSocialProviders?: SocialCredentials) {
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
    // Federated tokens are sensitive; encrypt them in D1 and keep OAuth state server-side.
    account: { encryptOAuthTokens: true, storeStateStrategy: "database" },
    disabledPaths: ["/token"],
    hooks: {
      after: createAuthMiddleware(async (ctx) => {
        // Passkey enrollment never grants admin assurance. Only a newly
        // verified passkey sign-in with a freshly issued session does.
        if(ctx.path!=="/passkey/verify-authentication")return;
        const session=ctx.context.newSession;
        if(!session?.session?.id || !session.user?.id)return;
        await env.DB.prepare(
          "INSERT INTO nathan_admin_assurance(session_id,user_id,method,verified_at) "+
          "VALUES (?,?,'passkey',unixepoch()) "+
          "ON CONFLICT(session_id) DO UPDATE SET user_id=excluded.user_id,method='passkey',verified_at=unixepoch()"
        ).bind(session.session.id,session.user.id).run();
      })
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 100,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/oauth2/token": { window: 60, max: 30 }
      }
    },
    trustedOrigins: [issuer.origin],
    socialProviders: resolvedSocialProviders ?? socialProviders,
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
      // The IdP's session is strictly host-only on login.<domain>.
      // Never turn on cross-subdomain cookies to implement OIDC SSO.
      cookiePrefix: "nathan",
      useSecureCookies: true,
      crossSubDomainCookies: { enabled: false },
      ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] },
      database: { joins: false }
    },
    plugins: [
      admin(),
      organization(),
      twoFactor({ allowPasswordless: true }),
      passkey({ rpID: issuer.hostname, rpName: "Nathan" }),
      jwt({disableSettingJwtHeader:true,jwks:{rotationInterval:30*24*60*60,gracePeriod:30*24*60*60}}),
      oauthProvider({
        loginPage: "/sign-in",
        consentPage: "/consent",
        scopes: ["openid", "profile", "email", "offline_access", "nathan:read", "nathan:admin"],
        resources: [{
          identifier: issuer.origin + "/mcp",
          allowedScopes: ["nathan:read", "nathan:admin"],
          accessTokenTtl: 300
        }],
        scopeExpirations: {"nathan:read":"15m","nathan:admin":"5m"},
        allowDynamicClientRegistration: false,
        allowUnauthenticatedClientRegistration: false,
        // Public dynamic registration is disabled; only verified and allowlisted
        // Nathan admins may use Better Auth's authenticated client CRUD API.
        clientPrivileges: async ({ user, session }) => {
          return Boolean(user && await isAdminPrincipal(user,env) && await mayAdminister(env,user.id,session?.id));
        },
        ...(env.NATHAN_PAIRWISE_SECRET ? { pairwiseSecret: env.NATHAN_PAIRWISE_SECRET } : {})
      }),
      ...(env.ENTERPRISE_SSO === "true" ? [sso({
        domainVerification: { enabled: true },
        saml: {
          enableInResponseToValidation: true,
          allowIdpInitiated: false,
          requireTimestamps: true
        }
      })] : [])
    ]
  });
}
