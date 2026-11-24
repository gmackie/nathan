import { betterAuth } from "better-auth";
import { passkeyRpName, instanceName } from "./passkey-config.mjs";
import {APIError, createAuthMiddleware, getSessionFromCtx} from "better-auth/api";
import { admin, jwt, organization } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { sendAuthEmail } from "./email";
import type { AuthEnv } from "./env";
import type { SocialCredentials } from "./provider-store";
import { recordProviderSignIn } from "./provider-store";
import { ACCOUNT_LINKING, buildSocialProviders } from "../shared/providers.mjs";
import {mayAdminister} from "./bootstrap";
import {isAdminPrincipal} from "./admin-service";
import { nathanAccessTokenExtension, guardAuthorizationScopes, MAX_ACCESS_TOKEN_SECONDS, API_SCOPE } from "./tokens";

// NATH-15: the provider's scopes, also Better Auth's default for an authorization request without `scope`.
const OAUTH_SCOPES = ["openid", "profile", "email", "offline_access", "nathan:read", "nathan:admin", "nathan:directory.read", API_SCOPE];
import {ssoPluginOptions} from "./saml-policy.mjs";
import { nathanDatabaseHooks } from "./database-hooks";
import { admissionBeforeEmailVerification, withInviteeSupersession } from "./admission";

import { hostedEmailOTP, hostedTwoFactor } from "./email-sign-in-plugin";
import { isEmailSession, type EmailFlow } from "./email-sign-in-policy";

const ADMIN_CREDENTIAL_PATHS = new Set(["/passkey/generate-register-options", "/passkey/verify-registration", "/passkey/delete-passkey",
  "/set-password", "/change-password", "/change-email", "/link-social", "/unlink-account", "/delete-user"]);

export function createAuth(env: AuthEnv, resolvedSocialProviders?: SocialCredentials, email?: { browser: string; flow: EmailFlow }) {
  const issuer = new URL(env.NATHAN_ISSUER);
  if (issuer.protocol !== "https:" && issuer.hostname !== "localhost")
    throw new Error("Nathan requires an HTTPS identity hostname");
  if (!env.BETTER_AUTH_SECRET || env.BETTER_AUTH_SECRET.length < 32)
    throw new Error("BETTER_AUTH_SECRET must have at least 32 characters");

  // Legacy Worker-secret providers, built through the shared registry so they get the same
  // verified-email mapping as managed providers (NATH-9).
  const socialProviders: SocialCredentials = buildSocialProviders({
    ...(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
      ? { google: { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET } } : {}),
    ...(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
      ? { github: { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET } } : {})
  });

  return betterAuth({
    // NATH-43: the name users see (TOTP issuer fallback, emails); "gmacko" at id.gmac.io.
    appName: instanceName(env),
    baseURL: issuer.origin,
    basePath: "/api/auth",
    secret: env.BETTER_AUTH_SECRET,
    database: env.DB,
    // Federated tokens are sensitive; encrypt them in D1 and keep OAuth state server-side.
    // NATH-9: implicit account linking only on a provider-verified email matching a verified
    // Nathan user; no provider is trusted by name (see docs/providers.md).
    account: { encryptOAuthTokens: true, storeStateStrategy: "database", accountLinking: { ...ACCOUNT_LINKING, trustedProviders: [...ACCOUNT_LINKING.trustedProviders] } },
    // Independent OTP records for concurrent browser requests. Every other Better Auth
    // verification identifier retains its existing storage format.
    ...(email ? { verification: { storeIdentifier: { default: "plain" as const, overrides: {
      "sign-in-otp-": { hash: async () => "nathan-email:" + email.flow.generation }
    } } } } : {}),
    disabledPaths: ["/token"],
    // SAML sign-in never creates accounts unless the connection allows
    // just-in-time provisioning for its verified domain (NATH-10); no method creates an account the
    // installation's admission policy refuses (NATH-16). Both compose in ./database-hooks.ts.
    // Isolate a reissued email proof from delayed sends and verification retries for its predecessor.
    ...(email ? { verification: { storeIdentifier: { default: "plain" as const, overrides: {
      "sign-in-otp-": { hash: async () => "hosted-email-" + email.flow.generation }
    } } } } : {}),
    databaseHooks: nathanDatabaseHooks(env, email?.flow),
    hooks: {
      // NATH-15: a client not marked agent may not have a user delegate nathan:api.
      before: createAuthMiddleware(async ctx => {
        await guardAuthorizationScopes(env, ctx, OAUTH_SCOPES);
        // An email-authenticated administrator needs an existing authenticator before changing
        // credentials, including enrolling the passkey that would grant privileged step-up.
        if (ctx.path.startsWith("/two-factor/") || ADMIN_CREDENTIAL_PATHS.has(ctx.path)) {
          const current = await getSessionFromCtx(ctx);
          if (current?.user && "role" in current.user && current.user.role === "admin" && await isEmailSession(env.DB, current.session.id))
            throw new APIError("FORBIDDEN", { message: "Sign in with an existing authenticator to manage administrator credentials." });
        }
      }),
      after: createAuthMiddleware(async (ctx) => {
        // NATH-9: remember which social provider created a session, so a Studio test
        // sign-in can prove the provider round trip.
        if(ctx.path==="/callback/:id"){
          const created=ctx.context.newSession;
          if(created?.session?.id && created.user?.id && typeof ctx.params?.id==="string")
            await recordProviderSignIn(env,{providerId:ctx.params.id,sessionId:created.session.id,userId:created.user.id});
          return;
        }
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
    // NATH-16: a verified provider address supersedes a squatted provisional password account.
    socialProviders: withInviteeSupersession(env, resolvedSocialProviders ?? socialProviders),
    emailAndPassword: {
      enabled: env.ENABLE_PASSWORD === "true",
      requireEmailVerification: true,
      sendResetPassword: async ({ user, url }) =>
        sendAuthEmail(env, user.email, "Reset your Nathan password", url)
    },
    emailVerification: {
      sendVerificationEmail: async ({ user, url }) =>
        sendAuthEmail(env, user.email, "Verify your Nathan email", url),
      // NATH-16: a provisional password sign-up claims its invitation only now, or stays unverified.
      beforeEmailVerification: async (user) => admissionBeforeEmailVerification(env, user)
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
      // NATH-43: authenticator apps label the TOTP entry with this issuer (Better Auth's default is "Better Auth").
      hostedTwoFactor(instanceName(env)),
      ...(email ? [hostedEmailOTP(email.browser + "." + email.flow.generation)] : []),
      passkey({ rpID: issuer.hostname, rpName: passkeyRpName(env) }),
      jwt({disableSettingJwtHeader:true,jwks:{rotationInterval:30*24*60*60,gracePeriod:30*24*60*60}}),
      oauthProvider({
        loginPage: "/sign-in",
        consentPage: "/consent",
        scopes: OAUTH_SCOPES,
        // NATH-15: hard cap for every access token (Gatekeeper's limit). Better Auth takes the minimum
        // of this, scope expirations and a resource's accessTokenTtl, so no resource can exceed it.
        accessTokenExpiresIn: MAX_ACCESS_TOKEN_SECONDS,
        m2mAccessTokenExpiresIn: MAX_ACCESS_TOKEN_SECONDS,
        // NATH-15: principal_kind, the roles hint and passkey evidence claims (docs/gatekeeper.md).
        extensions: [nathanAccessTokenExtension(env)],
        resources: [{
          identifier: issuer.origin + "/mcp",
          allowedScopes: ["nathan:read", "nathan:admin"],
          accessTokenTtl: 300
        }, {
          // NATH-13: Gatekeeper's directory reads (client-credentials machine clients only).
          identifier: issuer.origin + "/directory",
          allowedScopes: ["nathan:directory.read"],
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
        // NATH-15: resource (audience) admin calls are server-only; also require the same administrator.
        resourcePrivileges: async ({ user, session }) => {
          return Boolean(user && await isAdminPrincipal(user,env) && await mayAdminister(env,user.id,session?.id));
        },
        ...(env.NATHAN_PAIRWISE_SECRET ? { pairwiseSecret: env.NATHAN_PAIRWISE_SECRET } : {})
      }),
      // Hardened SAML/OIDC enterprise SSO options: see src/auth/saml-policy.mjs.
      ...(env.ENTERPRISE_SSO === "true" ? [sso(ssoPluginOptions())] : [])
    ]
  });
}
