import { betterAuth } from "better-auth";
import { passkeyRpName, instanceName } from "./passkey-config.mjs";
import {createAuthMiddleware, APIError} from "better-auth/api";
import { admin, jwt, organization, twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { sendAuthEmail } from "./email";
import type { AuthEnv } from "./env";
import type { SocialCredentials } from "./provider-store";
import { recordProviderSignIn } from "./provider-store";
import { ACCOUNT_LINKING, buildSocialProviders } from "../shared/providers.mjs";
import {mayAdminister} from "./bootstrap";
import {isAdminPrincipal, audit} from "./admin-service";
import { nathanUpstreamPlugin } from "./nathan-upstream.mjs";
import { supersedeUnprovenAccount } from "./admission-policy.mjs";
import { nathanAccessTokenExtension, guardAuthorizationScopes, MAX_ACCESS_TOKEN_SECONDS, API_SCOPE } from "./tokens";

// NATH-15: the provider's scopes, also Better Auth's default for an authorization request without `scope`.
const OAUTH_SCOPES = ["openid", "profile", "email", "offline_access", "nathan:read", "nathan:admin", "nathan:directory.read", API_SCOPE];
import {ssoPluginOptions} from "./saml-policy.mjs";
import { nathanDatabaseHooks } from "./database-hooks";
import { admissionBeforeEmailVerification, withInviteeSupersession } from "./admission";

export function createAuth(env: AuthEnv, resolvedSocialProviders?: SocialCredentials) {
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

  // NATH-51: the Nathan upstream ("Sign in with Nathan") is registered through genericOAuth, not as
  // a Better Auth social provider. Only a trusted, discovered parent ever reaches this point.
  const { nathan: upstream, ...social } = withInviteeSupersession(env, resolvedSocialProviders ?? socialProviders) as SocialCredentials;
  const upstreamPlugins = upstream?.upstream === true ? [nathanUpstreamPlugin(upstream, {
    onRefused: reason => audit(env, "system:nathan-upstream", "nathan_upstream_signin", "nathan", "refused_" + reason).catch(() => {}),
    // NATH-16: like a verified social address, a verified parent address replaces a squatted provisional account.
    onVerified: async email => { await supersedeUnprovenAccount(env.DB, email, "nathan"); }
  })] : [];

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
    disabledPaths: ["/token"],
    // SAML sign-in never creates accounts unless the connection allows
    // just-in-time provisioning for its verified domain (NATH-10); no method creates an account the
    // installation's admission policy refuses (NATH-16). Both compose in ./database-hooks.ts.
    databaseHooks: nathanDatabaseHooks(env),
    hooks: {
      // NATH-15: a client not marked agent may not have a user delegate nathan:api.
      before: createAuthMiddleware(async (ctx) => {
        // NATH-9/NATH-51: sign-in and linking use the redirect flow only. A client-submitted ID token
        // carries no state, PKCE or nonce bound to this browser, so it is refused for every provider.
        if ((ctx.path === "/sign-in/social" || ctx.path === "/link-social") && ctx.body?.idToken)
          throw new APIError("BAD_REQUEST", { code: "ID_TOKEN_SIGN_IN_DISABLED", message: "Sign in with the provider's redirect flow" });
        return guardAuthorizationScopes(env, ctx, OAUTH_SCOPES);
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
    socialProviders: social,
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
      twoFactor({ allowPasswordless: true, issuer: instanceName(env) }),
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
      ...(env.ENTERPRISE_SSO === "true" ? [sso(ssoPluginOptions())] : []),
      ...upstreamPlugins
    ]
  });
}
