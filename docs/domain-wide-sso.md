# Domain-wide SSO: login.<DOMAIN> for the apex and authorized subdomains

Nathan can operate as one OpenID Connect Provider (OP) at \`login.example.com\` for applications hosted at \`example.com\`, \`www.example.com\`, \`app.example.com\`, \`admin.example.com\`, and any other **explicitly registered** subdomain. External domains and non-Worker applications can still register ordinary OIDC clients.

The central issuer is \`https://login.example.com/api/auth\`. The OIDC discovery URL is \`https://login.example.com/.well-known/openid-configuration\`. Social OAuth provider callbacks remain on the issuer hostname (for example \`https://login.example.com/api/auth/callback/google\`).

**SSO scope is not application authorization.** A user who signs into one application gets an IdP session on \`login.example.com\`, but each application must still implement OIDC or be protected by a correctly isolated Nathan gateway, validate the token's exact audience, and enforce its own authorization rules.

## Topology

\`\`\`mermaid
flowchart TB
  IDP["login.example.com<br/>Nathan OIDC Provider / Better Auth"]
  DB[("D1 identity, realms and OAuth clients")]
  IDP --- DB
  ROOT["example.com"] <-->|"OIDC Authorization Code + PKCE"| IDP
  WWW["www.example.com"] <-->|"Own OIDC client + session"| IDP
  APP["app.example.com"] <-->|"Own OIDC client + session"| IDP
  ADM["admin.example.com"] <-->|"OIDC + administrator/MFA policy"| IDP
  EXT["Other domains / external apps"] <-->|"Standard OIDC"| IDP
\`\`\`

Every OIDC client has an exact registered callback (e.g. \`https://example.com/auth/callback\`, \`https://app.example.com/__nathan/callback\`) and a unique client ID. An RP must compare its expected issuer and audience against the returned signed ID Token. Do not trust email-domain matching as proof of access rights.

## Host-only cookies — by design

The IdP's Better Auth cookie is confined to \`login.example.com\`. Nathan explicitly disables Better Auth cross-subdomain cookies, requires secure cookies and encrypts upstream OAuth tokens in D1.

\`example.com\` and \`app.example.com\` each issue their **own** host-only application session after completing OIDC. They do **not** receive a \`.example.com\` cookie, and one application's session should never be accepted by another application.

A later OIDC redirect from a second app to \`login.example.com\` can reuse the IdP's existing session, giving seamless SSO without exposing shared session cookies to potentially compromised sibling subdomains.

## Create a realm

The hosted wizard offers **Domain-wide SSO for root + subdomains** for new \`login.<domain>\` deployments, automatically derives \`example.com\`, and checks that the Cloudflare OAuth user has access to the active zone. The installer stores a realm record linking the issuer, Cloudflare account ID and zone ID in Nathan's D1 database. A local CLI installation can create the same record using the scoped Cloudflare API token.

\`\`\`json
{
  "name": "nathan",
  "hostname": "login.example.com",
  "realm": {
    "apex": "example.com",
    "issuerHostname": "login.example.com",
    "includeApex": true,
    "includeSubdomains": true,
    "registration": "approved-only"
  },
  "securityProfile": "business",
  "database": { "type": "d1", "name": "nathan-auth" },
  "applications": []
}
\`\`\`

The wizard provisions an **exact** Custom Domain only for \`login.example.com\`. It does **not** replace the root site's DNS, deploy a wildcard Worker Route, change unrelated Workers, or create wildcard redirect URI registrations.

## Review which hosts can use SSO

Run:

\`\`\`sh
npm run wizard
node scripts/nathan.mjs domains overview
node scripts/nathan.mjs domains discover
node scripts/nathan.mjs domains callback example.com
node scripts/nathan.mjs domains callback app.example.com gateway
node scripts/nathan.mjs domains routes
\`\`\`

\`domains discover\` requires the configured Cloudflare account ID and scoped \`CLOUDFLARE_API_TOKEN\`. It lists proxied A/AAAA/CNAME DNS hosts and Workers Custom Domains within the verified realm. The results are **suggestions**, not approvals. Mail-only DNS records, wildcard DNS names, the login issuer itself, and unrelated domains are omitted.

The hosted wizard also provides **Discover existing subdomains** through its Cloudflare OAuth connection. Copy reviewed exact hostnames to Identity Studio.

## Onboard applications in Identity Studio

At \`https://login.example.com/studio\`, select **Domain-wide SSO**:

1. Inspect the verified domain realm and registered clients.
2. Register the root (\`example.com\`), an exact subdomain, or paste up to 20 reviewed hostnames for batch creation.
3. Choose web, Worker OIDC, Nathan gateway, or external application; enter a concrete callback path.
4. Nathan creates a **disabled-by-default** Better Auth OIDC client and returns its client ID and a one-time secret if confidential.
5. Configure the RP with Nathan's issuer/discovery URL, client ID, confidential client secret when applicable, and its exact redirect URL.
6. Test the RP login and token/audience validation, then enable the client through **Registered applications**.

New clients require consent by default. Domain ownership by itself does **not** make a client trustworthy enough to bypass consent. Explicit first-party/trusted consent settings would need stronger review before being added.

These operations never proxy HTTP traffic, remove existing route protection, or share browser cookies. Legacy HTTP apps without native OIDC need a Nathan gateway; the upstream must be inaccessible through any public Worker or origin route.

### A new subdomain later

Create \`newapp.example.com\` on your normal hosting provider. Register a new OIDC client in Studio with \`https://newapp.example.com/auth/callback\` (or its framework's actual callback). The user can immediately use the existing \`login.example.com\` IdP once that RP is configured and its client explicitly enabled.

No IdP redeployment or new OAuth provider credentials are needed.

### External domains

An app on \`anothercompany.com\` can register a regular OIDC client under Nathan; domain-wide realm restrictions only apply to the special managed first-party realm inventory. Never assert that Nathan owns another domain without an explicit proof-of-control process.

## Cloudflare wildcard HTTP routing is separate

Cloudflare Worker **Custom Domains do not support wildcard hostname records**. Workers **Routes** can match \`example.com/*\` and \`*.example.com/*\`, but they are a different product mechanism, and each matched hostname needs DNS resolution. Cloudflare's docs explicitly warn that \`*.example.com/*\` does not match the apex and that careless wildcard patterns can match unwanted hosts.

Adding those Routes to an existing zone could intercept all its HTTP traffic, including the login host, and break applications or produce recursion without proper route exemptions and exact upstream routing. Nathan's default domain-wide SSO mode therefore does **not** install wildcard Routes.

An opt-in future whole-zone gateway must first inventory exact hostname routes, classify upstream Workers versus external origins, prove no origin bypass, avoid catching \`login.example.com\`, and fail closed for unknown hosts.

Cloudflare references:
- https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
- https://developers.cloudflare.com/workers/configuration/routing/routes/

Better Auth references:
- https://better-auth.com/docs/plugins/oauth-provider
- https://better-auth.com/docs/concepts/cookies

## Security and acceptance criteria

- Realm only created after verifying the Cloudflare zone, account and \`login.<apex>\` issuer match.
- All client hostnames are strictly inside the apex with a label boundary; \`example.com.evil.test\`, wildcard and login issuer host are refused.
- Exact HTTPS callback URI per application. No wildcard callback, dynamic first-party trust or cross-subdomain cookie.
- Every client initially disabled and consent-required. Registration is admin-authenticated, CSRF-protected and audited.
- One-time confidential secrets are not written to client inventory or installer logs.
- Test login at the apex, \`www\`, a nested subdomain, and a non-Worker external RP with the same IdP session; verify token audiences cannot be replayed between clients.
- Test a compromised sibling subdomain cannot read the IdP's login session cookie.
- Test that disabling any registered OIDC client stops issuance and online introspection; local JWT verification still needs short expiry or an online check for immediate revocation.
- Verify client registration failures remain reserved for manual reconciliation, rather than retrying blindly and creating duplicate credentials.

Domain-wide SSO does not imply NIST AAL2/AAL3. Required MFA policies remain unavailable until authentication assurance is proven end-to-end across federated sign-in methods.
