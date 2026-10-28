# Nathan deployment guide

> ⚠️ **Not production-ready.** This guide describes the current experimental local installer and explicit manual steps. It is not an assurance or compliance certification.

## Prerequisites

- Node.js 22+, npm, Wrangler / Cloudflare Workers Paid account.
- A Cloudflare-managed active zone for your identity hostname (e.g. \`auth.example.com\`).
- A Cloudflare API token scoped to the chosen account/zone. Avoid global API keys.
- A verified email account for administrator bootstrap.
- A Google or GitHub OAuth application, or another supported upstream IdP.

## 1. Prepare

\`\`\`sh
npm install
cp nathan.config.example.json nathan.config.json
npm run init
npm test
npm run plan
\`\`\`

The wizard inspects local Wrangler configuration, suggests a hostname and builds a manifest. It does not manage Cloudflare or OAuth provider secrets automatically yet.

Optional read-only Cloudflare discovery:

\`\`\`sh
export CLOUDFLARE_API_TOKEN=...       # use a secret manager
npm run plan
\`\`\`

The plan checks account/zones, Workers, D1 databases, and exact hostname DNS records. Any conflicts must be resolved deliberately; Nathan never overwrites existing DNS on its own.

## 2. Generate database schema

The Better Auth plugin schema is version-dependent. It **must** be generated from the *pinned package version*, not from a manually guessed schema:

\`\`\`sh
npm run schema:generate
\`\`\`

The schema generator is \`src/auth/schema-config.ts\`. It creates a superset of tables for Better Auth, the OAuth Provider, SSO, MFA/passkeys, admin, and organizations. Store the generated SQL under \`migrations/0002_better_auth.sql\` and review the diff before applying. The current repository does **not** yet contain a verified generated migration. **Deployment should be blocked until it does.**

Apply migrations against a staging D1 database before production. Cloudflare D1's transaction semantics need adversarial testing for concurrent user, OAuth code, and session operations.

## 3. Configure OAuth

When creating a Google OAuth Web application, use the exact URL:

\`\`\`
https://auth.example.com/api/auth/callback/google
\`\`\`

For GitHub OAuth use:

\`\`\`
https://auth.example.com/api/auth/callback/github
\`\`\`

Set \`GOOGLE_CLIENT_ID\`, \`GOOGLE_CLIENT_SECRET\`, \`GITHUB_CLIENT_ID\`, and \`GITHUB_CLIENT_SECRET\` using \`wrangler secret put\`. Never include these values in source-controlled Wrangler config, command arguments, logs, or screenshots.

## 4. Deploy safely

The experimental CLI requires an explicit \`--apply\` confirmation and uses the current Cloudflare API token and generated Wrangler config. **It currently only deploys the identity Worker.** Before applying, inspect the generated migration set and the script's order of operations.

\`\`\`sh
node scripts/nathan.mjs deploy --apply
\`\`\`

The IdP must have a secret set before its public custom domain is enabled. Validate \`/.well-known/openid-configuration\`, \`/api/auth/jwks\`, and the authorization-code + PKCE flow, not just \`/healthz\`.

## 5. Bootstrap an administrator

Create an ordinary verified account through the configured IdP, then promote it to the Better Auth \`admin\` role through a deliberately privileged, audited migration or future bootstrap CLI command. The identity studio checks **both** verified email + admin role + \`NATHAN_ADMIN_EMAILS\` allowlist. Changing the allowlist alone does not grant admin privileges.

## 6. Register clients

Navigate to \`https://auth.example.com/studio\`. Register an HTTPS redirect URI for each OIDC client. The client secret is displayed once and must be stored safely.

A Cloudflare application can use the standard OIDC flow, a bound Nathan verifier, or a dedicated gateway. An external domain uses OIDC directly; only legacy apps without OIDC need an HTTP gateway.

## 7. Gateway

Before routing traffic to the gateway:

1. Disable the upstream Worker's \`workers.dev\`, preview URLs, and all independent public routes.
2. Register a **confidential** OIDC client whose exact callback is \`https://app.example.com/__nathan/callback\`.
3. Provision a separate gateway D1 database and apply \`migrations/gateway/0001_sessions.sql\`.
4. Supply \`OIDC_CLIENT_SECRET\` and 32 random bytes (base64url) as \`SESSION_ENCRYPTION_KEY\` via Workers Secrets.
5. Generate gateway Wrangler bindings and review changes before deploying.
6. Verify browser login, logout, API 401 behavior, invalid state/nonce rejection, replay protection, expiration, and user-session revocation.

The gateway source code exists, but full automated gateway provisioning and comprehensive integration tests remain incomplete. **Do not claim Access-equivalent protections until origin isolation and session lifecycle are proven.**

## 8. Rollback and incident recovery

Retain previous Worker versions and database backups before migrations. Revoke exposed provider credentials and OIDC clients; rotate signing material with overlapping keys, rather than deleting keys immediately. Verify recovery, session revocation, and that no direct public upstream URLs remain.

Read [security](security.md) and [roadmap](roadmap.md).
