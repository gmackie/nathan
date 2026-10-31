# Nathan deployment guide

> ⚠️ **Not production-ready.** This guide describes the current experimental local installer and explicit manual steps. It is not an assurance or compliance certification.

## Prerequisites

- Node.js 22+, npm, Wrangler / Cloudflare Workers Paid account.
- A Cloudflare-managed active zone for your identity hostname (e.g. `login.example.com`).
- A Cloudflare API token scoped to the chosen account/zone. Avoid global API keys.
- A verified email account for administrator bootstrap.
- A Google or GitHub OAuth application, or another supported upstream IdP.

## Domain-wide login identity

If the intention is one central identity provider for an entire Cloudflare zone, use `login.example.com` as Nathan's custom domain and select **Domain-wide SSO**. The setup registers a verified realm for `example.com` and its subdomains, without changing their existing DNS or automatically protecting unrelated applications.

After installation, open `https://login.example.com/studio` → Domain-wide SSO to review and register exact hostname OIDC clients. The root and any additional subdomains get their own callback and session, reusing the central Nathan login. Read [domain-wide-sso.md](domain-wide-sso.md).

## Quick-start wizard

```sh
npm ci
# Export a scoped CLOUDFLARE_API_TOKEN from your secret manager
npm run wizard
```

This interactive wizard covers local manifest creation, account/zone/Worker discovery, deployment planning, private IdP deployment, provider credentials, admin promotion and an optional protected-Worker gateway. Every mutation requests explicit approval.

For browser-first customer onboarding, run `npm run setup:installer` to create a dedicated Cloudflare OAuth-powered installer. See [installer.md](installer.md). Once deployed, visitors do not need to install Node or supply a general-purpose Cloudflare API token.

## 1. Prepare

```sh
npm install
cp nathan.config.example.json nathan.config.json
npm run init
npm test
npm run plan
```

The wizard inspects local Wrangler configuration and, with an explicitly supplied Cloudflare API token, available accounts, zones and Workers. It builds a local manifest. Provider secret setup is handled separately by the masked prompts below.

Optional read-only Cloudflare discovery:

```sh
export CLOUDFLARE_API_TOKEN=...       # use a secret manager
npm run plan
```

The plan checks account/zones, Workers, D1 databases, and exact hostname DNS records. Any conflicts must be resolved deliberately; Nathan never overwrites existing DNS on its own.

## 2. Generate database schema

The Better Auth plugin schema is version-dependent. It **must** be generated from the *pinned package version*, not from a manually guessed schema:

```sh
npm run schema:generate
```

The schema generator is `src/auth/schema-config.ts`. It creates a superset of tables for Better Auth, the OAuth Provider, SSO, MFA/passkeys, admin, and organizations. Store the generated SQL under `migrations/0002_better_auth.sql` and review the diff before applying. The repository commits the generated SQL migration and CI regenerates it from the pinned package versions, failing on any difference. The rate-limit table is included.

Apply migrations against a staging D1 database before production. Cloudflare D1's transaction semantics need adversarial testing for concurrent user, OAuth code, and session operations.

## 3. Configure OAuth

When creating a Google OAuth Web application, use the exact URL:

```
https://login.example.com/api/auth/callback/google
```

For GitHub OAuth use:

```
https://login.example.com/api/auth/callback/github
```

Run `node scripts/nathan.mjs providers guide google` or `providers guide github`, then `providers add google --apply` / `providers add github --apply`. These commands collect the secret in a masked TTY and use `wrangler secret put`. Alternatively set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, and `GITHUB_CLIENT_SECRET` manually via Wrangler. Never include these values in source-controlled Wrangler config, command arguments, logs, or screenshots.

## 4. Deploy safely

The CLI requires an explicit `--apply` confirmation and uses the current Cloudflare API token and generated Wrangler config. **It currently only deploys the identity Worker.** Before applying, inspect the generated migration set and the script's order of operations.

```sh
node scripts/nathan.mjs deploy --apply
```

The IdP must have a secret set before its public custom domain is enabled. Validate `/.well-known/openid-configuration`, `/api/auth/jwks`, and the authorization-code + PKCE flow, not just `/healthz`.

## 5. Bootstrap an administrator

Create an ordinary verified account through the configured IdP, then promote it with `node scripts/nathan.mjs admin promote --apply` using a scoped Cloudflare token and explicit confirmation. This reads and updates a verified user record in D1. The identity studio checks **both** verified email + admin role + `NATHAN_ADMIN_EMAILS` allowlist. Changing the allowlist alone does not grant admin privileges.

## 6. Register clients

Navigate to `https://login.example.com/studio`. Register an HTTPS redirect URI for each OIDC client. The client secret is displayed once and must be stored safely.

A Cloudflare application can use the standard OIDC flow, a bound Nathan verifier, or a dedicated gateway. An external domain uses OIDC directly; only legacy apps without OIDC need an HTTP gateway.

## 7. Gateway

Before routing traffic to the gateway:

1. Disable the upstream Worker's `workers.dev`, preview URLs, and all independent public routes.
2. Register a **confidential** OIDC client whose exact callback is `https://app.example.com/__nathan/callback`.
3. Provision a separate gateway D1 database and apply `migrations/gateway/0001_sessions.sql`.
4. Supply `OIDC_CLIENT_SECRET` and 32 random bytes (base64url) as `SESSION_ENCRYPTION_KEY` via Workers Secrets.
5. Generate gateway Wrangler bindings and review changes before deploying.
6. Verify browser login, logout, API 401 behavior, invalid state/nonce rejection, replay protection, expiration, and user-session revocation.

The `node scripts/nathan.mjs protect <application-id>` CLI previews the hostname, callback and upstream exposure requirements. It can attempt staged gateway deployment with `--apply` only after public-route checks and OIDC client registration. Comprehensive live integration tests remain incomplete. **Do not claim Access-equivalent protections until origin isolation and session lifecycle are proven.**

## 8. Rollback and incident recovery

Retain previous Worker versions and database backups before migrations. Revoke exposed provider credentials and OIDC clients; rotate signing material with overlapping keys, rather than deleting keys immediately. Verify recovery, session revocation, and that no direct public upstream URLs remain.

Read [security](security.md), [operations](operations.md), and [roadmap](roadmap.md).
