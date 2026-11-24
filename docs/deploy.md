# Nathan deployment guide

> ⚠️ **Not production-ready.** This guide describes the current experimental local installer and explicit manual steps. It is not an assurance or compliance certification.

## Prerequisites

- Node.js 22+, npm, Wrangler / Cloudflare Workers Paid account.
- A Cloudflare-managed active zone for your identity hostname (e.g. `login.example.com`).
- A Cloudflare API token scoped to the chosen account/zone. Avoid global API keys.
- A verified email account for administrator bootstrap.
- An OAuth client from Google, GitHub, Apple, Discord, Twitch or X (see [providers.md](providers.md)), or another supported upstream IdP.

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

Each provider needs the exact callback `https://login.example.com/api/auth/callback/<id>`, where `<id>` is `google`, `github`, `apple`, `discord`, `twitch` or `twitter` (X). [providers.md](providers.md) has the console links, scopes and gotchas for each one.

Run `node scripts/nathan.mjs providers guide <id>`, then `providers add <id> --apply`. These commands validate the credentials, collect secrets in a masked TTY (the Apple `.p8` key from a file path) and store them as one `NATHAN_PROVIDER_<ID>` Worker secret with `wrangler secret put` over stdin. That Worker secret is the provider's single source of truth and overrides credentials saved in Identity Studio. Studio refuses to save that provider until you delete the secret. Without it, credentials saved in Studio (encrypted in D1) are used, and the legacy `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` and `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` Worker secrets come last. See [providers.md](providers.md#storage-secrets-and-precedence). Never include these values in source-controlled Wrangler config, command arguments, logs, or screenshots.

## 4. Deploy safely

The CLI requires an explicit `--apply` confirmation and uses the current Cloudflare API token and generated Wrangler config. **It currently only deploys the identity Worker.** Before applying, inspect the generated migration set and the script's order of operations.

```sh
node scripts/nathan.mjs deploy --apply
```

The IdP must have its secrets set before its public custom domain is enabled. Re-running `npm run deploy -- --apply` after an interruption installs any missing `BETTER_AUTH_SECRET` or `NATHAN_CONFIG_KEY` (never replacing existing ones) and refuses to publish the route while either is missing. Validate discovery at the issuer path `/api/auth/.well-known/openid-configuration` (the host-root path returns 404 because the issuer is `https://<host>/api/auth`), the `jwks_uri` it advertises, and the authorization-code + PKCE flow, not just `/healthz`.

## 5. Bootstrap an administrator

Create an ordinary verified account through the configured IdP, then promote it with `node scripts/nathan.mjs admin promote --apply` using a scoped Cloudflare token and explicit confirmation. This reads and updates a verified user record in D1. The identity studio checks **both** verified email + admin role + `NATHAN_ADMIN_EMAILS` allowlist. Changing the allowlist alone does not grant admin privileges.

## 6. Register clients

Navigate to `https://login.example.com/studio`. Register an HTTPS redirect URI for each OIDC client. The client secret is displayed once and must be stored safely.

A Cloudflare application can use the standard OIDC flow, a bound Nathan verifier, or a dedicated gateway. An external domain uses OIDC directly; only legacy apps without OIDC need an HTTP gateway.

## 7. Gateway

Before routing traffic to the gateway:

1. Disable the upstream Worker's `workers.dev`, preview URLs, and all independent public routes.
2. Register a **confidential** OIDC client whose exact callback is `https://app.example.com/__nathan/callback`.
3. Provision a separate gateway D1 database and apply the migrations in `migrations/gateway/` in order. The gateway retains signed logout receipts for 48 hours to cover delivery retries and in-flight callbacks.
4. Supply `OIDC_CLIENT_SECRET` and 32 random bytes (base64url) as `SESSION_ENCRYPTION_KEY` via Workers Secrets.
5. Generate gateway Wrangler bindings and review changes before deploying.
6. Verify browser login, logout, API 401 behavior, invalid state/nonce rejection, replay protection, expiration, and user-session revocation.

The `node scripts/nathan.mjs protect <application-id>` CLI previews the hostname, callback and upstream exposure requirements. It can attempt staged gateway deployment with `--apply` only after public-route checks and OIDC client registration. Comprehensive live integration tests remain incomplete. **Do not claim Access-equivalent protections until origin isolation and session lifecycle are proven.**

### Upgrade or roll back an existing stock gateway

Apply this procedure to the stock gateway Worker and its sessions database. ClassCheck uses its own relying party and stays online throughout a stock gateway upgrade.

1. Put the stock gateway in maintenance on every ingress, keeping the upstream private. Return HTTP 503 with `Retry-After` on the back-channel endpoint so Nathan queues delivery. Pause the gateway's scheduled cleanup and wait for in-flight requests and scheduled executions on the old version to finish. Keep Nathan's issuer delivery scheduler running.
2. Apply every pending gateway migration through `0003_legacy_logout_retention.sql` to the gateway's D1 database. Older Workers recorded only the event ID. The upgrade preserves every remaining legacy receipt and extends its retention, including entries still awaiting cleanup.
3. Route 100% of gateway traffic to the upgraded Worker. Confirm it is the only serving version before reopening the back-channel endpoint. Check that queued deliveries have been acknowledged, restore the gateway cleanup schedule, then reopen browser traffic. Verify a new login and a logout. Browsers with an unfinished pre-upgrade login must start it again. Unrelated established sessions keep their existing cookies.

For rollback, drain the gateway again and retain the migrated D1 database, receipts and session keys. Deploy a single tested version that checks the receipt sequence on login callbacks and records scoped logout events. If the prior version predates those checks, keep the stock gateway in maintenance while applying the corrective build. Restoring a database snapshot taken before a logout could revive the ended session.

## 8. Rollback and incident recovery

Retain previous Worker versions and database backups before migrations. Revoke exposed provider credentials and OIDC clients; rotate signing material with overlapping keys, rather than deleting keys immediately. Verify recovery, session revocation, and that no direct public upstream URLs remain.

Read [security](security.md), [operations](operations.md), and [roadmap](roadmap.md).
