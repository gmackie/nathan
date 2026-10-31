# Nathan's self-hosted browser installer

This is a standalone Cloudflare Worker that walks a customer through deploying a Better Auth identity provider into **their own Cloudflare account**. You can host your own installer on a custom domain, or deploy the IdP directly using the Nathan CLI.

> ⚠️ The implementation exists and dry-run bundles in GitHub Actions; it has not yet completed end-to-end testing against real Cloudflare OAuth accounts and custom domains. Use a staging account. It is **not approved for production IdP use**.

## Launch your own installer

Requires Node 22+, Wrangler, a Cloudflare Workers account with an active DNS zone, and a scoped \`CLOUDFLARE_API_TOKEN\` to bootstrap the installer infrastructure.

Create a Cloudflare OAuth client in **Manage Account → OAuth clients**:

- Authorization Code + Refresh Token; \`client_secret_basic\`; PKCE S256.
- Redirect URI: \`https://install.example.com/api/callback\` (replace hostname).
- Grant scopes: \`user-details.read\`, \`account-settings.read\`, \`zone.read\`, \`workers-scripts.admin\`, \`workers-routes.write\`, \`d1.write\`. Verify scope IDs against \`cf oauth-scopes list\` and your client settings. The installer must obtain every scope it needs.

Then:

\`\`\`sh
git clone https://github.com/gmackie/nathan.git
cd nathan
git switch feat/bootstrap-blueprint
npm ci
# Export CLOUDFLARE_API_TOKEN securely with appropriate permissions.
npm run setup:installer
\`\`\`

The bootstrap asks for your Cloudflare account ID, installer hostname, OAuth client ID and masked secret. It creates an **isolated** installer D1 database, packs a pinned IdP release into static assets, applies installer migrations, publishes the installer Worker **privately**, installs Cloudflare OAuth and encryption secrets, and then requires separate confirmation to attach its custom domain.

The installer encryption secret is generated locally, never committed. Back it up in a secure secrets manager; rotating it invalidates active installer sessions.

## Customer browser wizard

Once hosted, visitors:
1. Sign in to Cloudflare through OAuth + PKCE.
2. Select an account and Cloudflare-managed active DNS zone.
3. Choose the IdP Worker and `login.<domain>` hostname; enable domain-wide SSO for the root and approved subdomains. The wizard verifies the managed Cloudflare zone and previews candidate HTTP DNS records and Worker Custom Domains. Enter the Cloudflare identity email for first admin bootstrap.
4. Follow Google/GitHub OAuth setup instructions. The wizard generates the exact callback URL.
5. Enter provider client ID and masked secret; optionally enable enterprise SSO.
6. Choose MFA options; **enforced MFA modes are blocked until full assurance validation**.
7. Review the Cloudflare resource diff.
8. Explicitly consent to deployment.
9. Follow resumable steps to create D1, apply hash-verified migrations, upload the IdP Worker **inactive** with secrets, disable workers.dev/preview ingress, attach a custom domain, activate, verify OIDC discovery and JWKS.
10. Sign into Nathan with the selected provider and complete verified admin bootstrap. Then use \`/studio\`, \`/security\`, and \`/mcp\`.

The installer saves an opaque job ID in browser session storage but **never stores Cloudflare or provider tokens there**. Cloudflare OAuth tokens are encrypted in the installer's D1 database for a short-lived session. Provider secrets are sent in the installation step and supplied directly as Cloudflare Worker \`secret_text\` bindings; they are not stored in installer job records.

The job record is bound to the same Cloudflare user ID and account, with a per-step lock and a release version pin. In-progress jobs can resume after browser refresh or reauthentication to the same Cloudflare user, provided the same installer release is used.

## Failure behavior

- Before the first private upload, required migrations and secrets must be present.
- The first Worker upload uses \`NATHAN_INSTALL_ACTIVE=false\` to deny all auth endpoints while still allowing health inspection.
- The app's workers.dev and preview routes are explicitly disabled before attaching its custom domain.
- Activation preserves secrets through Workers' \`keep_bindings\` support.
- If DNS is in use, a Worker name is owned by an unrelated deployment, or a D1 database is ambiguous, the installer **stops** instead of replacing an existing resource.
- If an application login is not yet complete, admin bootstrap stops and offers a sign-in link.

On failures, do not delete D1 databases automatically. Inspect the provisioned infrastructure, fix the cause, then retry the current job step. The operator is responsible for preserving database backups during upgrades; rollback automation is not yet implemented.

## Implementation map

- \`scripts/pack-release.mjs\` — build, enumerate and hash the exact shipped auth Worker and SQL migrations.
- \`scripts/verify-release.mjs\` — independent integrity and required-resource verification.
- \`src/installer/release.ts\` — runtime asset integrity enforcement.
- \`src/installer/oauth.ts\` — Cloudflare OAuth code + PKCE and refresh.
- \`src/installer/storage.ts\` — encrypted, short-lived installer sessions.
- \`src/installer/deploy.ts\` — idempotent step state, D1, Workers upload, domain, verification and admin bootstrap.
- \`src/installer/ui.ts\` — browser wizard.
- \`src/installer/worker.ts\` — authenticated HTTP endpoints.
- \`migrations/installer/\` — independent installer database schemas.
- \`scripts/setup-installer.mjs\` — self-hosted installer bootstrap.

## Production gates

Staging must verify Cloudflare OAuth permissions, D1 API migration transactions, Worker multipart uploads, \`keep_bindings\` preservation, private staging, custom domain TLS, IdP OIDC discovery, Google/GitHub callbacks, SSO/MFA enrollment, session revocation, audit logs and recovery. Passing a build does **not** establish IAM assurance. Follow [roadmap](roadmap.md) and [security requirements](security.md).

## Domain-wide identity rather than wildcard proxy

The issuer remains `https://login.<domain>/api/auth`; the root and each approved subdomain gets its own OIDC client, exact callback and host-only application session. No `.domain` login cookies and no wildcard redirect registration. The installer does not overwrite existing apex/subdomain routes or add a wildcard Worker Route. See [domain-wide-sso.md](domain-wide-sso.md).
