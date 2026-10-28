# Hosted Nathan installer — experimental browser wizard

Nathan includes a separate installer Worker that signs in with Cloudflare Dashboard OAuth + PKCE, encrypts install-session credentials in a **separate D1 database**, lets users choose their account/zone, discovers Workers and hostnames, and produces a read-only deployment plan.

**The hosted installer's publish action is currently disabled.** Creating Worker bundles, uploading the compiled identity Worker, applying its D1 migrations, and activating the custom domain through the Cloudflare API require additional release packaging and live API testing. Use the CLI from \`docs/deploy.md\` until these steps are verified.

## Deploy the preview installer

1. Create a Cloudflare OAuth client (Account → Manage Account → OAuth clients). Configure authorization code + refresh token with client_secret_basic and PKCE; callback \`https://install.example.com/api/callback\`.
2. Choose the scopes appropriate to the requested read-only discovery and later provisioning. \`CF_OAUTH_SCOPES\` must match the permissions granted to your OAuth client. **Cloudflare scope identifiers can change; review them with \`cf oauth-scopes list\` and the current Cloudflare OAuth settings.**
3. Provision the installer D1 database and configure its UUID in \`wrangler.installer.jsonc\`. Apply \`migrations/installer/0001_sessions.sql\`.
4. Set \`CF_OAUTH_CLIENT_SECRET\` and \`INSTALLER_ENCRYPTION_KEY\` through Wrangler Secrets. The encryption key must be exactly 32 random bytes encoded as base64url; keep a secure backup.
5. Set \`PUBLIC_ORIGIN\` and \`CF_OAUTH_CLIENT_ID\`, then deploy the installer using \`wrangler deploy --config wrangler.installer.jsonc\`.

The installer never exposes Cloudflare OAuth tokens to the browser. Tokens are stored encrypted in D1 with 30-minute opaque host-only cookies. Login state and PKCE verifier are stored encrypted and consumed atomically; signed-in API responses return only necessary metadata. Plans are read-only; writes are blocked in the installer.

## Limitations and security obligations

The OAuth account selection and discovery path is implemented but not verified against a real authorized Cloudflare OAuth application. The installer needs login, refresh, CSRF, credential expiry, rate-limit, and cross-tenant access tests before publication. Scope and RBAC checks rely on Cloudflare API enforcement.

Separate the public installer from the customer-owned Nathan IdP runtime. No IdP administrator secrets should ever be stored on the installer service. The eventual release installer should pin a verified Worker bundle and migrations to a release digest and support idempotent resumption, rollback, and secure secret installation before routes are exposed.
