# Deployment guide (planned)

Nathan does **not** yet provide a working installer, hosted wizard, or deployable Better Auth IdP. The CLI here validates local configuration and emits a proposal only.

## Explore the blueprint locally

1. Install Node.js 20+.
2. Copy `nathan.config.example.json` to `nathan.config.json`.
3. Edit the deployment name, proposed hostname, D1 database name and application records.
4. Run `npm test`, then `npm run plan` and `npm run doctor`.

No Cloudflare API token is needed for the current read-only planner.

## Intended full installer

A Coworkers-style hosted installer will use Cloudflare OAuth + PKCE, discover the account and available zones/Workers, preview resources, deploy pinned assets, provision D1 and encrypted secret values, and reconcile custom domain mappings. OAuth provider registration will show exact callbacks, link to Google/GitHub configuration, and securely collect credentials.

Installations must be resumable and idempotent. Production auth routes must **fail closed** before any public hostname is enabled.
