# EducateOS staging registration

The private `nathan-stg-educateos-registration` Workflow applies the original EducateOS registration to Nathan staging and verifies the unauthenticated OAuth redirect with Cloudflare Browser Run. Its Worker has no HTTP route or D1 binding.

Install the Worker dependency from the repository root with `npm ci --prefix deploy/staging/educateos-registration`. Run `node --test tests/educateos-staging-registration.test.mjs` and bundle with `npx wrangler deploy --dry-run --config deploy/staging/educateos-registration/wrangler.jsonc`.

The Worker uses the original receipt's user ID and public client ID as deployment variables `NATHAN_STAGING_USER_ID` and `NATHAN_PROBE_CLIENT_ID`. It checks both against the approved target. Provision the enrolled Llavero helper identity as the Worker's encrypted `LLAVERO_NATHAN_CLI_TOKEN` secret. The helper checks the owner's policy digest and custody event in Llavero before releasing the D1 credential into the apply step.

After handoff from the old waiter, start instance `educateos-staging-2026-11-24` with an empty payload. The reporting task can start it when Llavero issuance and hosted enrollment are ready. The instance output records the verified D1 grant, the public client used, and the browser redirect. If the browser step needs another attempt, preserve the D1 checkpoint. If reconciliation is required, inspect the existing staging rows and audit before taking any further action.
