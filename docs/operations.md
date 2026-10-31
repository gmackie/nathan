# Nathan operations and incident response

**Draft operational runbook.** Validating procedures against a real staging deployment is a required release gate.

## Deployment ownership

Every installation is owned by the customer's Cloudflare account: one Auth Worker, D1 identity database, custom identity hostname, optional per-app gateway Workers and session databases. For external OIDC clients no gateway or DNS migration is required.

The hosted installer is separate infrastructure. Its OAuth authorization and encrypted installer sessions must not be shared with identity data or gateway sessions.

## Before the first deployment

- Confirm the target Cloudflare account and zone in the preview. Do not overwrite existing DNS or worker routes without an explicit change plan.
- Configure a test user and independent recovery administrator; verify the primary admin is email-verified and explicitly allowlisted.
- Export a copy of the current identity schema and deployment manifest, and back up D1 before migrating.
- Generate Better Auth schema from the pinned CLI and ensure the checked-in migration agrees. Maintain a known-good Worker deployment version.
- Keep the upstream Worker private when using gateway mode, and audit direct route/preview leakage before cutover.
- Provision separate restricted tokens for deployments and for day-to-day administration.

## Credential and key management

- Better Auth secret: generate 32+ bytes of cryptographically random material and store in Workers Secrets; use an approved overlapping-rotation mechanism where available. Do not store secrets in any committed config.
- OIDC signing keys: never assume a database-backed signing key is HSM-protected. High-assurance deployments require approved external signing controls and key-rollover tests.
- OAuth provider secrets: use masked CLI entry and Workers Secrets. Plan for provider client ID/secret rotation and rollback.
- Gateway session encryption key: a new random key invalidates encrypted in-flight PKCE states; changing it does not rotate hashed D1 session cookies, but can interrupt login attempts. Test rollovers.
- Hosted installer encryption key: encrypted Cloudflare OAuth sessions require the original key until expiry. Rotate deliberately, clearing installer sessions if necessary.
- Revoke leaked Cloudflare OAuth grants and API tokens immediately.

## Access reviews and recovery

Admin privileges require verified identity, Better Auth admin role, and allowlisted address. Treat changes to this allowlist as privileged configuration. Reevaluate administrators, client registry access, allowed redirects and active gateway exposure regularly.

Provision two independently controlled recovery paths. Never disable MFA or issue an unverified role promotion as a quick fix. Account recovery must be signed, short-lived, single-use and audited.

## Incident response

1. **Contain:** disable a compromised OAuth client (IdP can stop issuing new tokens), isolate its gateway, revoke sessions and block unsafe routes. For IdP compromise, suspend token issuance and inform relying parties.
2. **Identify:** collect the IdP/installer/gateway release hashes, deployment logs and immutable security events. Avoid logging secrets, raw tokens, user passwords or MFA material.
3. **Revoke/rotate:** OAuth client credentials, upstream IdP secrets, Cloudflare API tokens, Better Auth secret and signing keys as appropriate. Handle JWKS overlap and ensure relying parties reject old keys after retirement.
4. **Restore:** deploy a previously validated Worker version and restore D1 only from a tested backup. Check migrations and the client registry before reopening.
5. **Verify:** retest PKCE, signing keys, client audience, logouts, gateway origin isolation, account linking, MFA and recovery.
6. **Postmortem:** create a documented timeline, customer notifications where required, impact assessment and security tests preventing recurrence.

## Data retention and audit

D1 audit entries are not append-only storage. For regulated deployments, export events to a separate write-once/tamper-evident destination under an independent security principal. Define retention, minimization and deletion obligations by customer jurisdiction and use case.

## Upgrade and rollback

Use version-pinned Better Auth packages, plugin versions and lockfile. Before upgrades, generate and review plugin schema changes, validate staging, back up D1 and test key/session compatibility. For down migrations and irreversible data changes, explicitly document recovery steps rather than assuming Worker rollback undoes database migrations.

## Open operational questions

- Verified D1 restore method and recovery objectives, depending on deployment volume.
- AAL and identity-proofing evidence retention for enterprise customers.
- Third-party email delivery and outage behavior.
- Periodic drift detection of DNS, Workers routes, client redirects and MFA policies.
- Security update policy and signing-key rollovers supported by Better Auth.
