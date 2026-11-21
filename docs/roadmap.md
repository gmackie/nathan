# Nathan roadmap and verification status

## Source implemented and CI-validated (not yet live-deployed)

- [x] README, architecture/security docs, permissive MIT license.
- [x] Better Auth identity Worker with OAuth 2.1 Provider / OIDC, JWT, admin, organizations, passkeys, TOTP, optional SSO.
- [x] Admin-only application registration form and endpoint.
- [x] OIDC gateway implementation with PKCE, nonce, AES-GCM flow state, D1 opaque sessions and proxy binding.
- [x] Typed bearer verification guard for Workers.
- [x] CLI configuration validator, DNS/account discovery, preview, and opt-in D1/Worker deployment path.
- [x] Node unit and SQLite migration tests, GitHub Actions build-check workflow, three Worker dry-run bundles.
- [x] Reproducible npm lockfile and generated Better Auth 1.7.14 migration including D1 rate limiting.
- [x] Hosted installer: Cloudflare OAuth PKCE, encrypted D1 sessions, account/zone/Worker discovery, read-only deployment plan, resumable job state and customer-owned resource deployment code.
- [x] Provider-specific guided secret installation, verified-admin bootstrap and application gateway installer staging.
- [x] Identity Studio OAuth client create/list/disable, plugin catalog and admin security audit.
- [x] Identity Studio application policy management and enterprise OIDC registration UI.
- [x] MCP 2026-07-28 read tools and opt-in audited write tools, resource-bound OAuth + current-admin checks.
- [x] Installer release bundling, hash verification, private upload, migrations, domain/activation and bootstrap workflow.
- [x] CLI `npm run wizard` and self-hosted installer bootstrap `npm run setup:installer`.
- [x] Verified `login.<domain>` OIDC realm covering the root and approved subdomains, with strict exact redirects and host-only IdP cookies.
- [x] Cloudflare proxied-DNS/Worker hostname discovery, safe CLI callback generation, read-only wildcard-route preview.
- [x] Identity Studio one-at-a-time and reviewed batch realm OIDC client registration, disabled by default, plus read-only MCP realm tools.

## Initial administrator, OAuth, SCIM and MFA (implemented source; staging pending)

- [x] Cloudflare OAuth owner-bound initial administrator, email verification, verified-user claim, enrollment and completed bootstrap.
- [x] Encrypted D1-managed Google/GitHub provider credentials; add/rotate/enable/disable in Identity Studio without a deployment.
- [x] Enterprise OIDC registration, DNS TXT domain ownership challenge and verification in the privileged UI.
- [x] Block direct raw Better Auth admin/SSO management endpoints to avoid bypassing Nathan's admin policy.
- [x] Per-connection SCIM 2.0 Users/Groups SQLite Durable Object, strict bearer validation, disabled-by-default connection and token rotation.
- [x] Optional initial SCIM configuration in hosted wizard; one-time directory token revealed after verified admin setup.
- [x] Server-side admin enrollment policy and session-scoped passkey reauthentication for privileged actions.
- [x] Explicit additional verified-admin grants, revocation and session invalidation.
- [x] Runtime-forward-only MFA policy tightening from Identity Studio, never weakening the deployment baseline.
- [x] Wizard-vs-Studio settings/recovery guide: [setup-lifecycle.md](setup-lifecycle.md).

## Roles and minimal RBAC (NATH-13; implemented source, staging pending)

- [x] Per-app permissions, roles, groups, members and grants (migration 0011) with both NATH-1 access modes; deny by default; legacy role lists migrated without changing any current decision.
- [x] One pure evaluator (`src/shared/policy.mjs`) used by the gateway RPC, the SDK's token path, `NathanVerifier.authorize/access` and the directory API.
- [x] App-scoped `NathanVerifier` binding: each binding pins its application in binding props, answers only for it, and has no directory methods (security review; workerd-tested).
- [x] Gateway resolves roles over the `NathanVerifier` service binding, caches them for at most 60 s per session, answers 403 on deny, strips inbound `X-Nathan-*` and forwards a signed, ≤ 60 s `X-Nathan-Principal` (workerd-tested: forged/unsigned principals rejected, grant removal effective within the cache window).
- [x] Worker SDK `nathan(request, env)` with `hasRole`, `can`, `require`; the gateway and bearer-token paths give the same answers (workerd table test with access tokens issued by the built identity Worker). Machine (client-credentials) and DPoP-bound tokens are refused on the bearer path.
- [x] Gateway fails closed with 503 for a missing, throwing, unpinned or mis-pinned binding, a missing or short principal key and a cache TTL outside 0–60 (workerd-tested).
- [x] Audit trail: rejected Studio RBAC attempts are audited `rejected`; `nathan rbac sync` audits `attempted` first and `partial`/`failed` on error (the D1 REST API cannot run a sync as one transaction).
- [x] Change feed also carries bans, unbans and deleted users' memberships and grants (D1 triggers; SQLite- and workerd-tested).
- [x] Directory read API and change feed for Gatekeeper's PIP, with client-credentials authentication (workerd-tested with a token from Nathan's own endpoint).
- [x] Identity Studio Roles and access (admin-only, step-up, audited, change-fed), permissions as code (`nathan rbac plan|sync`), principal key setup in `nathan protect`. [Quickstart](quickstart-rbac.md), [reference](rbac.md).
- [ ] Follow the quickstart end to end against a staging Cloudflare account (gateway + upstream + Studio grants).
- [ ] Contract test with Gatekeeper's PIP adapter (GATE-9) against a Nathan fixture.
- [ ] Access-token role claims as hints (NATH-15), MCP scopes capped by permissions (NATH-14).

## Inbound SCIM lifecycle (NATH-11; implemented source, staging pending)

- [x] Identity linking by (connection, externalId); first link by email only on the connection's verified domain and a verified Nathan email; a link never moves across connections (migration 0016, workerd-tested).
- [x] Optional just-in-time account creation per connection (default off, unverified email), with an admission hook for NATH-16.
- [x] Fail-closed deprovisioning: `active=false` or DELETE bans, deletes sessions, revokes all access and refresh tokens and queues back-channel logout in one D1 transaction; the SCIM request gets 503 until it commits; the Durable Object alarm retries (workerd-tested with real logout delivery to the gateway).
- [x] Reactivation lifts only Nathan's SCIM ban and restores no sessions; administrator bans are never lifted by the directory.
- [x] Back-channel logout delivery queue (signed `logout+jwt`, `sub` tokens, backoff retries, failures audited).
- [x] Explicit SCIM group → Nathan group mapping (`source = 'scim'`); idempotent membership; mapping grants nothing.
- [x] Replay-safe reconciliation (per-resource revisions, ordered outbox, applied-revision guard) and RFC 7644 PATCH with Okta and Entra request shapes (fixtures in `tests/fixtures/scim/`).
- [x] Identity Studio lifecycle section: settings, mappings, link status, last sync, error log (admin-only, step-up, audited). Setup guide: [scim.md](scim.md).
- [ ] Provision from a live Okta tenant and a live Entra tenant against staging (create, update, deactivate, reactivate, group push), and check the vendors' current payloads against the fixtures.
- [x] Security review fixes: Nathan administrators (admin role, admin grant, bootstrap owner, `NATHAN_ADMIN_EMAILS`) are never linked or deprovisioned automatically; held changes become audited review items approved or dismissed in Studio with step-up and exact confirmation; the last administrator is never deprovisioned by SCIM (unit- and workerd-tested).
- [x] Administrator overrides: keep active (recorded with actor and time, kept through replays and resyncs until a new deprovision change), out-of-band unbans detected and recorded, and a Studio unlink action.
- [x] Rehires: deleted SCIM resources move to tombstone tables in the Durable Object (migrated in place on existing data), live-only uniqueness in D1, and a rehire with the same externalId takes over the deleted identity's link. A deleted Nathan account's link is never re-made automatically.
- [x] Bounded reconciliation per invocation (100 statements per batch, 500 per invocation, alarm continuation, removals before additions; 1,200 JIT links and 3,000 memberships in workerd), and a Studio outbox view with skip-after-review for a poisoned entry.
- [x] Race-safe application: compare-and-set on `apply_seq` in every batch; duplicate outbox rows, late revisions and racing appliers tested directly.
- [ ] Per-user directory profile sync (name only) if needed.

## Required before first actual production-ready release

- [ ] Verify root → nested-subdomain → root SSO against real Cloudflare Workers and non-Workers, including strict per-client audience isolation.
- [ ] Verify the complete OAuth/OIDC flow with real Cloudflare D1 and Workers.
- [ ] Complete real-account end-to-end tests for initial-admin claim, passkey/TOTP enrollment, session step-up, SSO linking and administrator recovery.
- [ ] Complete the fail-closed provisioning sequence and all gateway deployment workflows.
- [ ] Verify that `workers.dev`, previews, extra routes and direct origin paths cannot bypass gateways.
- [ ] Add assurance claim support; do not report AAL2/AAL3 without verification.
- [x] Implement signed back-channel logout receiver. Revocation and JTI replay record commit atomically, storage failures return 503 so the IdP retries (NATH-8, workerd-tested). IdP-side delivery with retries exists for SCIM deprovisioning (NATH-11); delivery on interactive sign-out still relies on Better Auth's single attempt.
- [ ] Add integration suite for OAuth/OIDC, malformed callbacks, replay, concurrency and D1 state transitions.
- [ ] Run installer end-to-end against a real Cloudflare OAuth client; validate D1 API batch semantics, domain propagation, script binding retention, retries and safe recovery on failure.
- [ ] Implement full installer rollback/reconciliation for interrupted upload states. Interrupted D1 creation, stale/concurrent stage execution and CLI secret reconciliation are handled and runtime-tested (NATH-8); other ambiguous states still fail closed.
- [ ] Verify end-to-end Enterprise SSO provider registration, passkey/TOTP enrollment and policy enforcement. Plugin runtime installation remains a reviewed redeploy operation.
- [ ] Validate rollback, key rotation, backups, logs and incident response under staging load.
- [ ] Independent security review, SBOM, signed release provenance and staged operational audit.

## Later extensions

- Custom plugin approvals and isolation for out-of-process extensions.
- SCIM ingress/egress and verified enterprise SAML/OIDC provisioning.
- Authentik-style flow designer. Rich authorization policy (conditions, approvals, resource rules) belongs to Gatekeeper, which reads Nathan's roles.
- RADIUS/LDAP/SSH/non-HTTP outposts via native edge agents.

## Future optional whole-zone ingress

- [ ] Design an explicitly opt-in, fail-closed `example.com/*` + `*.example.com/*` gateway with a verified upstream map and a login-host exclusion. Domain-wide OIDC alone does not intercept or secure HTTP traffic.
- [ ] Support high-scale tenant subdomains through an explicitly authorized canonical callback app plus cryptographically bound tenant return state rather than wildcard redirects.

## SCIM lifecycle status

Since NATH-11, SCIM links directory users to Nathan accounts (opt-in per connection), deprovisions them fail-closed, and feeds explicitly mapped groups; see [scim.md](scim.md). It is not yet verified against live Okta or Entra tenants. The official Better Auth SCIM plugin still cannot be enabled against D1, because it needs interactive transactions; Nathan's per-connection Durable Object plus single-batch D1 reconciliation replaces it.
