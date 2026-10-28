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

## Required before first actual production-ready release

- [ ] Verify root → nested-subdomain → root SSO against real Cloudflare Workers and non-Workers, including strict per-client audience isolation.
- [ ] Verify the complete OAuth/OIDC flow with real Cloudflare D1 and Workers.
- [ ] Complete real-account end-to-end tests for initial-admin claim, passkey/TOTP enrollment, session step-up, SSO linking and administrator recovery.
- [ ] Complete the fail-closed provisioning sequence and all gateway deployment workflows.
- [ ] Verify that `workers.dev`, previews, extra routes and direct origin paths cannot bypass gateways.
- [ ] Add assurance claim support; do not report AAL2/AAL3 without verification.
- [x] Implement signed back-channel logout receiver; full end-to-end logout delivery and revocation test remains pending.
- [ ] Add integration suite for OAuth/OIDC, malformed callbacks, replay, concurrency and D1 state transitions.
- [ ] Run installer end-to-end against a real Cloudflare OAuth client; validate D1 API batch semantics, domain propagation, script binding retention, retries and safe recovery on failure.
- [ ] Implement full installer rollback/reconciliation for interrupted upload and database ownership states (currently fails closed on ambiguity).
- [ ] Verify end-to-end Enterprise SSO provider registration, passkey/TOTP enrollment and policy enforcement. Plugin runtime installation remains a reviewed redeploy operation.
- [ ] Validate rollback, key rotation, backups, logs and incident response under staging load.
- [ ] Independent security review, SBOM, signed release provenance and staged operational audit.

## Later extensions

- Custom plugin approvals and isolation for out-of-process extensions.
- SCIM ingress/egress and verified enterprise SAML/OIDC provisioning.
- Authentik-style policy and flow designer.
- RADIUS/LDAP/SSH/non-HTTP outposts via native edge agents.

## Future optional whole-zone ingress

- [ ] Design an explicitly opt-in, fail-closed `example.com/*` + `*.example.com/*` gateway with a verified upstream map and a login-host exclusion. Domain-wide OIDC alone does not intercept or secure HTTP traffic.
- [ ] Support high-scale tenant subdomains through an explicitly authorized canonical callback app plus cryptographically bound tenant return state rather than wildcard redirects.

## SCIM production-lifecycle limitation

Current SCIM support stages transactional directory Users and Groups but deliberately **does not** link external IDs to Better Auth login identities or immediately deprovision sessions. Production SCIM identity synchronization, role/group mapping, replay-safe reconciliation and fail-closed revocation need a separate tested milestone. The official Better Auth SCIM plugin cannot simply be enabled against D1 because it needs interactive transaction semantics.
