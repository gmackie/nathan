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
- [x] Hosted installer preview: Cloudflare OAuth PKCE, encrypted D1 sessions, account/zone/Worker discovery, read-only deployment plan.
- [x] Provider-specific guided secret installation, verified-admin bootstrap and application gateway installer staging.
- [x] Identity Studio OAuth client create/list/disable, plugin catalog and admin security audit.

## Required before first actual production-ready release

- [ ] Verify the complete OAuth/OIDC flow with real Cloudflare D1 and Workers.
- [ ] Test passkey enrollment, TOTP, SSO account linking, account recovery and administrator bootstrap.
- [ ] Complete the fail-closed provisioning sequence and all gateway deployment workflows.
- [ ] Verify that `workers.dev`, previews, extra routes and direct origin paths cannot bypass gateways.
- [ ] Add assurance claim support; do not report AAL2/AAL3 without verification.
- [x] Implement signed back-channel logout receiver; full end-to-end logout delivery and revocation test remains pending.
- [ ] Add integration suite for OAuth/OIDC, malformed callbacks, replay, concurrency and D1 state transitions.
- [ ] Complete hosted Cloudflare OAuth installer release-upload, migrations, secret installation, custom-domain publishing, retries and rollback.
- [ ] Extend Identity Studio with live plugin installation, enterprise SSO provider enrollment, passkey/TOTP enrollment and policy management.
- [ ] Validate rollback, key rotation, backups, logs and incident response under staging load.
- [ ] Independent security review, SBOM, signed release provenance and staged operational audit.

## Later extensions

- Custom plugin approvals and isolation for out-of-process extensions.
- SCIM ingress/egress and verified enterprise SAML/OIDC provisioning.
- Authentik-style policy and flow designer.
- RADIUS/LDAP/SSH/non-HTTP outposts via native edge agents.
