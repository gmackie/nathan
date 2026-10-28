# Nathan roadmap and verification status

## Completed implementation work (requires CI/runtime verification)

- [x] README, architecture/security docs, permissive MIT license.
- [x] Better Auth identity Worker with OAuth 2.1 Provider / OIDC, JWT, admin, organizations, passkeys, TOTP, optional SSO.
- [x] Admin-only application registration form and endpoint.
- [x] OIDC gateway implementation with PKCE, nonce, AES-GCM flow state, D1 opaque sessions and proxy binding.
- [x] Typed bearer verification guard for Workers.
- [x] CLI configuration validator, DNS/account discovery, preview, and opt-in D1/Worker deployment path.
- [x] Node unit tests and GitHub Actions build-check workflow.

## Required before first actual production-ready release

- [ ] CI green on pinned dependencies; inspect package compatibility.
- [ ] Generate and commit Better Auth plugin schema migration from pinned release.
- [ ] Verify the complete OAuth/OIDC flow with real Cloudflare D1 and Workers.
- [ ] Test passkey enrollment, TOTP, SSO account linking, account recovery and administrator bootstrap.
- [ ] Complete the fail-closed provisioning sequence and all gateway deployment workflows.
- [ ] Verify that \`workers.dev\`, previews, extra routes and direct origin paths cannot bypass gateways.
- [ ] Add assurance claim support; do not report AAL2/AAL3 without verification.
- [ ] Implement back-channel logout and enforced local session revocation on IdP logout.
- [ ] Add integration suite for OAuth/OIDC, malformed callbacks, replay, concurrency and D1 state transitions.
- [ ] Complete automated Cloudflare OAuth/PCKE hosted installer and Identity Studio plugin UI.
- [ ] Validate rollback, key rotation, backups, logs and incident response under staging load.
- [ ] Independent security review, SBOM, pinned lockfile and release provenance.

## Later extensions

- Custom plugin approvals and isolation for out-of-process extensions.
- SCIM ingress/egress and verified enterprise SAML/OIDC provisioning.
- Authentik-style policy and flow designer.
- RADIUS/LDAP/SSH/non-HTTP outposts via native edge agents.
