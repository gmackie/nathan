# Nathan threat model (v0.1, pre-release)

Nathan is an identity provider. An attacker who compromises its signing keys, OAuth clients, session records, or policy rules can potentially compromise every relying application. This document is a **threat-model draft**, not a completed assessment.

## Assets and trust boundaries

**Critical assets:** Better Auth users and credentials, passkeys/TOTP secrets, signed OAuth codes/tokens, signing keys, verified federation claims, upstream IdP credentials, OIDC client registry, administrator sessions, Cloudflare API/OAuth tokens, private Worker routes, gateway session handles, email recovery links, and audit events.

**Boundaries:** public Internet to Cloudflare Worker; browser to Nathan IdP; IdP to its D1 database; browser to gateway; gateway to private Worker through service binding; hosted installer to Cloudflare account API; Nathan to external upstream IdPs; trusted core to third-party plugins/extensions.

**Attackers:** unauthenticated Internet clients, malicious registered OAuth clients, compromised end-user sessions, tenants attempting cross-tenant impersonation, compromised OAuth providers, malicious npm plugins, insider admins and attackers with Cloudflare deploy permissions.

## Threat register

| ID | Threat | Required defense | Current state |
| --- | --- | --- | --- |
| T01 | Forged ID/access tokens | Strict JWT issuer, audience, signature algorithms, JWKS and key rotation | Implemented in gateway/SDK; live tests pending |
| T02 | Authorization code interception | S256 PKCE, exact redirect, single-use code | Better Auth + gateway configured; E2E pending |
| T03 | OAuth login CSRF / mix-up | Random state, nonce, issuer check, short-lived encrypted flow state | Gateway implementation; E2E pending |
| T04 | User-to-user token substitution | Token audience/resource binding, session/account checks | Partial; test matrix pending |
| T05 | Unverified email claim | Never promote unverified email into application identity | Gateway email forwarding hardened |
| T06 | MFA bypass through social or passkey login | Central verified AAL/ACR, step-up, enrollment and recovery | **Not complete**; high profile must fail closed |
| T07 | Direct upstream Worker bypass | Remove all public routes, previews and workers.dev; verify bindings | Installer checks visible exposure; audit pending |
| T08 | Header spoofing | Strip incoming identity headers before trusted forwarding | Implemented; integration tests pending |
| T09 | Session fixation or replay | Opaque random handles, hashed D1 storage, host-only Secure HttpOnly cookies | Implemented; concurrency tests pending |
| T10 | Session persists after logout | Verified signed back-channel logout, revoked D1 record | Receiver built; interoperability pending |
| T11 | Cross-origin state-changing request | Same-origin check + CSRF protections | Gateway/Studio/installer protected; browser tests pending |
| T12 | Cached private responses | Explicit no-store and origin-only proxy | Gateway hardened |
| T13 | Credential stuffing / distributed brute-force | Atomic shared rate-limit storage, provider-specific rules | D1-backed rate limits configured; load testing pending |
| T14 | Rogue OAuth client registration | Admin allowlist and Better Auth clientPrivileges, DCR disabled | Implemented; privilege regression tests pending |
| T15 | Installer token theft | Encrypt D1 tokens, host-only cookies, no browser token exposure | Hosted preview implemented; live review pending |
| T16 | Plugin supply-chain compromise | Pinned lockfile, independent review, no arbitrary runtime eval | Initial controls; release attestation pending |
| T17 | Signing key exfiltration or unexpected rotation | Least-privilege secrets, verified rotation and secure backup | **Not complete** |
| T18 | Audit-log manipulation | External tamper-evident export and administrative separation | D1 audit events exist; immutable export pending |
| T19 | D1 race / transaction failure | Atomic one-time operations, idempotent migrations, adversarial concurrency tests | Unit schema tests only; load tests pending |
| T20 | Cloudflare zone or OAuth scope confusion | Exact account/hostname inspection, least privilege, explicit plan diff | Preview checks implemented; real account tests pending |

## Security release gates

1. Successful login and token issuance against a real Cloudflare D1/staging Worker deployment; verify code exchange, PKCE, nonce, JWKS, userinfo and session revocation.
2. Unauthorized client registrations and scope escalations rejected by both public Better Auth endpoints and Nathan Studio.
3. Cross-client access tokens and wrong-audience tokens rejected; verify public clients never receive bearer secrets reserved for confidential clients.
4. Gateway upstream unreachable through every public route, preview and Workers.dev path, including Cloudflare routing changes during install.
5. Passkey/TOTP/SSO enrollment, identity linking, MFA step-up and recovery proven with browser E2E tests and the selected assurance profile.
6. Key rotation, downtime, failed email delivery, migration crash, D1 concurrency and OAuth provider outage recover safely and fail closed.
7. External security review, third-party dependency review, operational monitoring, backups and incident response drills completed.

Do not advertise production-grade access, FAPI 2.0, NIST AAL2/AAL3, SOC 2, ISO 27001, HIPAA or FedRAMP compliance until the corresponding independently validated controls and deployment obligations are satisfied.

## Useful references

- OAuth 2.0 Security Best Current Practice (RFC 9700)
- OpenID Connect Core 1.0 and Back-Channel Logout 1.0
- JWT Best Current Practices (RFC 8725)
- NIST SP 800-63-4 digital identity guidance
- OWASP ASVS 5.0
- Cloudflare Workers security and secret management documentation
