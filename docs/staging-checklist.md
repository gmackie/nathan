# Nathan staging acceptance and security checklist

**Never run the following tests against an existing production identity authority or a sensitive application.** Create a disposable Cloudflare account or staging zone with explicit authorization.

## Prepare

- [ ] Verify the exact Git commit, lockfile, migration checksums, plugin versions and release manifest.
- [ ] Use an isolated Cloudflare account with Workers and D1, a managed active test zone and no overlapping DNS records.
- [ ] Register a Cloudflare OAuth client for the hosted installer with only the documented required scopes, code + PKCE and exact callback.
- [ ] Register separate test Google and GitHub OAuth apps with exact Nathan callback URLs.
- [ ] Set up test email and a password manager for one-time OAuth secrets.

## Hosted installer acceptance

- [ ] Run \`npm ci && npm run setup:installer\` from a clean checkout.
- [ ] Verify installer first deploy has no public routes and cannot be called without its secrets.
- [ ] Verify Cloudflare OAuth state/nonce, callback, refresh, client authorization, and sign-out.
- [ ] Select account, DNS zone, hostname and security profile; confirm resource preview exactly matches the chosen account.
- [ ] Simulate an existing DNS record, existing Worker, and existing D1 name. Verify each condition blocks installation without mutation.
- [ ] Create a new job. Verify one job per account/hostname and one active step per job; concurrent advance requests must fail closed.
- [ ] Verify D1 creation and complete SQL migration; compare the recorded migration hashes against the release manifest.
- [ ] Verify the uploaded Worker initially has \`NATHAN_INSTALL_ACTIVE=false\`; requests must return 503 except health.
- [ ] Verify \`workers.dev\` and previews remain disabled throughout the install.
- [ ] Confirm the attached custom hostname routes to the exact intended Worker only after secrets exist.
- [ ] Verify \`NATHAN_INSTALL_ACTIVE=true\` is set only after private upload and DNS attachment.
- [ ] Verify OIDC discovery issuer, JWKS and health; simulate DNS propagation delay and resume.
- [ ] Sign in with the same verified admin email. Verify account bootstrap promotes only that identity and logs the operation.
- [ ] Reload the wizard / sign in again as the same Cloudflare user, confirm only their own job is resumable.
- [ ] Attempt to continue another Cloudflare user's job; expect rejection.
- [ ] Interrupt each stage, retry, and verify no unrelated resources are overwritten or silently adopted.

## Domain-wide SSO acceptance

- [ ] Install the IdP at `login.example.com` and verify its realm row identifies the exact Cloudflare account, active zone and issuer host.
- [ ] Discover proxied HTTP DNS and Worker Custom Domains. Verify TXT/MX-only, wildcard DNS, `login.example.com` itself and lookalike domains never become suggested clients.
- [ ] Register `example.com`, `www.example.com` and `app.example.com` through Identity Studio. Confirm each new OAuth client is initially **disabled** with a distinct exact HTTPS callback.
- [ ] Complete the first root login, then visit subdomain apps and verify the same IdP login is reused without sharing `.example.com` cookies.
- [ ] Verify an application cannot use another app's OIDC ID Token or callback.
- [ ] Verify an unregistered subdomain cannot mint OAuth tokens merely because its hostname matches the apex.
- [ ] Test registration of nested subdomains and reject lookalikes, invalid callbacks, issuer-host registration, and duplicate/partially completed registrations.
- [ ] Verify a new subdomain can be explicitly onboarded without changing the original IdP's DNS or provider credentials.
- [ ] Verify domain-wide setup never installs wildcard Worker Routes or changes existing apex/subdomain DNS without explicit operator approval.

## OIDC/RP acceptance

- [ ] Verify authorize code + S256 PKCE, exact redirect URI and consent flow with a confidential Worker gateway client.
- [ ] Verify native public client with PKCE and no client secret; reject code exchange without verifier.
- [ ] Verify JWT signature, \`iss\`, \`aud\`, \`exp\`, \`azp\`, \`nonce\`, and token replay/redirect mismatch handling.
- [ ] Register an external web app and verify SSO works without Cloudflare DNS changes.
- [ ] Verify token revocation and refresh replay; rotate signing keys without breaking outstanding valid tokens.
- [ ] Verify logout, signed back-channel Logout Token, replay JTI rejection and local gateway session invalidation.
- [ ] Confirm the protected Worker cannot be reached through \`workers.dev\`, previews, another hostname, or the direct origin.
- [ ] Verify gateway removes caller-provided identity headers and enforces private upstream service binding.
- [ ] Verify \`API 401\`, interactive browser redirects, session expiry and revocation during DB outage.

## MFA/enterprise acceptance

- [ ] Enroll passkey, use it to authenticate, list and remove enrolled credential.
- [ ] Enroll TOTP, store recovery codes, finish password+TOTP sign-in; verify wrong code rejects.
- [ ] Verify SAML/OIDC enterprise discovery and account linking, including disabled/upstream deprovisioned accounts.
- [ ] Test safe admin recovery without creating an unprotected fallback account.
- [ ] Verify high-assurance or mandatory MFA options **remain disabled** until downstream \`acr\`/\`amr\` evidence is correct.
- [ ] Run policy tests for role authorization, applications disabled by default and changed permissions.

## First administrator, OAuth, SCIM and MFA acceptance

- [ ] Verify Cloudflare OAuth owner email matches the bootstrap admin and an arbitrary first visitor cannot become admin.
- [ ] Require verified Better Auth email and stable user ID before promoting the first account.
- [ ] Confirm enrollment and recovery codes, then require a recent session-bound passkey login for Business-profile privileged admin changes.
- [ ] Add a second verified administrator, test their MFA and permissions, revoke their grant and verify session invalidation; never permit web revocation of root owner.
- [ ] Block raw Better Auth admin/SSO management endpoints; test CSRF and authorized Studio checks.
- [ ] Encrypt initial Google/GitHub credentials in D1 and verify rotation/disable in Studio without stale Worker-secret fallback.
- [ ] Verify enterprise OIDC remains untrusted before DNS TXT domain proof; test same-domain account linking and signed upstream tokens.
- [ ] Validate SCIM Durable Object Users/Groups transactions, immutable externalId, PATCH active, ETags, bearer revocation and no automatic login authorization.
- [ ] Ensure audit records never reveal credentials, recovery codes or OAuth tokens.
- [ ] Confirm UI can tighten but never lower effective deployment MFA requirements.
- [ ] Test NATHAN_CONFIG_KEY loss/restore and managed-provider ciphertext decryption.
- [ ] Do not enable untested enterprise SAML metadata/signing/key management flows.
## MCP/admin acceptance

- [ ] Verify Identity Studio requires verified allowlisted Better Auth admin.
- [ ] Test unauthenticated and unscoped MCP requests, wrong issuer/audience, expired tokens, DPoP-bound tokens, incorrect origin, malformed protocol metadata and oversized bodies.
- [ ] Verify MCP reads list only redacted clients/users, SSO metadata and audit actions.
- [ ] Verify writes are not advertised by default; if explicitly enabled, require \`nathan:admin\`, a live admin session, and exact confirmation string.
- [ ] Verify user/client audit records redact secrets and sensitive credentials.
- [ ] Verify command-line and web login sessions cannot be confused with OAuth resource-bound MCP bearer tokens.

## Operational acceptance

- [ ] D1 database restore test using Cloudflare backup/restore mechanisms.
- [ ] Protect encrypted installer tokens from the app UI and user logs, then rotate installer encryption key.
- [ ] Rotate Google/GitHub OAuth secrets and user-facing app client secrets; revoke compromised sessions.
- [ ] Test Cloudflare API 403/429/5xx, D1 failures and service-binding outage with fail-closed behavior.
- [ ] Run OWASP ASVS Level 2-aligned review, dependency audit, SAST and independent protocol pentest.
- [ ] Record staging results with timestamps, commit SHA, severity, and remediation PRs.

**A passing GitHub Actions build is a necessary gate, not a production readiness approval.**
