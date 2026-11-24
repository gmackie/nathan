# Nathan staging acceptance and security checklist

**Never run the following tests against an existing production identity authority or a sensitive application.** Create a disposable Cloudflare account or staging zone with explicit authorization.

## Prepare

- [ ] Verify the exact Git commit, lockfile, migration checksums, plugin versions and release manifest.
- [ ] Use an isolated Cloudflare account with Workers and D1, a managed active test zone and no overlapping DNS records.
- [ ] Register a Cloudflare OAuth client for the hosted installer with only the documented required scopes, code + PKCE and exact callback.
- [ ] Register separate test Google, GitHub, Apple, Discord, Twitch and X OAuth apps with exact Nathan callback URLs (see providers.md).
- [ ] Run a Studio test sign-in for each provider with a real test account; confirm unverified/absent emails (Discord unverified, X without email access) get placeholder emails and do not link.
- [ ] Run a Studio test sign-in as an administrator for the provider administrators will keep; confirm disabling the other providers is refused until then, and that `providers add <id> --apply` with a new secret takes effect immediately and voids the provider's previous test.
- [ ] Apple: confirm domain registration, form_post callback and the runtime-minted client secret are accepted by appleid.apple.com.
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

## Hosted email sign-in

- [ ] On the staging issuer, record the deployed revision, migrations 0019 through 0021, the email feature flag and the configured Resend sender. Open a registered staging RP with S256 PKCE, state and nonce using an invited test mailbox.
- [ ] Check the delivered subject, app name and any configured inline logo. Complete one authorization with the code and another with the link. Verify the exact callback, state, token signature, issuer, nonce and registered resource audience.
- [ ] Confirm each email yields at most one session. Check that an email-authenticated administrator still needs a passkey for Studio. Check that a directory member outside a verified SSO domain still needs enrolled TOTP. Check a verified enterprise-domain refusal and one success audit per completed sign-in. Record delivery and round-trip results against the revision.

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
- [ ] SAML (NATH-10): connect a real Okta, Entra ID and Google Workspace tenant per [saml.md](saml.md); verify the DNS TXT challenge resolves from the deployed Worker; sign in through **Sign in with SSO**; confirm invitation-only refuses a new person, just-in-time creates one in the domain only; rotate a certificate (add next, activate in the IdP, retire old); confirm an IdP-initiated tile login and a disabled connection are refused.
- [ ] SAML IdP (NATH-12): generate the signing key, sign in to real AWS IAM Identity Center, Salesforce and Grafana tenants per [saml-idp.md](saml-idp.md) (SP- and, where enabled, IdP-initiated); confirm a user without the bound app's role, a disabled SP and an unregistered ACS get no assertion; confirm the auto-POST page is not blocked by `form-action` when the ACS redirects cross-origin; with an unsigned SP (AWS) and an existing Nathan session, confirm the "Continue to … as …?" page appears, Continue signs in and Cancel sends nothing, while a signing SP (Salesforce, Grafana with `signature_algorithm`) goes straight through; rotate the key through the overlap without an SP outage.
- [ ] Test safe admin recovery without creating an unprotected fallback account.
- [ ] Verify high-assurance or mandatory MFA options **remain disabled** until downstream \`acr\`/\`amr\` evidence is correct.
- [ ] Run policy tests for role authorization, applications disabled by default and changed permissions.
- [ ] Follow [quickstart-rbac.md](quickstart-rbac.md) end to end: new app denies everyone, a granted user reaches the upstream, `user.can()` matches the role, and a revoked grant returns 403 within `ACCESS_CACHE_TTL_SECONDS`.
- [ ] Confirm the upstream rejects requests without a valid `X-Nathan-Principal`, and that `NATHAN_PRINCIPAL_KEY` differs per gateway.
- [ ] Register a directory client and read `/directory/v1/principal` and `/directory/v1/changes` with a client-credentials token; disabling the client must cut access immediately.

## First administrator, OAuth, SCIM and MFA acceptance

- [ ] Verify Cloudflare OAuth owner email matches the bootstrap admin and an arbitrary first visitor cannot become admin.
- [ ] Require verified Better Auth email and stable user ID before promoting the first account.
- [ ] Confirm enrollment and recovery codes, then require a recent session-bound passkey login for Business-profile privileged admin changes.
- [ ] Add a second verified administrator, test their MFA and permissions, revoke their grant and verify session invalidation; never permit web revocation of root owner.
- [ ] Block raw Better Auth admin/SSO management endpoints; test CSRF and authorized Studio checks.
- [ ] Encrypt the installer's first provider credentials in D1 and verify rotation/disable in Studio without stale Worker-secret fallback.
- [ ] Verify enterprise OIDC remains untrusted before DNS TXT domain proof; test same-domain account linking and signed upstream tokens.
- [ ] Validate SCIM Durable Object Users/Groups transactions, immutable externalId, PATCH active, ETags, bearer revocation and no automatic login authorization.
- [ ] NATH-11 with live Okta and Entra tenants: verified-domain linking, deactivation revoking Nathan and gateway sessions within 60 s, reactivation without restored sessions, group push into a mapped group, a D1 outage answered with 503 and later applied, and back-channel logout reaching the gateway.
- [ ] NATH-11 review fixes on staging: a directory deactivation of a Nathan administrator is held for review (no ban, sessions intact) and applies once when another administrator approves; keep active survives a resync; a rehire after DELETE gets 201; a resync of a large directory drains through the Durable Object alarm; a poisoned outbox entry is skipped from Studio.
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
- [ ] Rotate social provider OAuth secrets (and the Apple .p8 key) and user-facing app client secrets; revoke compromised sessions.
- [ ] Test Cloudflare API 403/429/5xx, D1 failures and service-binding outage with fail-closed behavior.
- [ ] Run OWASP ASVS Level 2-aligned review, dependency audit, SAST and independent protocol pentest.
- [ ] Record staging results with timestamps, commit SHA, severity, and remediation PRs.

**A passing GitHub Actions build is a necessary gate, not a production readiness approval.**
