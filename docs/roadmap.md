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
- [x] Guided social login for Google, GitHub, Apple, Discord, Twitch and X from one registry across Studio, hosted installer and CLI: console deep links, exact callbacks, validated credentials, field-bound encrypted storage, runtime-minted Apple client secret, verified-email-only account linking and recorded test sign-in (NATH-9, workerd-tested against mocked providers; live provider accounts pending).
- [x] One credential source per provider (CLI Worker secret, then Studio D1 row, then legacy secrets) with no copying between them, so a CLI rotation always takes effect. Tests are bound to a credential version. The last-login-method rule requires an administrator's test and is one atomic D1 write. Provider updates, denials and validation failures are audited (NATH-9 security review).
- [x] Enterprise OIDC registration, DNS TXT domain ownership challenge and verification in the privileged UI.
- [x] Block direct raw Better Auth admin/SSO management endpoints to avoid bypassing Nathan's admin policy.
- [x] Per-connection SCIM 2.0 Users/Groups SQLite Durable Object, strict bearer validation, disabled-by-default connection and token rotation.
- [x] Optional initial SCIM configuration in hosted wizard; one-time directory token revealed after verified admin setup.
- [x] Server-side admin enrollment policy and session-scoped passkey reauthentication for privileged actions.
- [x] Explicit additional verified-admin grants, revocation and session invalidation.
- [x] Runtime-forward-only MFA policy tightening from Identity Studio, never weakening the deployment baseline.
- [x] Wizard-vs-Studio settings/recovery guide: [setup-lifecycle.md](setup-lifecycle.md).
- [x] Inbound enterprise SAML (NATH-10): samlify/xmldom proven in workerd; IdP metadata validator (Okta/Entra/Google shapes); hardened plugin plus Nathan's pre-parse message guard (duplicate SAML parameters refused so the checked message is the processed one; SHA-1/MD5 rejected including POSTed XML signatures, which the plugin's onDeprecated does not cover; encrypted content refused), 2 minute skew, timestamps, SP-initiated only, InResponseTo and assertion replay protection); Studio connections that start disabled, require DNS-verified domains, rotate certificates (compare-and-swap) and warn before expiry; audited metadata preview; invitation-only or just-in-time provisioning limited to the verified domain; "Sign in with SSO" domain routing. Runtime-tested in workerd with a test IdP; live IdP tenants pending ([saml.md](saml.md)).

## Nathan as a SAML identity provider (NATH-12; implemented source, staging pending)

- [x] SPs (AWS IAM Identity Center, Salesforce, Grafana, any SAML 2.0 SP) registered in Identity Studio from metadata (pasted or fetched over HTTPS without redirects) or by hand: disabled by default, bound to one Nathan application, exact HTTPS ACS URLs, persistent pairwise NameIDs unless email is chosen, attribute mapping (email, name, the bound app's roles, permissions and granting groups), optional signed AuthnRequests, Response signing, passkey requirement and IdP-initiated sign-in. Admin with step-up, exact confirmation, audited (migration 0018).
- [x] IdP signing keys generated in the Worker (RSA 2048/3072/4096, self-signed SHA-256 certificate), sealed under NATHAN_CONFIG_KEY with purpose AAD, never returned; rotation publishes the next certificate in metadata, activates it after a 24 h overlap and retires the old key. Global metadata at `/saml/idp/metadata`, SSO for HTTP-Redirect and HTTP-POST at `/saml/idp/sso`.
- [x] SP-initiated SSO through one strict parser (inbound lessons: one of each parameter, canonical encoding, no body on GET, processed bytes = inspected bytes, POST requests processed from the signed bytes), registered/enabled SP, exact ACS, signatures when required, 5-minute freshness and single-use request IDs in D1; a signed single-use resume handle across sign-in; issuance only after NATH-13 allows the bound app and ban, SCIM, admission and email checks pass; signed assertion (RSA-SHA256, exclusive c14n, ≤ 5 min, audience/recipient/InResponseTo) on an auto-POST page with nonce CSP and `form-action` limited to the ACS origin. AuthnContextClassRef only from passkey evidence. Every assertion audited (SP, user, outcome).
- [x] Unsigned AuthnRequests answered with a pre-existing session need the user's confirmation on Nathan's page (forged cross-site requests cannot auto-post an assertion); ACS indexes resolved by the SP metadata's values; bounded body reads; a reason code on every refusal.
- [x] Workerd-tested with samlify's ServiceProvider validating Nathan's responses (Redirect and POST, signed requests, tampering, signature wrapping, every refusal case with its reason code, the confirmation page, rotation gates through the overlap, 3072/4096-bit keys), each test on its own SP and independent of order. [Guide](saml-idp.md).
- [ ] Verify against real AWS IAM Identity Center, Salesforce and Grafana tenants on staging (including the `form-action` check for ACS endpoints that redirect cross-origin). Single logout is not implemented.

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
- [x] MCP scopes capped by permissions (NATH-14, see below).
- [x] SCIM group mapping (NATH-11, see below).

## Gatekeeper-ready access tokens (NATH-15; implemented source, staging pending)

- [x] RFC 9068 JWT access tokens (`typ: at+jwt`, `client_id`, `jti`) with `principal_kind` (user / machine / agent), capped at 900 s for every access token.
- [x] Token audiences registered in Identity Studio (migration 0014), optionally bound to an app for a `roles` hint from the NATH-13 evaluator. Clients are linked per audience. Machine and agent client-credentials clients use scope `nathan:api`.
- [x] Administrator-set `agent` kind per client (admin-only, audited). Without a live user session a token is never `user`.
- [x] `nathan_amr`/`nathan_acr`/`nathan_auth_time` only from verified passkey sign-in evidence for the token's session. Better Auth 1.7.14 reserves and strips `acr`/`amr`/`auth_time` on access tokens, so Gatekeeper `mfa` is never set by Nathan tokens.
- [x] Ready-to-paste Gatekeeper provider entry ([gatekeeper.md](gatekeeper.md)), workerd-tested with user (authorization code + PKCE), machine and agent tokens, against Gatekeeper's own resolver (a pinned, unmodified copy in `tests/vendor/gatekeeper`, so CI runs it without a checkout).
- [x] Security-review fixes: user tokens for registered audiences need a live, unexpired session of the same user (refresh after sign-out, session revocation or expiry gets `invalid_grant`), banned users get no tokens, `nathan:api` only for client credentials and administrator-marked agents, `roles` only when every requested audience is bound to the same app, audience removal drops client links, and docs say that Gatekeeper policies must check `principal_kind`. Passkey evidence is tested through a real software-authenticator sign-in.
- [ ] Verify against a deployed Nathan and Gatekeeper on staging, including a live passkey sign-in.
- [ ] Standard `acr`/`amr`/`auth_time` on access tokens once Better Auth offers a supported way, and verified provider evidence.

## Remote MCP servers with per-scope consent (NATH-14; implemented source, staging pending)

- [x] Nathan-owned MCP authorization server (`/mcp-oauth`): RFC 8414 metadata, rate-limited expiring RFC 7591 public-client registration restricted to MCP catalog scopes, S256 PKCE only, exact HTTPS/loopback redirects, mandatory RFC 8707 `resource` on authorize, token and refresh. Better Auth 1.7.14's consent and static scopes cannot express per-app catalogs ([decision](remote-mcp.md#design-decisions)).
- [x] Scope catalogs from app permissions (migration 0015): labels, descriptions, groups, `requires`, sensitive and admin-only scopes, aliases and a Full access marker that never covers sensitive scopes.
- [x] Script-free consent page with per-scope checkboxes, single-use session-bound ticket, empty selection without consuming it, Safari `form-action` allowance; `/connections` to edit or disconnect; Studio registration and revocation (admin, step-up, audited).
- [x] Effective scopes = grant ∩ current permissions at every issuance and check; refresh narrowing by intersection; rotation reuse and code replay revoke the grant; RFC 7009 revocation.
- [x] NATH-15 tokens (`principal_kind: agent`, 300 s) and Worker SDK `nathanMcp()` with RFC 9728 metadata, 401/403 challenges, `user.can()` and a ≤ 30 s cached grant check (service binding or HTTPS). Workerd-tested with an MCP TypeScript SDK client and a sample MCP server. [Guide](remote-mcp.md).
- [x] Security review fixes: consent and connections pages use `Referrer-Policy: same-origin` so browser form posts carry Nathan's `Origin` (`Origin: null` stays refused); registration bounded (unused clients pruned after 24 h and capped at 1,000, stored metadata < 4 KB, unknown fields dropped, global limit counts stored registrations only); codes and refresh tokens consumed atomically so a concurrent second use revokes the grant; a refresh with nothing usable (or during a ban) keeps its refresh token; Studio keeps MCP resources and Better Auth audiences apart; the SDK answers 503 for JWKS outages.
- [ ] Verify with a deployed Nathan and MCP server, real browsers (Chromium form posts with the same-origin policy, Safari `form-action` after the consent redirect) and specific MCP products.
- [ ] Client ID Metadata Documents (needs resolve-once DNS handling; Better Auth's `@better-auth/cimd` is a separate plugin).
- [ ] Import scope metadata from a Gatekeeper action catalog (shape designed in [remote-mcp.md](remote-mcp.md#design-decisions)).

## Inbound SCIM lifecycle (NATH-11; implemented source, staging pending)

- [x] Identity linking by (connection, externalId); first link by email only on the connection's verified domain and a verified Nathan email; a link never moves across connections (migration 0016, workerd-tested).
- [x] Optional just-in-time account creation per connection (default off, unverified email), subject to the installation's admission policy (NATH-16).
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
- [x] Re-review fixes: deprovisioning takes over expiring bans (a lapsed suspension never ends a deprovisioning or counts as an override); only lifting Nathan's own SCIM ban is an override, recorded by a D1 trigger on every path; every batch of a large group starts with the compare-and-set; the last-administrator check is inside the deprovisioning batch (atomic across connections); approve/dismiss audit `rejected` when the item was decided meanwhile; review creation is rate-limited per connection and Studio pages reviews pending first, oldest first, with counts.
- [ ] Per-user directory profile sync (name only) if needed.

## Follow-ups to the federation work (NATH-16 to NATH-19; implemented source, staging pending)

- [x] Account admission (NATH-16): installation-wide invitation-only (default) or self-service mode, changed in Studio (admin, step-up, exact confirmation, audited); invitations bound to one email, single use, expiring, revocable and listed (migration 0017). One Better Auth `user.create.before` guard composes the SAML guard, the enterprise OIDC domain guard and admission for password, social, enterprise OIDC and SAML sign-ups; an invitation is claimed only by a method that proved the address (a password sign-up is provisional and claims it at email verification; enterprise OIDC only inside the connection's verified domain). SCIM just-in-time creation asks the same policy and claims the invitation in its account batch (raced against Better Auth: exactly one account). A squatted invitation does not lock the invitee out: their verified social sign-in supersedes the provisional account (audited), and Studio can remove an unverified account and reissue the invitation. The installer's first administrator is admitted only with a proven installer email. A refusal creates no user row and explains itself (`ACCOUNT_NOT_ADMITTED`). Workerd-tested per method (password with verification, GitHub, Discord placeholder email, enterprise OIDC, SAML JIT, SCIM JIT). **Upgrade note:** 0017 switches existing installations to invitation-only (recorded in the audit; Studio shows a one-time notice when accounts already existed), and SCIM just-in-time connections stop creating accounts until invitations or self-service are set. [Guide](admission.md).
- [x] Per-provider credential isolation (NATH-17): an undecryptable or unusable provider is skipped and marked unavailable (migration 0017, reason code only, audited at most once per provider per hour, shown with id and reason in Studio, and only as a count in the public `/healthz`), never replaced by an older or legacy credential source; other providers, Studio, repair and disable keep working. Workerd-tested with a corrupted D1 row and legacy secrets present.
- [x] App-scoped cookie principal (NATH-18): `NathanVerifier.getPrincipal` answers only for users the pinned application allows, with the app's roles and permissions and without the global Better Auth role; `access` returns `sub` only when allowed. The SCIM Durable Object refuses callers other than the identity Worker (no RPC, caller proof on `fetch`), and only the identity Worker may bind it (documented). Workerd-tested with app-bound probes and a foreign Worker that binds the class.
- [x] Ban/unban change-feed tests through Better Auth's own admin `banUser`/`unbanUser` and an expired-ban sign-in through the identity Worker, plus a schema test that the 0011 and 0016 user-state triggers exist (NATH-18).
- [x] SCIM ban lapse (NATH-19): a deprovisioned user without an administrator override gets no session when an administrator's expiring ban over the SCIM ban lapses. Better Auth lifts the expired ban at sign-in; Nathan's `session.create.before` guard refuses the session, restores the SCIM ban in the same batch and audits `scim_ban_lapse_reapplied`. Workerd-tested with the exact scenario through Better Auth's admin `banUser` and a real sign-in, plus the override and ordinary-ban cases.
- [ ] Verify invitation-only sign-up against staging with real providers, a live IdP and a live SCIM directory.

## Required before first actual production-ready release

- [ ] Verify root → nested-subdomain → root SSO against real Cloudflare Workers and non-Workers, including strict per-client audience isolation.
- [ ] Verify the complete OAuth/OIDC flow with real Cloudflare D1 and Workers.
- [x] Passwordless email sign-in code (NATH-49): Better Auth's first-party `emailOTP` plugin, sign-in only, off by default (`ENABLE_EMAIL_OTP`), Resend required (fails closed); 6-digit hashed codes, 10 minutes, 3 attempts; per-IP, per-address (10 minutes and daily, hashed) and instance-wide refused-code limits; generic answers with background delivery; codes mailed only to addresses that may sign in by code; administrators, TOTP/passkey accounts, directory and SSO accounts never sign in by code (answered as a wrong code); email-code sessions never administer (migration 0019); admission as method `email-otp` (invitation claim, self-service, refusal, squatted unverified account); no assurance evidence; audited; hosted "Email me a code" path that resumes OIDC authorization. Workerd-tested with mocked Resend. [Guide](providers.md#passwordless-email-sign-in-email-code).
- [ ] Complete real-account end-to-end tests for initial-admin claim, passkey/TOTP enrollment, session step-up, SSO linking and administrator recovery.
- [ ] Complete the fail-closed provisioning sequence and all gateway deployment workflows.
- [ ] Verify that `workers.dev`, previews, extra routes and direct origin paths cannot bypass gateways.
- [ ] Add assurance claim support; do not report AAL2/AAL3 without verification. (NATH-15 reports passkey sign-in evidence under `nathan_*` claims only; it is not AAL2.)
- [x] Implement signed back-channel logout receiver. Revocation and JTI replay record commit atomically, storage failures return 503 so the IdP retries (NATH-8, workerd-tested). IdP-side delivery with retries exists for SCIM deprovisioning (NATH-11); delivery on interactive sign-out still relies on Better Auth's single attempt.
- [ ] Add integration suite for OAuth/OIDC, malformed callbacks, replay, concurrency and D1 state transitions.
- [ ] Run installer end-to-end against a real Cloudflare OAuth client; validate D1 API batch semantics, domain propagation, script binding retention, retries and safe recovery on failure.
- [ ] Implement full installer rollback/reconciliation for interrupted upload states. Interrupted D1 creation, stale/concurrent stage execution and CLI secret reconciliation are handled and runtime-tested (NATH-8); other ambiguous states still fail closed.
- [ ] Verify each social provider with real test accounts in staging (Apple domain/form_post, X email access, Twitch email_verified claim).
- [ ] Verify end-to-end Enterprise SSO provider registration, passkey/TOTP enrollment and policy enforcement. Plugin runtime installation remains a reviewed redeploy operation.
- [ ] Validate rollback, key rotation, backups, logs and incident response under staging load.
- [ ] Independent security review, SBOM, signed release provenance and staged operational audit.

## Later extensions

- Custom plugin approvals and isolation for out-of-process extensions.
- SCIM ingress/egress and verified enterprise OIDC provisioning. SAML follow-ups: encrypted assertions, signed AuthnRequests, single logout, scheduled metadata refresh.
- SAML IdP follow-ups (NATH-12 shipped the base): single logout, encrypted assertions, outbound SCIM to SPs, AWS IAM role-ARN attributes, honouring RequestedAuthnContext.
- Authentik-style flow designer. Rich authorization policy (conditions, approvals, resource rules) belongs to Gatekeeper, which reads Nathan's roles.
- RADIUS/LDAP/SSH/non-HTTP outposts via native edge agents.

## Future optional whole-zone ingress

- [ ] Design an explicitly opt-in, fail-closed `example.com/*` + `*.example.com/*` gateway with a verified upstream map and a login-host exclusion. Domain-wide OIDC alone does not intercept or secure HTTP traffic.
- [ ] Support high-scale tenant subdomains through an explicitly authorized canonical callback app plus cryptographically bound tenant return state rather than wildcard redirects.

## SCIM lifecycle status

Since NATH-11, SCIM links directory users to Nathan accounts (opt-in per connection), deprovisions them fail-closed, and feeds explicitly mapped groups; see [scim.md](scim.md). It is not yet verified against live Okta or Entra tenants. The official Better Auth SCIM plugin still cannot be enabled against D1, because it needs interactive transactions; Nathan's per-connection Durable Object plus single-batch D1 reconciliation replaces it.
