# Nathan as an OIDC identity provider

Nathan's Better Auth OAuth Provider issues tokens and owns discovery, client registration, JWKS, refresh and revocation. Clients can be in the same account or on any other hosting provider.

- Worker with service binding: session verification via private RPC; OIDC client optional.
- Single-app instance (`AUTH_MODE=single-app`): the pinned app calls `beginEmailSignIn` / `finishEmailSignIn` on `NathanVerifier` and draws its own sign-in form. The methods return a subject and email, never a session cookie, a token, or an admin role. The identity hostname stays the instance's IdP management UI. Unset on a shared IdP (`id.gmac.io`); those methods then answer unavailable, as does a binding that is not pinned.
- Worker or external web app: confidential OIDC client using authorization code + PKCE.
- Mobile app: public OIDC client with PKCE, claimed HTTPS or loopback redirects.
- CLI: device authorization where enabled.
- Machine: client credentials with explicit scopes and audience; never confuse a machine principal with a user.

Client secrets are displayed once. Callback URIs must be exact, HTTPS except explicitly permitted native loopback forms. JWTs are resource-bound and validated for issuer, audience, signature, and required scope.

**Access tokens (NATH-15):** a token request that names a configured RFC 8707 `resource` gets an RFC 9068 JWT (`typ: at+jwt`) with `principal_kind` (`user`, `machine` or `agent`). Otherwise the token is opaque. No access token lives longer than 900 s, so use refresh tokens (`offline_access`) for long sessions. A refresh for a registered audience works only while the user's sign-in session is live (signing out, session expiry and bans end it with `invalid_grant`), except for clients marked `agent`. Name the scopes you need: `nathan:api` is refused to clients not marked `agent`, and so is an authorization request without `scope` when the default would include it. Register APIs and Gatekeeper as token audiences in Identity Studio. See [gatekeeper.md](gatekeeper.md) for the claims, the evidence-only `nathan_amr`/`nathan_acr` claims and the Gatekeeper provider entry.

**Assurance limitation:** Better Auth's OAuth Provider currently advertises ACR `0` by default. Nathan must not invent an AAL2 claim because a TOTP or passkey plugin was enabled. High-assurance gateway requests fail closed until real assurance claims are verified.

**Logout:** Gateway code verifies signed OIDC back-channel Logout Tokens and deletes sessions by `sid` or subject. Client registration must enable `backchannel_logout_uri` for the gateway to receive them.

## Domain-wide relying parties

Use one issuer `https://login.example.com/api/auth` for `example.com` and all approved subdomains. Each client must register its own **exact HTTPS callback**, and its authorization is not inherited from the domain or from another RP. See [domain-wide-sso.md](domain-wide-sso.md) and the Identity Studio realm tab. Never use wildcard redirect URLs or a shared `.example.com` session cookie.

## Hosted email sign-in

Start at the discovered authorization endpoint with the registered client's exact callback, `response_type=code`, S256 PKCE, `state`, `nonce` and explicit scopes such as `openid email`. An optional `login_hint` prefills the email address. Nathan carries the issuer-signed authorization through the hosted email form and consent. The RP receives its usual authorization code and exchanges it with its PKCE verifier. ClassCheck can use this contract for its confidential web client, mapping the verified issuer and subject to its local user.

One Resend message contains a six-digit code and a link to the issuer. Both redeem the same five-minute credential. Open the link in the requesting browser. When reading mail on another device, enter the code in the original tab. A link preview cannot consume the credential. A new delivery for the same address supersedes its predecessor. Each email proof expires after five minutes and allows five attempts. The same browser completes any enrolled TOTP challenge within that expiry.

| Limit | Ten minutes | Day |
| --- | ---: | ---: |
| Sends per normalized address | 3 | 10 |
| Sends per source IP | 10 | — |
| Verifications per address, including TOTP | 5 | 15 |
| Verifications per source IP | 20 | — |

The issuer also caps refused proofs at 500 per hour across all addresses. Requests give the same acknowledgment for ineligible addresses, delivery errors and throttling. A successful sign-in records a session-bound `email_otp_sign_in` audit. Rejected proof checks share one anonymous rejection audit per minute.

Eligible users have a verified account, an active directory-provisioned subject, or an open invitation. New accounts need that specific invitation even on a self-service instance. An active directory user outside verified enterprise SSO domains may use email and must complete enrolled TOTP. Addresses in a verified enterprise domain (including its subdomains) and accounts linked to an enterprise identity provider use organization sign-in. Nathan rechecks eligibility at redemption and session creation. Bans, directory deprovisioning and inconsistent factor enrollment fail closed. An administrator who signs in by email needs a separate authenticator sign-in and the existing fresh passkey step-up for privileged operations.

### Sender and client branding

Set `ENABLE_EMAIL_OTP=true`, configure `RESEND_API_KEY` and `EMAIL_FROM` on the identity Worker. Apply every migration in the release package in order before upgrading an auth Worker. Migration 0023 adds the shared logout queue’s issued subject. Migrations 0024–0026 record membership changes, capture participants at session deletion, and retire unproven historical erasure notifications. Fresh installs and the tracked production configuration default to off. The tracked staging configuration opts in. The signed OIDC client selects the registered name and its validated `appearance` metadata. The protected `POST /studio/api/clients` registration accepts an optional `appearance` object, for example `{"wordmark":"ClassCheck","logo":"classcheck"}`. An operator can supply a parent appearance as a JSON-encoded string in the Worker's `NATHAN_APPEARANCE` variable.

When upgrading an earlier hosted draft, apply the migrations before switching the issuer to the new Worker. Outstanding proofs retain their original storage identifiers. The database ignores delayed sends from an older Worker once the new Worker has published a credential for that address.

To roll back to an earlier draft, pause new email requests and keep verification available through the five-minute lifetime of the last issued proof. Drain pending promotion logouts with the current Worker's scheduled handler before switching traffic. Confirm that `SELECT count(*) FROM nathan_backchannel_deliveries WHERE reason='email-otp-promotion' AND state='pending'` returns zero. Older Workers interpret every queued logout as subject-wide. After switching Workers, resume email requests.

The email logo uses the validated logo ID to select an operator-installed, sanitized PNG from `NATHAN_EMAIL_LOGOS`, a JSON-encoded string mapping IDs to base64 PNG content. Nathan attaches it inline. A missing logo leaves the name in the text and HTML. The From address remains the instance's verified sender.

For an access token addressed to an explicitly registered and linked API resource, request its `resource` at authorization and token exchange. Its JWT carries `nathan_amr: ["email"]` for the live email session. Verify the ID token signature, issuer, client audience and nonce. With the `email` scope, fetch the discovered UserInfo endpoint with the access token and require its `sub` to match the ID token before reading `email` and `email_verified`. An access token issued without a resource may be opaque. Application grants, native callbacks and ClassCheck provisioning have their own contracts.
