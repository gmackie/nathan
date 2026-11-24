# Nathan as an OIDC identity provider

Nathan's Better Auth OAuth Provider issues tokens and owns discovery, client registration, JWKS, refresh and revocation. Clients can be in the same account or on any other hosting provider.

- Worker with service binding: session verification via private RPC; OIDC client optional.
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

One Resend message contains a six-digit code and a link to the issuer. Both redeem the same five-minute credential. Open the link in the requesting browser. When reading mail on another device, enter the code in the original tab. A link preview cannot consume the credential. A new delivery for the same address supersedes the earlier one. Each challenge allows five attempts. Fixed ten-minute windows allow three sends per normalized address, twenty sends per source IP and forty verification requests per IP. Requests show the same acknowledgment for ineligible addresses, delivery failures and throttled sends.

A verified account, an active SCIM-provisioned account, or the holder of an open invitation can use email. New accounts need that specific invitation even on a self-service instance. Nathan rechecks eligibility at redemption, honors enrolled TOTP, and grants ordinary OIDC authentication. An email session carries no admin step-up. An administrator must use an existing authenticator before managing credentials and a fresh passkey wherever privileged step-up is required.

### Sender and client branding

Configure `RESEND_API_KEY` and `EMAIL_FROM` on the identity Worker and apply migration `0019_email_sign_in.sql`. The hosted option appears when both sender settings are present. The signed OIDC client selects the registered name and its validated `appearance` metadata. The protected `POST /studio/api/clients` registration accepts an optional `appearance` object, for example `{"wordmark":"ClassCheck","logo":"classcheck"}`. An operator can supply a parent appearance as a JSON-encoded string in the Worker's `NATHAN_APPEARANCE` variable.

The email logo uses the validated logo ID to select an operator-installed, sanitized PNG from `NATHAN_EMAIL_LOGOS`, a JSON-encoded string mapping IDs to base64 PNG content. Nathan attaches it inline. A missing logo leaves the name in the text and HTML. The From address remains the instance's verified sender.

For an access token addressed to an explicitly registered and linked API resource, request its `resource` at authorization and token exchange. Its JWT carries `nathan_amr: ["email"]` for the live email session. A web client requesting only OIDC scopes can rely on its verified ID token. An access token issued without a resource may be opaque. Application grants, native callbacks and ClassCheck provisioning have their own contracts.
