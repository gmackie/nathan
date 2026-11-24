# Nathan as an OIDC identity provider

Run one Nathan identity Worker and D1 database for all the applications that trust the same issuer. Each relying party (RP) gets its own registration and application session. An RP can run in a different Cloudflare account or on another hosting provider. Start with the [IdP deployment guide](deploy.md).

## Connect two web applications

1. In the issuer's Kumo Identity Studio, open **Applications → Register OIDC client**. Register each web app separately. For example, Books registers `https://books.example.com/auth/callback` and Courses registers `https://courses.example.org/oidc/callback`. Use the exact HTTPS callback your framework implements.
2. Copy each registration's client ID and one-time client secret into that app's server-side secret store. A confidential web app uses `client_secret_basic`. For a client that cannot hold a secret, select **Public OIDC client (PKCE, no secret)**. Studio accepts exact HTTPS callbacks for these clients as well.
3. Configure both apps with the same **issuer**, for example `https://login.example.com/api/auth`. For libraries that require an explicit discovery URL, use `https://login.example.com/api/auth/.well-known/openid-configuration`. Read `authorization_endpoint`, `token_endpoint` and `jwks_uri` from the document and verify its `issuer` matches the configured value exactly.
4. Start an authorization-code flow with `response_type=code`, scopes `openid profile email`, the RP's client ID and its registered `redirect_uri`. Generate fresh `state`, `nonce` and a PKCE verifier for each attempt. Store them in the RP's short-lived login transaction. Send the verifier's SHA-256 challenge with `code_challenge_method=S256`.
5. At the RP's callback, validate the response issuer and state against that transaction. Exchange the code with the same redirect URI, the original verifier and the RP's own client credentials. Use an OIDC library to verify the ID token signature against the discovered JWKS and check its issuer, audience (this RP's client ID), expiry and nonce. Establish the app's own host-only session using the verified subject.

The first application takes the user through Nathan sign-in and consent. When the same browser opens the second application, Nathan can reuse the issuer session. The second application requests its own consent and receives an ID token with its own audience. An RP can request `prompt=none` to check silently and handle `login_required` or `consent_required` by starting an interactive flow.

For managed hosts in a verified realm, register the RP under **Protected apps and domains → Domain-wide SSO**. Realm clients start disabled. Configure each RP, then enable its registration in **Applications** before testing sign-in. [Domain-wide SSO](domain-wide-sso.md)

Mobile apps can register a claimed HTTPS callback and use a public client with PKCE. Command-line clients can use device authorization where enabled. A Worker with a Nathan service binding can verify a session through private RPC. Machine clients use the client-credentials grant with explicit scopes and an API audience.

## API access and logout

**Access tokens (NATH-15):** a token request that names a configured RFC 8707 `resource` gets an RFC 9068 JWT (`typ: at+jwt`) with `principal_kind` (`user`, `machine` or `agent`). Otherwise the token is opaque. No access token lives longer than 900 s, so use refresh tokens (`offline_access`) for long sessions. A refresh for a registered audience works only while the user's sign-in session is live (signing out, session expiry and bans end it with `invalid_grant`), except for clients marked `agent`. Name the scopes you need: `nathan:api` is refused to clients not marked `agent`, and so is an authorization request without `scope` when the default would include it. Register APIs and Gatekeeper as token audiences in Identity Studio. See [gatekeeper.md](gatekeeper.md) for the claims, the evidence-only `nathan_amr`/`nathan_acr` claims and the Gatekeeper provider entry.

**Assurance limitation:** Better Auth's OAuth Provider currently advertises ACR `0` by default. Nathan must not invent an AAL2 claim because a TOTP or passkey plugin was enabled. High-assurance gateway requests fail closed until real assurance claims are verified.

**Logout:** Gateway code verifies signed OIDC back-channel Logout Tokens and deletes sessions by `sid` or subject. Client registration must enable `backchannel_logout_uri` for the gateway to receive them.
