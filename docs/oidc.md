# Nathan as an OIDC identity provider

Nathan's Better Auth OAuth Provider issues tokens and owns discovery, client registration, JWKS, refresh and revocation. Clients can be in the same account or on any other hosting provider.

- Worker with service binding: session verification via private RPC; OIDC client optional.
- Worker or external web app: confidential OIDC client using authorization code + PKCE.
- Mobile app: public OIDC client with PKCE, claimed HTTPS or loopback redirects.
- CLI: device authorization where enabled.
- Machine: client credentials with explicit scopes and audience; never confuse a machine principal with a user.

Client secrets are displayed once. Callback URIs must be exact, HTTPS except explicitly permitted native loopback forms. JWTs are resource-bound and validated for issuer, audience, signature, and required scope.

**Assurance limitation:** Better Auth's OAuth Provider currently advertises ACR `0` by default. Nathan must not invent an AAL2 claim because a TOTP or passkey plugin was enabled. High-assurance gateway requests fail closed until real assurance claims are verified.

**Logout:** Gateway code verifies signed OIDC back-channel Logout Tokens and deletes sessions by `sid` or subject. Client registration must enable `backchannel_logout_uri` for the gateway to receive them.

## Domain-wide relying parties

Use one issuer `https://login.example.com/api/auth` for `example.com` and all approved subdomains. Each client must register its own **exact HTTPS callback**, and its authorization is not inherited from the domain or from another RP. See [domain-wide-sso.md](domain-wide-sso.md) and the Identity Studio realm tab. Never use wildcard redirect URLs or a shared `.example.com` session cookie.
