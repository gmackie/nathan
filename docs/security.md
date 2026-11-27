# Nathan security requirements

> The current bootstrap is **not a production-ready IdP**. Do not rely on it to secure sensitive applications.

## Minimum release gates

- OAuth 2.0 Security BCP (RFC 9700), OpenID Connect Core, JWT BCP (RFC 8725), PKCE, exact redirect URI matching, audience/issuer checks, replay-resistant state/nonce, robust refresh-token rotation.
- Bind OAuth clients to the correct application identity; reject client-supplied application IDs as trust assertions.
- Default-deny policies. Gateway's upstream must be private, including preview and workers.dev routes. Strip untrusted identity headers.
- Secure `HttpOnly`, `Secure`, host-only cookies, CSRF defenses, logout and recovery testing.
- Distinguish verified assurance `acr`, `amr`, `auth_time` from upstream claims. Never imply passkey == AAL3.
- Protect signing keys, provider credentials, backups and administrative APIs; rotate keys safely; log security-sensitive actions without secrets or tokens.
- Make plugin trust explicit: verified, community, and custom; untrusted extension code must not execute inside privileged core without review.
- Rate limiting, anti-enumeration, anti-stuffing, phishing-resistant MFA options, hardened recovery, threat modeling and incident handling.

## Security profiles

Profiles adjust authentication friction and assurance (consumer, business, high assurance) but never disable protocol validation or default-deny authorization. Compliance overlays are deployment obligations, not certifications.

## Shared issuer with an Access-protected Studio

Set `NATHAN_ADMIN_ORIGIN` to the exact HTTPS origin `https://admin.<issuer-host>`. The Worker serves Studio and its APIs there. The public issuer continues to serve discovery, JWKS, application sign-in and account pages. Register any social sign-in callback used by operators on the admin hostname with the upstream provider as well. The WebAuthn relying-party ID stays on the issuer hostname so enrolled passkeys work on both origins. Session cookies are host-only.

Configure the Access team domain and application audience in `NATHAN_ACCESS_TEAM_DOMAIN` and `NATHAN_ACCESS_AUD`. Keep `NATHAN_CONFIG_KEY`, `NATHAN_BOOTSTRAP_REQUIRED=true` and `NATHAN_ADMIN_STEPUP_REQUIRED=true` in place. Studio verifies the signed app assertion on every administrator-host request, including assets. Its management cookies are bound to the Access principal. An operator needs an email in `NATHAN_ADMIN_EMAILS`, a matching verified local administrator, and the current Nathan session assurance required for Studio. Enroll or grant that local account before moving Studio. Retain an independently recoverable installation owner.

Before enabling the hostname, verify the exact self-hosted Access application, the assigned external IdP, an allow policy restricted to the intended administrators and independent MFA on that application. The Worker verifies the audience and relies on the policy attached to that audience for external MFA. Apply the private Worker update before attaching the exact custom domain. Confirm a fresh administrative sign-in there and an application OIDC round trip on the public issuer.

## Release verification

Run OWASP ASVS Level 2-aligned review, protocol conformance testing, penetration testing, Cloudflare runtime tests, concurrency/transaction tests for D1, dependency/SBOM scanning, external IdP callback tests, and disaster recovery drills. A self-hosted deployment does not automatically satisfy SOC 2, HIPAA, ISO 27001, FAPI or FedRAMP.
