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

## Release verification

Run OWASP ASVS Level 2-aligned review, protocol conformance testing, penetration testing, Cloudflare runtime tests, concurrency/transaction tests for D1, dependency/SBOM scanning, external IdP callback tests, and disaster recovery drills. A self-hosted deployment does not automatically satisfy SOC 2, HIPAA, ISO 27001, FAPI or FedRAMP.
