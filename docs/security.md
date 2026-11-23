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

## Account-token administration

Approved by the owner on 2026-11-23. An operator holding a Cloudflare API token with D1 edit on the Nathan account can, from `scripts/nathan.mjs`, enable or disable an application (`app enable|disable`), grant or revoke an application role (`rbac grant|revoke`), register an MCP server or change its status (`mcp register|status`), and look up a user id by email (`user find`, read-only). In Identity Studio each of these needs a verified, allowlisted administrator with enrolled authenticators and a recent passkey step-up. **The CLI path needs none of that: any holder of such a token skips the step-up.**

The trade-off: a holder of that token can already write these D1 tables directly (for example with `wrangler d1 execute`), so these commands do not add a capability. They make the path validated and audited instead of ad hoc SQL:

- One implementation: the CLI runs the Studio operations' own validation and statements (`src/shared/admin-ops.mjs`), so it cannot accept an identifier, audience, catalog, app, role or principal that Studio would refuse.
- Plan by default; `--apply` plus an interactive confirmation (the typed Studio confirmation strings for enabling or disabling apps and MCP servers). No secret is accepted as a flag; the token comes from `CLOUDFLARE_API_TOKEN`.
- Audit as `cli:<accountId>`: an `attempted` row, then the change, its change-feed row and Studio's `succeeded` row in one D1 batch, or `failed`; RBAC grant refusals are audited `rejected`, like Studio.
- Per-application manifests (`app apply`) run the same operations in sequence and add one `app_manifest_apply` audit row around them; they never contain grants.
- Not covered: Nathan administrator grants, OAuth client creation, MCP server removal and MCP grant revocation remain Studio-only.

Treat a Cloudflare token with D1 edit on the Nathan account as an administrator credential: scope it to that account, keep it in a secret manager, and review `cli:` rows in `nathan_security_audit`. Audit rows are written by the same token holder and are not tamper-evident (threat model T18).

## Security profiles

Profiles adjust authentication friction and assurance (consumer, business, high assurance) but never disable protocol validation or default-deny authorization. Compliance overlays are deployment obligations, not certifications.

## Release verification

Run OWASP ASVS Level 2-aligned review, protocol conformance testing, penetration testing, Cloudflare runtime tests, concurrency/transaction tests for D1, dependency/SBOM scanning, external IdP callback tests, and disaster recovery drills. A self-hosted deployment does not automatically satisfy SOC 2, HIPAA, ISO 27001, FAPI or FedRAMP.
