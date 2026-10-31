# Nathan contributor and coding-agent guidance

Nathan is a **security-sensitive identity provider**. Never claim a change is production-ready solely because TypeScript compiles or basic tests pass.

## Architecture

- \`src/auth/\`: Better Auth (OIDC issuer), admin API, Identity Studio, session enforcement, verified admin MCP.
- \`src/gateway/\`: private origin gateway, OIDC PKCE and D1 sessions.
- \`src/installer/\`: Cloudflare OAuth hosted wizard and resource provisioning.
- \`src/sdk/\`: local JWT verification for application APIs.
- \`scripts/\`: CLI setup, hosted installer bootstrap, release packaging.
- \`migrations/\`: Better Auth and custom D1 tables.
- \`plugins/catalog.json\`: **candidate** plugin catalog; not a security certification.

## Development

\`\`\`sh
npm ci
npm run schema:generate
npm test
npm run typecheck
npm run build:auth
npm run build:gateway
npm run pack:release
npm run verify:release
npm run build:installer
\`\`\`

Regenerate Better Auth schema only when plugin types/versions change; compare the generated SQL before committing. Do not edit the generated migration by hand without documenting why.

## Security invariants

- Validate redirect URIs exactly, prevent open redirects, require PKCE, verify JWKS signature, audience, issuer and nonce.
- Fail closed for unknown/disabled users and apps; admin identity needs current verified email, admin role and an explicit allowlist.
- Keep passwords, OAuth client secrets and access tokens out of logs, source and configuration files.
- Never enable public ingress for an upstream application protected by a gateway.
- Installers must not overwrite unrelated Workers, DNS records or D1 databases.
- Update installed Workers privately with secrets before attaching a public route.
- Don't mark any federated session AAL2 merely because MFA plugins are installed. Require proven authentication-method evidence.
- Every privileged operation needs audit; admin MCP writes are disabled by default.
- Treat community Better Auth plugins as trusted code inside the IdP runtime unless explicitly isolated.

## Release policy

Do not merge a PR as production-ready before staging OIDC flows, self-hosted installation and gateway bypass tests; use draft PRs until deployment verification and independent security review are complete.

## Domain-wide SSO rules

- New domains use one issuer `login.<apex>`, with an optional verified `realm.apex` and a Cloudflare account/zone ownership record.
- The apex and subdomains become OIDC **clients only by explicit admin registration**, disabled by default. Never auto-authorize based on suffix alone or wildcard redirect URIs.
- Do not set Better Auth cross-subdomain cookies. OIDC provides SSO without sharing cookie domains.
- Cloudflare Custom Domains are exact-hostname only; a wildcard Worker Route is an independent, potentially disruptive ingress change and must never be provisioned implicitly for domain-wide SSO.
- Protect non-OIDC apps through a verified private upstream gateway; DNS discovery is not proof of origin isolation.
