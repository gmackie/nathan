# Roadmap

## 0. Bootstrap (this branch)

- [x] Repository overview, security boundaries and architecture docs
- [x] Read-only local configuration validator and plan command
- [x] Tests for validation and no-side-effects planner
- [ ] Reproduce original naming image as a repository-hosted binary
- [ ] Choose license and contribution guidelines

## 1. Working identity core

- [ ] Better Auth Worker + D1 adapter with reproducible migrations
- [ ] Provider setup for Google/GitHub with masked secret provisioning
- [ ] OIDC provider (authorization code + PKCE, discovery, JWKS, refresh and revocation)
- [ ] Passkey/TOTP enrollment and application-specific MFA enforcement
- [ ] End-to-end tests on local workerd and Cloudflare staging

## 2. Developer integrations

- [ ] Gateway Worker, host-only sessions, authenticated reverse proxy and unbypassable upstream
- [ ] Named WorkerEntrypoint verifier and Hono/Workers/Effect guard
- [ ] Application registry for external OIDC and Worker clients
- [ ] `nathan doctor`: live provider/redirect/key/session integration diagnostics

## 3. One-click install

- [ ] Cloudflare OAuth installer with PKCE and least-privilege scopes
- [ ] Account/zone/Worker hostname discovery and DNS conflict check
- [ ] Idempotent resources and package release manifest with integrity verification
- [ ] Resume/rollback and explicit deployment plan before mutation
- [ ] Secure OAuth client ID/secret collection and provider-specific guides
- [ ] Hosted Identity Studio and account recovery workflow

## 4. Extensions and advanced assurances

- [ ] Better Auth plugin manifests, compatibility review and schema migration planner
- [ ] Enterprise OIDC/SAML federation, JIT provisioning and SCIM
- [ ] Policy engine, claims mapping, audit export and high-assurance signing
- [ ] Optional non-HTTP outposts and private origin access
