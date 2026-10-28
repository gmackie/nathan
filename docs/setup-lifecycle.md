# Nathan setup lifecycle: initial administrator, OAuth, enterprise SSO, SCIM and MFA

Nathan has one customer-owned identity runtime and one control plane. The **Cloudflare installer wizard** creates the first safe configuration; **Identity Studio** manages the same configuration after the initial bootstrap.

> **Security status:** The source, schema, unit tests and Worker dry-run bundles are implemented. Cloudflare OAuth, SCIM, SAML and WebAuthn protocol flows still require full real-account integration testing before production deployment.

## 1. Create the initial identity authority

The installer connects to a Cloudflare account with authorization-code + PKCE, chooses a managed DNS zone and a unique IdP hostname (recommended \`login.example.com\`), and checks Worker/database/domain conflicts.

The installer identity is the **root bootstrap authority**. The initial admin email must match its verified Cloudflare OAuth account email. There is no public "first visitor becomes admin" endpoint, default password or invitation link.

The wizard collects Google or GitHub OAuth credentials, creating exact \`https://login.example.com/api/auth/callback/google\` or \`/github\` callback instructions. The first provider credentials are encrypted using AES-256-GCM in the customer's D1 database; \`NATHAN_CONFIG_KEY\` is generated and stored as a Worker secret. It is not written to the installer database or a source file.

The optional selections at initial install:
- **Domain-wide SSO:** one OIDC issuer for the root and approved subdomains.
- **Enterprise SSO:** compile the SSO plugin; configure OIDC providers and DNS verification in Studio after bootstrap.
- **SCIM directory:** optionally create a disabled transactional directory-only connection with a one-time bearer token.
- **MFA profile:** Standard or Business. Business requires initial admin to enroll passkey and verified TOTP, plus recent passkey sign-in for privileged admin use. Federated AAL2/AAL3 assertion enforcement remains disabled until validated.

The Worker is uploaded privately and starts with an inactive flag. The installer applies migrations, installs secrets, disables workers.dev/preview ingress, attaches the exact custom domain, activates the IdP, and checks discovery/JWKS.

## 2. Claim the initial administrator safely

The installer writes \`nathan_bootstrap_status\` with the Cloudflare account's user ID and approved email. After deploying, the intended administrator:

1. Signs into Nathan using the configured Google/GitHub upstream provider (or a supported enterprise IdP once verified).
2. Completes verified email authentication using **exactly the Cloudflare-verified bootstrap email**.
3. Returns to the wizard. It checks the verified Better Auth user, binds its stable user ID to the original Cloudflare installer identity, and promotes only that account to the initial admin role.
4. Opens \`https://login.example.com/security?setup=admin\`, enrolls a passkey and TOTP authenticator, saves backup codes privately, and confirms setup. For Standard, one enrolled method is acceptable; Business requires both.
5. In Business, performs a **fresh passkey sign-in** before accessing privileged Identity Studio operations. Nathan records that signed-in session's successful passkey ceremony for a 15-minute window. Merely having a registered passkey or TOTP secret does not count as session assurance.
6. Returns to the installer. It will not complete until the server-side bootstrap state says complete.

Cloudflare identity verification, verified user identity, recorded bootstrap state and secure authenticator enrollment are independent controls.

**Important:** This product-specific recent passkey control does not automatically establish NIST AAL2 or AAL3, especially for users originally authenticated through upstream federation. Nathan must not issue elevated \`acr\` claims without verified evidence.

## 3. Identity Studio once deployed

Visit \`https://login.example.com/studio\` as a fully enrolled administrator. Settings are **real backend operations**, not decorative toggles.

| Feature | Wizard | Identity Studio |
| --- | --- | --- |
| Cloudflare account and DNS discovery | Yes | Read-only realm inventory after setup |
| IdP hostname, Worker and D1 provisioning | Yes | Deployment CLI / reviewed infrastructure change |
| Initial administrator | Cloudflare owner and verified account | See bootstrap status; add/revoke additional verified admins |
| Google/GitHub OAuth | Setup guides; encrypted first provider | Add/rotate/enable/disable, encrypted runtime configuration |
| OIDC provider and RP clients | Enabled with initial Worker | Register individual external/Worker/gateway clients, including reviewed subdomain batches |
| Enterprise OIDC federation | SSO plugin opt-in | Register provider, obtain DNS TXT challenge, verify domain before login |
| Enterprise SAML federation | Plugin option | Metadata/SP certificate admin interface pending validation |
| SCIM directory | Optional disabled initial directory connection | Create, list, enable/disable and rotate bearer token |
| Passkeys / TOTP | Enrollment required to complete initial admin | Self-service enrollment, authenticator inspection and passkey reauthentication |
| MFA posture | Standard or Business profile | View effective policy and *increase* admin requirements without redeploying |
| Additional administrators | Not during initial install | Grant an existing verified user and revoke additional admins with session termination |
| Plugin code changes | Pinned Worker release | Requires reviewed build/deploy, not hot-loaded arbitrary JavaScript |

### OAuth providers and encryption

Social credentials are encrypted in \`nathan_oauth_providers\`. Once there is a database record, it takes precedence over older Worker secrets. Disabling a provider must not silently fall back to its old credentials. A server-side check prevents disabling the last configured sign-in path unless another fallback exists.

\`NATHAN_CONFIG_KEY\` is held in Cloudflare Workers Secrets; losing it renders managed provider credentials undecryptable. Operators must back up the key in a separate secure secrets manager and rotate credentials deliberately. Encryption at rest does not eliminate the need for access controls, database backups, key rotation, and incident handling.

### Enterprise OIDC federation

A registered enterprise provider starts **untrusted**. Better Auth's SSO plugin requires proving ownership of the claimed domain through a TXT record, such as \`_better-auth-token-acme-entra.acme.example\`. Nathan displays the actual provider-generated token, never invents one. Identity Studio calls the domain-verification endpoint only for a verified and currently authorized administrator.

Direct Better Auth SSO management HTTP endpoints are blocked; only authenticated Studio management APIs may register, update, or verify enterprise providers. SAML import, SP key custody and assertion signature handling are not yet claimed as a completed UI workflow.

### SCIM 2.0

SCIM is not the same as SSO. It provisions directory identities and group data, whereas OIDC/SAML authenticate users.

Nathan stores SCIM connection metadata and **one-way SHA-256 hashes** of its high-entropy bearer tokens in D1. The directory itself uses one SQLite-backed Durable Object per connection with atomic transactions. Its endpoints are \`/scim/v2/<connectionId>/Users\` and \`/Groups\`; each connection has a scoped, independently revocable token.

The initial SCIM implementation is deliberately **directory-only**, with users and groups staged transactionally. It does **not** create Better Auth user accounts, implicitly link accounts by email, assign admin rights, deprovision sessions, or satisfy a production directory-lifecycle requirement. Before a connected organization uses SCIM for access control, we must design and test immutable external ID mapping, fail-closed deprovisioning, reconciliation, replay and event delivery.

Better Auth's official SCIM plugin depends on interactive transaction features unavailable on D1; Nathan therefore uses its own outpost storage boundary. Do not enable the official D1-backed plugin as though it were equivalent.

### Additional administrators

The root owner comes from Cloudflare-authorized bootstrap. Additional admins must first sign in and verify their email, then be explicitly approved in Studio by an already-enrolled admin performing a recent passkey step-up. The grant records the exact Better Auth user ID and verified email. Revoking a grant removes access and invalidates Better Auth sessions. The bootstrap root cannot be revoked by a normal Studio endpoint.

### Authentication policy

The wizard selects Standard or Business. Studio can tighten its effective policy from Standard, such as requiring both enrolled authenticators or a recent passkey for privileged management. A routine web toggle cannot lower a deployment's hard security floor. OAuth redirect validation, cookie protections, MFA proof verification and default-deny authorization are never tradeable convenience features.

## 4. Recovery, upgrades and key custody

**No unauthenticated HTTP break-glass backdoor.** If the only administrator is locked out, recovery belongs to an authorized Cloudflare account operator with audited D1/Workers access and a documented change procedure. Do not simply set \`emailVerified\` or update an OAuth redirect URI to take over an account.

Before upgrades, back up D1, Worker secrets (through a proper secret-management escrow), compiled release manifest and DNS/route plans. Migrations are pinned and hash-checked. Test key rotation without dropping existing JWKS signing keys prematurely.

## 5. Validation before production

See [staging-checklist.md](staging-checklist.md). Integration tests must cover:
- Cloudflare OAuth identity → Better Auth verified user → secure bootstrap → MFA enrollment → recent passkey reauthentication.
- Wrong Cloudflare owner, email mismatch, replayed installer job, forged session cookie and MFA-bypass attempts.
- Google/GitHub setup and rotation from both wizard and Studio without leaking client secrets.
- Enterprise OIDC registration, TXT ownership verification, untrusted-provider rejection and account-linking safety.
- SCIM group/user CRUD, duplicate externalId rejection, disabled connection, token rotation/revocation, PATCH and concurrency, with no automatic auth access.
- Added admin grant and revocation, including online authorization checks and expired bearer tokens.
- Live Cloudflare D1, Workers and SQLite Durable Object behavior, recovery drills and independent protocol review.

Only a staging test with a real Cloudflare account can validate the end-to-end deployment and OAuth callback behavior. A green CI build alone is not evidence of production IAM safety.
