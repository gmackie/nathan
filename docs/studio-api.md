# Identity Studio JSON API v1

`/studio/api/v1/*` is the typed management API behind Identity Studio (NATH-24). The Kumo Studio SPA
(NATH-26), Cloudflare Access admin mode (NATH-25) and parent-to-child fleet management (NATH-27) all
build on it. It adds no new capability: every route calls the same service function as the legacy
`/studio/api/*` route it mirrors, so behaviour and audit records are unchanged. The legacy routes
and the server-rendered Studio keep working.

Code: `src/auth/studio-api/` (router, `authorizeStudioRequest`, one module per area).
Schemas: `src/auth/studio-api/schemas.ts` (imports only zod, shared with the SPA).

## Envelope

Success:

```json
{ "ok": true, "data": { "...": "the legacy route's JSON body, unchanged" } }
```

Failure:

```json
{ "ok": false, "error": { "code": "validation_failed", "message": "…", "issues": [{ "path": "kind", "code": "invalid_value", "message": "…" }] } }
```

Every response has `Cache-Control: no-store`. Messages are safe to show and never echo submitted
values. `issues` appears only with `validation_failed`.

## Authorization

Every route goes through `authorizeStudioRequest(request, env, auth, { action, write, stepUp })`:

1. Writes (POST) only: `Origin` must equal the issuer origin and `Sec-Fetch-Site` must not be
   `cross-site` (`cross_origin`), and `Content-Type` must be `application/json` (`unsupported_media_type`).
2. A Nathan session is required (`unauthenticated`).
3. The user must be a verified, explicitly granted administrator: the completed bootstrap owner or
   an enabled `nathan_admin_grants` row, verified email, `admin` role and `NATHAN_ADMIN_EMAILS`
   (`not_admin`).
4. Admin assurance (`stepUp: "admin-policy"`, every route): completed bootstrap and enrolled
   authenticators (`enrollment_incomplete`) and, when the policy requires it, a passkey verification
   of this session in the last 15 minutes (`step_up_required`).

These are the legacy checks (`isAdminPrincipal` + `mayAdminister`). The principal is a
discriminated union, `{ kind: "nathan-admin", userId, email, sessionId }` today. NATH-25 (Access) and
NATH-27 (fleet token) add kinds in `authorize.ts`. The audit actor is the administrator's user id.

## Validation and audit

The order is: route, then authorization, then body byte limit (`payload_too_large`), then JSON
(`invalid_json`), then schema and service.

The schema is the contract, and the service stays the authority. A write that fails the schema
still goes to the service, so refused attempts are audited exactly as before: RBAC, admission,
providers, SCIM, directory clients and the SAML IdP audit refused input. The response is then
`400 validation_failed` with the schema issues. If a service ever accepts input the schema refused,
the API returns the result as the legacy route would and logs `studio_api_schema_drift <action>`
(no input). Nothing reaches a service before authorization succeeds.

## Error codes

| Code | Status | Meaning |
| --- | --- | --- |
| `unauthenticated` | 401 | No Nathan session |
| `cross_origin` | 403 | Write without same-origin `Origin`, or `Sec-Fetch-Site: cross-site` |
| `not_admin` | 403 | Signed in, but not a verified, granted administrator |
| `enrollment_incomplete` | 403 | Admin bootstrap or authenticator enrollment incomplete |
| `step_up_required` | 403 | Recent passkey verification required by the admin policy |
| `unsupported_media_type` | 415 | Write without `Content-Type: application/json` |
| `payload_too_large` | 413 | Body over the route's limit |
| `invalid_json` | 400 | Body is not JSON |
| `validation_failed` | 400 | Input does not match the schema (`issues`), or a service input check (client status, app confirmation, SCIM review filter) |
| `not_found` | 404 | Unknown route, or unknown application/group/SCIM connection on a read |
| `method_not_allowed` | 405 | Known route, other method (`Allow` header) |
| `operation_rejected` | 409 | The service refused the change (its safe message) |
| `unavailable` | 503 | Feature not configured (domain realm) |

## Endpoints

All paths are below `/studio/api/v1`. Bodies are JSON. Limits are the legacy route's limits.

| Method | Path | Action | Schema | Limit | Service |
| --- | --- | --- | --- | --- | --- |
| GET | `/status` | status.read | — | | `studioStatus` |
| GET | `/plugins` | plugins.read | — | | plugin catalog (candidates) |
| GET | `/bootstrap` | bootstrap.read | — | | `bootstrapStatus` (the administrator's own setup state; NATH-39) |
| GET | `/audit` | audit.read | — | | `recentAudit` (latest 75) |
| GET | `/users` | users.read | — | | `listUsers` |
| GET | `/admins` | admins.read | — | | `listAdminGrants` |
| POST | `/admins/grant` | admins.grant | `adminGrantInput` | 4 KB | `grantAdmin` |
| POST | `/admins/revoke` | admins.revoke | `adminRevokeInput` | 4 KB | `revokeAdminGrant` |
| GET | `/clients` | clients.read | — | | `listClients` |
| POST | `/clients` | clients.create | `clientCreateInput` | 8 KB | `createOAuthClient` |
| POST | `/clients/status` | clients.status | `clientStatusInput` | 4 KB | `setOAuthClientStatus` |
| GET | `/apps` | apps.read | — | | `listApplications` |
| POST | `/apps` | apps.upsert | `applicationUpsertInput` | 16 KB | `upsertApplication` |
| POST | `/apps/status` | apps.status | `applicationStatusInput` | 16 KB | `setApplicationStatus` |
| GET | `/realm` | realm.read | — | | `loadVerifiedRealm` |
| GET | `/realm/clients` | realm.clients.read | — | | `listRealmClients` |
| POST | `/realm/clients` | realm.clients.create | `realmClientInput` | 8 KB | `registerRealmClient` |
| POST | `/realm/clients/batch` | realm.clients.batch | `realmClientBatchInput` | 8 KB | `registerRealmClientsBatch` |
| GET | `/providers` | providers.read | — | | `providerStatus` |
| POST | `/providers` | providers.upsert | `providerUpsertInput` | 16 KB | `upsertSocialProvider` |
| POST | `/providers/status` | providers.status | `providerStatusInput` | 16 KB | `setSocialProviderEnabled` |
| POST | `/providers/test` | providers.test | `providerTestInput` | 16 KB | `beginProviderTest` |
| GET | `/sso` | sso.read | — | | `listSso` |
| POST | `/sso/oidc` | sso.oidc.register | `ssoOidcRegisterInput` | 16 KB | `registerEnterpriseOidc` |
| POST | `/sso/token` | sso.domain.token | `ssoDomainInput` | 16 KB | `requestEnterpriseVerification` |
| POST | `/sso/verify` | sso.domain.verify | `ssoDomainInput` | 16 KB | `verifyEnterpriseDomain` |
| GET | `/saml` | saml.read | — | | `listSamlConnections` |
| POST | `/saml/preview` | saml.preview | `samlPreviewInput` | 160 KB | `previewSamlMetadata` |
| POST | `/saml/connections` | saml.connections.create | `samlConnectionCreateInput` | 160 KB | `createSamlConnection` |
| POST | `/saml/status` | saml.status | `samlStatusInput` | 160 KB | `setSamlConnectionEnabled` |
| POST | `/saml/provisioning` | saml.provisioning | `samlProvisioningInput` | 160 KB | `setSamlProvisioning` |
| POST | `/saml/certificates` | saml.certificates.add | `samlCertificateAddInput` | 160 KB | `addSamlCertificate` |
| POST | `/saml/certificates/retire` | saml.certificates.retire | `samlCertificateRetireInput` | 160 KB | `retireSamlCertificate` |
| GET | `/saml-idp` | saml-idp.read | — | | `samlIdpOverview` |
| POST | `/saml-idp` | saml-idp.apply | `samlIdpInput` (`op`) | 160 KB | `applySamlIdpOperation` |
| GET | `/scim/connections` | scim.connections.read | — | | `listScimConnections` |
| POST | `/scim/connections` | scim.connections.create | `scimConnectionCreateInput` | 16 KB | `createScimConnection` |
| POST | `/scim/status` | scim.status | `scimStatusInput` | 16 KB | `setScimConnectionEnabled` |
| POST | `/scim/rotate` | scim.rotate | `scimRotateInput` | 16 KB | `rotateScimToken` |
| GET | `/scim/connection?id=&reviewState=&reviewOffset=` | scim.connection.read | `scimConnectionQuery` | | `scimConnectionView` |
| POST | `/scim/settings` | scim.settings | `scimSettingsInput` | 4 KB | `updateScimSettings` |
| POST | `/scim/mappings` | scim.mappings | `scimMappingInput` (`op`) | 4 KB | `changeScimMapping` |
| GET | `/scim/outbox?id=` | scim.outbox.read | `scimOutboxQuery` | | `scimOutboxView` |
| POST | `/scim/outbox` | scim.outbox.skip | `scimOutboxInput` | 4 KB | `skipScimOutbox` |
| POST | `/scim/users` | scim.users.apply | `scimUserInput` (`op`) | 4 KB | `scimUserOperation` |
| GET | `/rbac?app=` | rbac.read | `rbacQuery` | | `rbacOverview` |
| GET | `/rbac/groups` | rbac.groups.read | — | | `listGroups` |
| GET | `/rbac/group?id=` | rbac.group.read | `rbacGroupQuery` | | `groupMembers` |
| POST | `/rbac` | rbac.apply | `rbacInput` (`op`) | 64 KB | `applyRbacOperation` |
| POST | `/directory/clients` | directory.clients.create | `directoryClientInput` | 64 KB | `createDirectoryClient` |
| GET | `/tokens` | tokens.read | — | | `tokenOverview` |
| POST | `/tokens` | tokens.apply | `tokenInput` (`op`) | 8 KB | `applyTokenOperation` |
| GET | `/mcp` | mcp.read | — | | `mcpOverview` |
| POST | `/mcp` | mcp.apply | `mcpInput` (`op`) | 64 KB | `applyMcpOperation` |
| GET | `/admission` | admission.read | — | | `admissionOverview` |
| POST | `/admission` | admission.apply | `admissionInput` (`op`) | 4 KB | `applyAdmissionOperation` |
| GET | `/security-policy` | security-policy.read | — | | `effectiveAdminPolicy` |
| POST | `/security-policy/tighten` | security-policy.tighten | `securityPolicyTightenInput` | 2 KB | `tightenAdminPolicy` |

Typed confirmation strings (`confirm`) are unchanged; see each service for the exact text. Not in
this API: the bootstrap endpoints under `/security/api/*` (the account page's setup flow, which
must work before someone is an administrator; `GET /bootstrap` above is the read-only admin view of
the same state) and the provider test landing page `/studio/providers/test-complete`, which are not
admin management actions.

The Identity Studio SPA (NATH-39, `src/ui/pages/studio/`) uses only this API.

## Differences from the legacy routes

- One envelope and stable error codes. Legacy routes return `{ error }` with route-specific
  statuses, and v1 uses the codes above. Service refusals are always 409 in v1, where some legacy
  routes used 400.
- Anonymous requests get 401 (legacy: 403).
- RBAC `grant.revoke` requires the selected application ID in `app` and the grant ID in `id`. The grant must belong to that application.
- Body limits count bytes and are enforced while reading (`readBoundedText`). Legacy routes count
  characters after reading.
