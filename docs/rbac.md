# Roles and minimal RBAC

Nathan authenticates users and keeps a **minimal** role model: applications declare permission strings, roles bundle permissions, and roles are granted per application to users or groups. Nathan has no policy language, conditions, approvals or resource-level rules. Those belong to Gatekeeper, which reads roles from Nathan; Nathan is their source of truth.

Start with the [5-minute quickstart](quickstart-rbac.md).

## Model (migration `0011_rbac.sql`)

| Table | Holds |
| --- | --- |
| `nathan_applications.access_mode` | `approved` (default) or `any_signed_in` |
| `nathan_rbac_permissions` | per-app permission keys such as `invoices:write`, with a source (`studio`, `code`, `legacy`) |
| `nathan_rbac_roles`, `nathan_rbac_role_permissions` | per-app roles and the permissions they bundle |
| `nathan_groups`, `nathan_group_members` | Nathan groups of Better Auth users (`source` `scim`: membership maintained by an explicit SCIM group mapping, see [scim.md](scim.md)) |
| `nathan_rbac_grants` | `(app, role) → user or group` |
| `nathan_rbac_changes`, `nathan_rbac_feed_state` | ordered change feed and its pruning watermark |

Deleting a role deletes its grants. Deleting a permission removes it from roles. Deleting a group deletes its memberships and grants. Deleting a user deletes their memberships.

Better Auth's global `admin` role is now only for administering Nathan. It no longer grants access to applications.

### Legacy migration

Before NATH-13, `NathanVerifier.authorize()` compared the user's single global Better Auth role (`NULL` counts as `user`) with each app's `roles` list, and an empty list admitted every signed-in user. Migration 0011 keeps every one of those decisions:

- An empty list becomes `access_mode = any_signed_in`.
- Each listed role becomes an app role (source `legacy`) granted to a **snapshot** group `legacy-role-<role>`. The group holds the users who had that global role at migration time.
- Malformed lists grant nothing, as before.

After the migration, changing someone's global role no longer changes their application access. Review the `legacy-role-*` groups in Identity Studio. A `tests/rbac-migration.test.mjs` case checks that every existing (user, app) decision is unchanged. The legacy `roles` column is kept but no longer read.

## One evaluator

`src/shared/policy.mjs` `evaluateAccess({app, user, groups, grants, roles})` returns `{allowed, reason, roles, permissions}`. It is pure and is the only decision function. The gateway (through `NathanVerifier.resolveAccess`), the SDK's bearer-token path, `NathanVerifier.authorize/access` and the directory API all call it.

- Unknown app, unknown user, malformed input, disabled app or blocked user (`banned = 1`, even after `banExpires`, until Better Auth lifts the ban at sign-in): deny, with no roles.
- `approved`: allowed only with at least one grant to the user or one of their groups.
- `any_signed_in`: every active user is allowed; grants still add roles.

The SQL that feeds it lives in `src/shared/rbac-store.mjs`, shared by the Worker, the CLI and the SQLite tests.

## Gateway and the signed principal

After login, the gateway calls `NATHAN.resolveAccess({applicationId, subject})` over a service binding to the identity Worker's `NathanVerifier` entrypoint.

**The binding is app-scoped.** Every binding to `NathanVerifier` (gateway or API Worker) must pin the one application it may ask about, in the calling Worker's wrangler config:

```jsonc
"services": [{ "binding": "NATHAN", "service": "nathan-auth", "entrypoint": "NathanVerifier",
               "props": { "applicationId": "billing" } }]
```

The identity Worker reads the pin from `ctx.props`, which the caller's code cannot change at runtime. It answers `resolveAccess`, `access`, `authorize`, `getPrincipal` and the remote MCP grant check `mcpGrant` (NATH-14) only for that application. A request for another application gets `{allowed: false, reason: "application_mismatch"}` with no roles, permissions or email; a binding without a valid pin gets `reason: "binding_not_pinned"`. The gateway turns either reason into a 503, because it means the binding is misconfigured. `nathan protect` and the gateway template (`wrangler.gateway.jsonc`) set the pin to `APPLICATION_ID`. The directory is **not** reachable over this binding. It is served only by the authenticated directory API below, so a compromised or buggy app Worker cannot enumerate other users' groups, grants or the change feed.

**Cookie methods disclose nothing beyond the app's own decision (NATH-18).** Some Workers hold a Nathan session cookie. For them:

- `getPrincipal(cookie)` returns `{sub, email, applicationId, roles, permissions}` for the pinned application **only when the evaluator allows that user for it**, and `null` otherwise, including for an unknown or expired session. It never returns the user's global Better Auth role (`admin`/`user`): an app sees only its own roles and permissions.
- `access({cookie})` returns the decision, with `sub` only when it is allowed. `authorize({cookie})` returns the boolean.

Before NATH-18, `getPrincipal` returned the id, email and global role of anyone signed in to Nathan, to any app Worker holding their cookie. A Worker that needs a user's identity for an app it does not serve must not get it. Use the gateway, or `resolveAccess` with an OIDC subject. All of this is workerd-tested (`tests/runtime/binding-trust.test.mjs`).

**Only the identity Worker may bind the SCIM Durable Object.** `NathanScimDirectory` (binding `SCIM_DIRECTORY`) holds each connection's staged directory, its outbox and the administrator operations. Never bind its namespace from another Worker (a `durable_objects` binding with `script_name` pointing at the identity Worker). The object enforces this itself too: it serves only `fetch`, with no RPC methods, and refuses any request without the identity Worker's caller proof (403). See [scim.md](scim.md#trust-boundary).

**Why a service binding rather than a signed internal HTTP endpoint:** the gateway and the identity Worker are deployed to the same customer account. A binding exposes no public route, needs no extra shared secret or replay protection, and only Workers the account owner binds to it can call it. The cost is that a gateway in another Cloudflare account cannot resolve roles; such gateways are not supported.

Subjects are Nathan user ids. Gateway OIDC clients must use the default public subject type; a pairwise subject resolves to no user and is denied.

The decision is cached per gateway session in the isolate for `ACCESS_CACHE_TTL_SECONDS` (0–60, default 30). A revoked grant, blocked user or disabled app therefore takes effect within that window. When the evaluator denies, the gateway answers 403. If the binding is missing or not pinned to this application, the identity Worker's RPC throws, `NATHAN_PRINCIPAL_KEY` is missing or shorter than 32 bytes, or `ACCESS_CACHE_TTL_SECONDS` is outside 0–60, it answers 503 (fail closed). Each of these is workerd-tested.

The gateway strips every inbound `X-Nathan-*` header and adds `X-Nathan-Principal`, a compact JWS:

- header `{"alg":"HS256","typ":"nathan-principal+jwt"}`
- claims `iss` (gateway origin), `aud` and `app` (application id), `sub`, `email` (verified email or `null`), `roles`, `permissions`, `iat`, `exp`, with `exp − iat ≤ 60`
- key `NATHAN_PRINCIPAL_KEY`: at least 32 random bytes, base64url, one per gateway, shared only with its upstream

`X-Nathan-Subject`, `X-Nathan-Email` and `X-Nathan-Application` are still set for older upstreams, but are only safe while the upstream is unreachable except through the gateway.

## Worker SDK

`src/sdk/nathan.mjs` exports `nathan(request, env, options?)` and `requirePermission(request, env, permission)`.

| Mode | Input | Environment |
| --- | --- | --- |
| Gateway | `X-Nathan-Principal` | `NATHAN_PRINCIPAL_KEY`, `NATHAN_APPLICATION_ID`, optional `NATHAN_GATEWAY_ORIGIN` |
| API | `Authorization: Bearer <Nathan at+jwt>` | `NATHAN_ISSUER`, `NATHAN_AUDIENCE`, `NATHAN_APPLICATION_ID`, `NATHAN` binding (or `options.resolve`) |

A present but invalid principal header never falls back to a bearer token. DPoP-bound (`cnf`) tokens are refused. Anything that does not verify is an anonymous user that can do nothing: `require()` returns 401 for anonymous users and 403 for authenticated users without the permission. Runtime tests check that both modes give the same answers.

`options.resolve(subject, payload)` is the extension point for NATH-14 MCP scopes. Since NATH-15, tokens carry `principal_kind` and, for audiences bound to an app, an optional `roles` hint ([gatekeeper.md](gatekeeper.md)). The SDK still takes roles from the evaluator, never from the token. A machine token's `sub` is a client id, which resolves to no user and is denied.

## Identity Studio and API

**Roles and access** in Identity Studio, backed by `GET /studio/api/rbac?app=`, `GET /studio/api/rbac/groups`, `GET /studio/api/rbac/group?id=` and `POST /studio/api/rbac` with an `op`:

`access_mode`, `permission.upsert`, `permission.delete`, `role.upsert`, `role.delete`, `group.upsert`, `group.delete`, `member.add`, `member.remove`, `grant.create`, `grant.revoke`, `sync`.

Every call needs a verified, allowlisted, enrolled administrator with the current step-up (`isAdminPrincipal` + `mayAdminister`), same-origin JSON, and a size limit. Every write commits its change, a change-feed row and a `succeeded` audit row in one D1 batch; failures are audited as `failed`. An administrator's attempt that validation refuses before anything is written (unknown role, missing confirmation, undeclared permission, unknown user and so on) is audited as `rejected`, with the action and a bounded target such as `billing:editor`. Requests refused because the caller is not an enrolled, stepped-up administrator are not written to the audit log, so anonymous traffic cannot fill it. These need explicit confirmation strings:

- widening to any signed-in user: `CONFIRM ANY SIGNED IN <app>`
- deleting a role: `CONFIRM DELETE ROLE <app>/<role>`
- deleting a group: `CONFIRM DELETE GROUP <id>`
- pruning during sync: `confirmPrune: CONFIRM PRUNE <app>`

Limits: 256 permissions and 64 roles per app, and 500 groups.

## Permissions as code

Format: `applications[].rbac` in `nathan.config.json`, with `permissions`, `roles` and an optional `accessMode`. See the quickstart. `nathan rbac plan|sync <app>` and the Studio `sync` operation use the same planner (`src/shared/rbac-manifest.mjs`). Sync upserts declared entries as source `code`. With `--prune`, it deletes code-sourced entries that are no longer declared; Studio-created entries are never pruned. Omitting `accessMode` leaves the mode alone. Grants are never synced.

The CLI applies statements one at a time through the D1 REST API. A failure part-way can only leave a role with fewer permissions, and re-running converges.

## Directory API for Gatekeeper

Gatekeeper's policy-information point reads Nathan's roles within its 30 s freshness window (`AUTHORITY_MAX_AGE_MS`). Responses are `Cache-Control: no-store` and carry `observedAt`; Gatekeeper must treat stale or unreachable data as indeterminate.

**Subject format.** Subjects are issuer-qualified: `<issuer>#<sub>`, for example `https://login.example.com/api/auth#Yk3…`. The issuer is Nathan's OIDC issuer, and `sub` is the Nathan user id, the same `sub` that Nathan JWT access tokens carry.

**Authentication.** Register a directory client in Studio (**Gatekeeper directory access**). It is a confidential client limited to the `client_credentials` grant and scope `nathan:directory.read`. Then request a token:

```http
POST /api/auth/oauth2/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=nathan:directory.read&resource=https://login.example.com/directory
```

The result is an `at+jwt` with `aud` set to `https://login.example.com/directory`, `sub = client_id`, `principal_kind: machine` and a lifetime of 300 s. On every request the directory re-checks that the client exists, is not disabled and still holds the scope. User-delegated tokens are refused. This API is the only way to read the directory: the app-scoped `NathanVerifier` binding has no directory methods, so a same-account Gatekeeper also uses this API with its own client credentials.

`GET /directory/v1/principal?subject=<url-encoded subject>` returns 200, or 404 `unknown_subject`:

```json
{
  "subject": "https://login.example.com/api/auth#u1", "issuer": "https://login.example.com/api/auth", "sub": "u1",
  "email": "u1@example.com", "active": true,
  "groups": [{ "id": "finance", "name": "Finance", "source": "studio" }],
  "grants": [{ "app": "billing", "role": "editor", "via": { "type": "group", "id": "finance" } }],
  "applications": {
    "billing": { "enabled": true, "accessMode": "approved", "allowed": true, "reason": "granted",
                 "roles": ["editor"], "permissions": ["invoices:read", "invoices:write"] }
  },
  "observedAt": "2026-11-21T12:00:00.000Z", "cursor": "42", "maxAgeSeconds": 30
}
```

`applications` covers apps where the user holds a grant, plus every `any_signed_in` app. Each entry comes from the same evaluator as the gateway.

`GET /directory/v1/changes?cursor=<n>&limit=<1..500>` returns `{changes, cursor, hasMore, observedAt}`, ordered by `seq`. Each change has `seq`, `kind`, `app`, `principal` (`{type, id, subject?}`), `detail` and `at`.

Kinds: `grant.created`, `grant.revoked`, `member.added`, `member.removed`, `group.upserted`, `group.deleted`, `role.upserted`, `role.deleted`, `permission.upserted`, `permission.deleted`, `app.access_mode`, `app.enabled`, `app.disabled`, `app.registered`, `user.banned`, `user.unbanned`, `user.deleted`, and from SCIM (NATH-11) `user.linked`, `user.deprovisioned`, `user.reactivated`, `user.unlinked`, `user.scim_override`, `group.scim_mapped`, `group.scim_unmapped` (SCIM memberships are `member.added`/`member.removed` with `detail.source = "scim"`).

Blocking and deleting users does not always go through Identity Studio (Better Auth's admin API, MCP, SCIM and SQL can do it too), so D1 triggers in migration 0011 feed those changes, with actor `system:user-state`:

- `user.banned` / `user.unbanned` when `user.banned` changes between set and not set (`NULL` and `0` both mean not set).
- When a user is deleted: one `member.removed` per membership that cascades away (`detail: {group, cause: "user.deleted"}`), one `grant.revoked` per direct grant, which is deleted with the user (`detail: {role, cause: "user.deleted"}`), then `user.deleted`.

To start, read the principal (or snapshot) and follow from its `cursor`. Entries older than 30 days are pruned by the daily cron. A cursor below the pruned watermark gets **410** `{resync: true}`: re-read and continue from the returned cursor.

Reads are not audited; every write that changes them is.

## Not in Nathan

These are out of scope: conditions, approvals, a policy language or resource rules (Gatekeeper); access-token role claims (NATH-15); MCP scopes capped by permissions (NATH-14). SCIM group mapping (NATH-11) writes `source = 'scim'` groups that Studio does not edit by hand, and never grants roles by itself.
