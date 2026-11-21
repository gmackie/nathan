# Inbound SCIM 2.0 (NATH-11)

Nathan accepts SCIM 2.0 provisioning from enterprise directories such as Okta and Microsoft Entra ID. It can link directory users to Nathan accounts, deprovision them (ban, revoke sessions and tokens, back-channel logout), and feed explicitly mapped Nathan groups.

> **Status:** source and workerd tests are done. It has not yet been verified against live Okta or Entra tenants or on staging Cloudflare. The request shapes in `tests/fixtures/scim/` follow the vendors' published examples; they are not captures from a live tenant.

## Model

| Piece | Where | What it holds |
| --- | --- | --- |
| Connection, bearer token hashes, policy | D1 `nathan_scim_connections`, `nathan_scim_credentials` | Domain, enabled, `linking_enabled`, `jit_enabled`, last sync and last error times |
| Staged Users and Groups | One SQLite Durable Object per connection | What the directory sent, with a revision (ETag) per resource and an ordered outbox |
| Applied state | D1 `nathan_scim_users`, `nathan_scim_groups` | Link status, applied revision, last change |
| Group mappings | D1 `nathan_scim_group_mappings` | SCIM group (by SCIM `id` or `externalId`) → one Nathan group |
| Error log | D1 `nathan_scim_errors` | The last 200 reconciliation failures per connection |
| Logout queue | D1 `nathan_backchannel_deliveries` | Back-channel logout deliveries, with retries |

**SCIM records never grant access by themselves** (NATH-1). A directory user reaches an application only through roles that an administrator grants, directly or to a mapped group (see [rbac.md](rbac.md)).

## Endpoint and token

- **Base URL:** `https://<identity host>/scim/v2/<connection-id>`, for example `https://login.example.com/scim/v2/acme-workforce`. Studio's connection list shows it as `baseUrl`. Resources live under it: `/Users`, `/Groups`, `/ServiceProviderConfig`, `/ResourceTypes` and `/Schemas`.
- **Authentication:** `Authorization: Bearer nathscim_…`. Each token belongs to exactly one connection. Nathan shows it **once**, when the connection is created or the token rotated, and stores only its SHA-256 hash. Paste it straight into the directory's secret field. Never put it in tickets, chat or configuration files.
- **Rotation:** in Studio, under SCIM directory connections, choose **Rotate bearer token**. The old token keeps working for five minutes, so update the directory within that time.
- New connections are **disabled** and **directory-only**: linking and just-in-time creation are both off. Enable the connection only after the directory is configured.

## Lifecycle settings (Identity Studio → SCIM → Directory lifecycle)

All changes require an enrolled, stepped-up administrator and an exact confirmation, and every attempt is audited, including refused ones (`scim_settings_update`, `scim_group_map`, `scim_group_unmap`).

- **Linking** (default off): links a directory user to an existing Nathan account.
  - A link is keyed by **(connection, externalId)**. Once made, it is the only way that directory user maps to Nathan.
  - The **first** link is made by email, and only when both of these hold:
    1. the email is in the connection's domain and that domain is **verified**, today through Better Auth enterprise SSO domain verification (the DNS TXT challenge under Enterprise SSO in Studio);
    2. the Nathan account's email is verified.

    Nathan never links by an unverified email, and never when more than one verified account matches.
  - A Nathan account can be linked to only one SCIM identity in one connection, so a link never moves and another connection can never take over or deprovision it.
  - Turning linking off does not undo existing links; deprovisioning still applies to linked users.
- **Just-in-time creation** (default off; needs linking on): creates an account for a directory user who has none. The account's email stays **unverified**, because a directory record does not prove it. The person must still sign in with a real method, such as enterprise SSO. `admitJustInTime` in `src/auth/scim/lifecycle.ts` is the hook where invitation-only admission (NATH-16) will require an invitation.
- Saving the settings re-applies every staged user and group under the new policy.

## Deprovisioning

`active: false` (PATCH or PUT, including Entra's string `"False"`) or `DELETE /Users/{id}` on a linked user does all of the following **in one D1 transaction**:

1. Bans the Nathan account (Better Auth's `banned`, `banReason = "SCIM deprovisioned (connection <id>)"`, no expiry). Better Auth refuses new sessions for a banned account.
2. Deletes every Nathan session of the account.
3. Revokes every OAuth access and refresh token, `offline_access` included.
4. Queues an OIDC back-channel logout for each enabled client with a `backchannel_logout_uri` that holds a token or consent for the user.
5. Writes `user.banned` and `user.deprovisioned` to the change feed, plus an audit row.

**Fail closed.** The SCIM request reports success only after that transaction commits. If it cannot commit, the directory gets **503** with `Retry-After`, the change stays queued in the Durable Object, the error is logged, and an alarm retries it even if the directory does not. While an earlier change is still unapplied, new changes are refused with 503, so nothing is applied out of order.

**Within 60 seconds.** Nathan gateways look up access over the `NathanVerifier` binding at least every 60 s (`ACCESS_CACHE_TTL_SECONDS` ≤ 60), and a banned user is always denied. Back-channel logout also deletes gateway sessions right away. Cookie-based `NathanVerifier.getPrincipal` fails at once, because the session is gone. A Worker that only verifies a Nathan-issued **JWT** access token locally, without the binding, still accepts it until it expires (at most 5 minutes for Nathan's own resources). Use the binding for immediate revocation.

**Back-channel logout delivery.** Each delivery is a Logout Token (`typ: logout+jwt`, `sub` only, meaning every session of that user at the client), signed with Nathan's ID-token key, so the gateway's `/__nathan/backchannel` receiver verifies it with the JWKS it already uses. Each attempt signs a new token with a new `jti`. The connection's Durable Object sends deliveries right after the revocation commits. Failures are retried after 15 s, 1 min, 5 min, 15 min, 1 h, 6 h and 12 h, then marked `failed` and audited (`backchannel_logout_failed`). The identity Worker's `scheduled` handler also retries due deliveries when a cron trigger is configured. A slow or failing relying party never delays or fails the revocation.

**Reactivation.** `active: true` lifts the ban only if it is still Nathan's own SCIM ban. A ban an administrator set is never lifted by the directory. Old sessions and tokens are **not** restored. The person signs in again.

`DELETE` never deletes the Nathan account. It bans the account and removes the user's mapped memberships.

## Group mapping

1. Create an empty Nathan group under Roles and access, for example `engineering`.
2. Under Directory lifecycle → Group mapping, map it to the directory's group:
   - **Entra ID:** by `externalId`, which is the Entra group's object ID (Entra's default mapping `objectId → externalId`).
   - **Okta:** Okta's Push Groups usually sends no `externalId`. Push the group first, then map it by its Nathan SCIM `id`, which is shown in the connection view's group list.
3. Grant the group roles in Roles and access. **Mapping alone grants nothing.**

Once mapped, the group is `source = 'scim'`: Studio refuses manual member changes, and its membership is exactly the linked, non-deleted directory members of that SCIM group. Changes are idempotent, so adding an existing member or removing an absent one changes nothing. Removing a user from a SCIM group removes only that group's membership, and other Nathan groups are untouched. Unmapped SCIM groups never change Nathan groups. A Nathan group can be fed by only one SCIM group. Removing a mapping removes the memberships the directory added and returns the group to `source = 'studio'`; the group's grants stay.

Change-feed kinds added by SCIM: `user.linked`, `user.deprovisioned`, `user.reactivated`, `group.scim_mapped` and `group.scim_unmapped`. Memberships appear as `member.added` and `member.removed`, with `detail.source = "scim"`.

## Replay safety and PATCH semantics

- Every staged change bumps the resource's revision (ETag `W/"<n>"`) and appends an outbox row **in the same Durable Object transaction**. Reconciliation applies the resource's current state to D1 and removes the outbox row only after D1 commits.
- A PATCH or PUT that changes nothing keeps the revision and queues nothing, so a replayed PATCH is a no-op. D1 also skips any resource already applied at that revision.
- `If-Match` is honoured: a stale ETag gets **412**.
- Supported PATCH operations (RFC 7644 §3.5.2): `add`, `replace` and `remove`, in any letter case.
  - Users: `active`, `userName`, `displayName`, `emails`, `emails[type eq "work"].value`, and pathless `replace` or `add` with an object value, including dotted keys such as `name.givenName`.
  - Groups: `displayName`, `externalId` (it can be set once), and `members` (`add`, `replace`, `remove` with a value array, `remove` without a value to clear all), plus `members[value eq "<id>"]`.
- `externalId` is immutable. A change gets **409** `mutability`, and a PUT that omits it keeps the stored value.
- Attributes Nathan does not store (`name`, `title`, `phoneNumbers`, `addresses`, the enterprise extension and others) are accepted and ignored. Unknown paths get **400** `invalidPath`.
- Filters: `userName eq` (case-insensitive), `externalId eq` and `displayName eq` on Users; `displayName eq`, `externalId eq` and `id eq` on Groups. `excludedAttributes=members` is supported on Groups.
- The rate limit is 600 requests per minute per connection.

## Okta setup

1. In Studio, create the connection (ID, the Okta org's email domain), copy the bearer token, and verify the domain under Enterprise SSO if you have not already.
2. In Okta, open your app integration and turn on SCIM provisioning. Under **Provisioning → Integration**:
   - **SCIM connector base URL:** `https://<identity host>/scim/v2/<connection-id>`
   - **Unique identifier field for users:** `userName`
   - **Supported provisioning actions:** Push New Users, Push Profile Updates, Push Groups
   - **Authentication Mode:** HTTP Header, and paste the token as the Bearer token.
3. Choose **Test Connector Configuration**. Okta calls `/ServiceProviderConfig` and `/Users`; the connection must be enabled.
4. Under **Provisioning → To App**, enable Create Users, Update User Attributes and Deactivate Users. Okta deactivates with `PATCH {"op":"replace","value":{"active":false}}` and updates with a full `PUT`.
5. Make sure `externalId` is mapped to an immutable Okta attribute. Nathan rejects a user without `externalId` (400).
6. Enable the connection in Studio, then turn on linking, and just-in-time creation if you want it, under Directory lifecycle. Push groups, then map them.

## Microsoft Entra ID setup

1. In Studio, create the connection (ID, the tenant's verified email domain) and copy the bearer token.
2. In Entra, open **Enterprise applications → your app → Provisioning**, and set the mode to **Automatic**:
   - **Tenant URL:** `https://<identity host>/scim/v2/<connection-id>`
   - **Secret Token:** the bearer token
3. Choose **Test Connection**. Entra queries `/Users?filter=userName eq "<random>"` and expects an empty list.
4. In **Mappings**, keep the defaults: user `objectId → externalId`, `userPrincipalName → userName`, `Switch([IsSoftDeleted], …) → active`, and group `objectId → externalId`, `displayName → displayName`.
5. Nathan handles Entra's request quirks: capitalized ops, `"True"`/`"False"` strings, pathless replace with dotted keys, `emails[type eq "work"].value`, and member removal by value array. It works with or without the `aadOptscim062020` compliance flag on the Tenant URL.
6. Enable the connection, turn on linking, map groups by their Entra object ID, and start provisioning.

## Operations

- **Status:** the Studio connection view (`GET /studio/api/scim/connection?id=<id>`, admin only) shows each staged user's link state, link method and note (for example "domain is not verified"), the mapped groups, the last sync time, the error log and the logout-queue counts.
- **A stuck change** shows up in the error log and as 503 responses to the directory. Fix the cause (D1 availability, a schema problem), and the Durable Object alarm or the directory's next retry applies it. Saving the lifecycle settings forces a full re-application.
- **Unlinking** a single user is not yet a Studio action.
