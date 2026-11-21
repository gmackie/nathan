# Inbound SCIM 2.0 (NATH-11)

Nathan accepts SCIM 2.0 provisioning from enterprise directories such as Okta and Microsoft Entra ID. It can link directory users to Nathan accounts, deprovision them (ban, revoke sessions and tokens, back-channel logout), and feed explicitly mapped Nathan groups.

> **Status:** source and workerd tests are done. It has not yet been verified against live Okta or Entra tenants or on staging Cloudflare. The request shapes in `tests/fixtures/scim/` follow the vendors' published examples; they are not captures from a live tenant.

## Model

| Piece | Where | What it holds |
| --- | --- | --- |
| Connection, bearer token hashes, policy | D1 `nathan_scim_connections`, `nathan_scim_credentials` | Domain, enabled, `linking_enabled`, `jit_enabled`, last sync and last error times |
| Staged Users and Groups | One SQLite Durable Object per connection | What the directory sent, with a revision (ETag) per resource and an ordered outbox; deleted resources move to tombstone tables |
| Applied state | D1 `nathan_scim_users`, `nathan_scim_groups` | Link status, applied revision, administrator overrides and holds, last change |
| Administrator reviews | D1 `nathan_scim_reviews` | Directory changes held for an administrator: linking or deprovisioning a Nathan administrator, re-linking a deleted account |
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

All changes require an enrolled administrator with a fresh passkey step-up (`mayAdminister`) and an exact confirmation, and every attempt is audited, including refused ones (`scim_settings_update`, `scim_group_map`, `scim_group_unmap`, `scim_review_approve`, `scim_review_dismiss`, `scim_user_keep_active`, `scim_user_unlink`, `scim_outbox_skip`). An administrator whose step-up is older than 15 minutes is refused (403) on every SCIM route, reads included. As everywhere in Studio, the page builds the exact confirmation string after the browser's confirmation dialog, so that dialog is the human check; each dialog states the consequence of the change.

- **Linking** (default off): links a directory user to an existing Nathan account.
  - A link is keyed by **(connection, externalId)**. Once made, it is the only way that directory user maps to Nathan.
  - The **first** link is made by email, and only when both of these hold:
    1. the email is in the connection's domain and that domain is **verified**, today through Better Auth enterprise SSO domain verification (the DNS TXT challenge under Enterprise SSO in Studio);
    2. the Nathan account's email is verified.

    Nathan never links by an unverified email, and never when more than one verified account matches.
  - A Nathan account can be linked to only one SCIM identity in one connection, so a link never moves and another connection can never take over or deprovision it.
  - **Rehires:** a directory user created again with the same `externalId` in the same connection, after a `DELETE`, takes over the deleted identity's link (and, being active, lifts Nathan's SCIM ban). `userName`, `externalId` and a group's `displayName` are unique among live resources only.
  - **Deleted Nathan accounts:** when a linked Nathan account is deleted, the link's email and time are kept. Neither that connection nor any other links that email again automatically; the claim becomes an administrator review (below). Approving one connection's claim makes the others unapprovable, because an account has one link.
  - **Administrators** are never linked automatically (see below).
  - Turning linking off does not undo existing links; deprovisioning still applies to linked users.
- **Just-in-time creation** (default off; needs linking on): creates an account for a directory user who has none. It never creates an account for an address in `NATHAN_ADMIN_EMAILS`, or for an email whose linked account was deleted. The account's email stays **unverified**, because a directory record does not prove it. The person must still sign in with a real method, such as enterprise SSO. `admitJustInTime` in `src/auth/scim/lifecycle.ts` is the hook where invitation-only admission (NATH-16) will require an invitation.
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

## Nathan administrators: review, never automatic

A leaked SCIM bearer token must not be able to lock Nathan's administrators out. So SCIM **never links or deprovisions a Nathan administrator by itself**. An administrator principal is any account with one of:

- the bootstrap owner (`nathan_bootstrap_status.admin_user_id`),
- an enabled administrator grant (`nathan_admin_grants`),
- the global `admin` role,
- an email in `NATHAN_ADMIN_EMAILS`.

When a directory change would link such an account, or deactivate or delete a linked one, Nathan applies nothing to the account: no ban, no session or token revocation, no back-channel logout. It opens one **review item** instead (`nathan_scim_reviews`, audited as `scim_admin_review_open`), notes it on the directory user, and answers the directory normally, so the connection is not blocked. Replays and resyncs do not add more items.

Under **Directory lifecycle → Administrator reviews**, an administrator (fresh step-up, exact confirmation `CONFIRM APPROVE LINK|DEPROVISION <email>`) can:

- **Approve:** the connection's Durable Object re-applies that directory user at once and the change is applied exactly once (`scim_review_approve`, then `scim_admin_review_apply`). An administrator cannot approve their own deprovisioning.
- **Dismiss** (`CONFIRM DISMISS LINK|DEPROVISION <email>`): the account stays as it is. A dismissed link holds the directory user unlinked; a dismissed deprovisioning is recorded like **keep active** (below), so only a new deprovision change from the directory opens a new review.

If the directory reactivates the user first, the open item is superseded. **The last administrator is never deprovisioned by SCIM**, even with an approved review: approval is refused when no other active administrator (bootstrap owner or enabled grant, not banned) exists, and reconciliation re-checks it when applying and puts the item back to pending.

## Administrator overrides

- **Keep active** (Directory user overrides; `CONFIRM KEEP ACTIVE <email>`): unblocks a user the directory deprovisioned by lifting Nathan's own SCIM ban (never an administrator's ban), and records who did it and when (`override_by`, `override_at`, `override_cause`). Old sessions and tokens are not restored. Replays and resyncs keep the decision. Only a **new** deprovision change from the directory applies again: a reactivation followed by a deactivation, or a `DELETE` after a kept deactivation.
- An unban made outside Studio (directly in D1) is detected the next time the user is reconciled and recorded the same way, with `override_by = "out-of-band unban (detected by reconciliation)"` and an audit row (`scim_override_detected`).
- **Unlink** (`CONFIRM UNLINK <email>`): detaches the directory user from its Nathan account, removes the memberships the directory maintained (with `member.removed` feed rows), writes `user.unlinked`, and holds the directory user so it is never linked again automatically. A block the directory caused stays; use keep active first if the account should be usable.

## Group mapping

1. Create an empty Nathan group under Roles and access, for example `engineering`.
2. Under Directory lifecycle → Group mapping, map it to the directory's group:
   - **Entra ID:** by `externalId`, which is the Entra group's object ID (Entra's default mapping `objectId → externalId`).
   - **Okta:** Okta's Push Groups usually sends no `externalId`. Push the group first, then map it by its Nathan SCIM `id`, which is shown in the connection view's group list.
3. Grant the group roles in Roles and access. **Mapping alone grants nothing.**

Once mapped, the group is `source = 'scim'`: Studio refuses manual member changes, and its membership is exactly the linked, non-deleted directory members of that SCIM group. Changes are idempotent, so adding an existing member or removing an absent one changes nothing. Removing a user from a SCIM group removes only that group's membership, and other Nathan groups are untouched. Unmapped SCIM groups never change Nathan groups. A Nathan group can be fed by only one SCIM group. Removing a mapping removes the memberships the directory added and returns the group to `source = 'studio'`; the group's grants stay.

Change-feed kinds added by SCIM: `user.linked`, `user.deprovisioned`, `user.reactivated`, `user.unlinked`, `user.scim_override`, `group.scim_mapped` and `group.scim_unmapped`. Memberships appear as `member.added` and `member.removed`, with `detail.source = "scim"`.

## Replay safety and PATCH semantics

- Every staged change bumps the resource's revision (ETag `W/"<n>"`) and appends an outbox row **in the same Durable Object transaction**. Reconciliation applies the resource's current state to D1 and removes the outbox row only after D1 commits.
- A PATCH or PUT that changes nothing keeps the revision and queues nothing, so a replayed PATCH is a no-op. D1 also skips any resource already applied at that revision (duplicate outbox rows, a late older revision), and every reconciliation batch starts with a compare-and-set on the row's `apply_seq`: a second writer that read the same state rolls back completely, so a transition, its feed rows, audit rows and logout deliveries are written once.
- `If-Match` is honoured: a stale ETag gets **412**.
- Supported PATCH operations (RFC 7644 §3.5.2): `add`, `replace` and `remove`, in any letter case.
  - Users: `active`, `userName`, `displayName`, `emails`, `emails[type eq "work"].value`, and pathless `replace` or `add` with an object value, including dotted keys such as `name.givenName`.
  - Groups: `displayName`, `externalId` (it can be set once), and `members` (`add`, `replace`, `remove` with a value array, `remove` without a value to clear all), plus `members[value eq "<id>"]`.
- `externalId` is immutable. A change gets **409** `mutability`, and a PUT that omits it keeps the stored value.
- Attributes Nathan does not store (`name`, `title`, `phoneNumbers`, `addresses`, the enterprise extension and others) are accepted and ignored. Unknown paths get **400** `invalidPath`.
- Filters: `userName eq` (case-insensitive), `externalId eq` and `displayName eq` on Users; `displayName eq`, `externalId eq` and `id eq` on Groups. `excludedAttributes=members` is supported on Groups.
- The rate limit is 600 requests per minute per connection (`NATHAN_SCIM_RATE_LIMIT` overrides it, 1 to 100000).

## Bounded work per invocation

Reconciliation runs inside the connection's Durable Object, and D1 limits queries per invocation. Nathan therefore bounds the work (`RECONCILE_LIMITS` in `src/auth/scim/lifecycle.ts`):

- at most **100 statements per D1 batch** and **500 D1 statements (reads and writes) per invocation**;
- a large group is applied in several batches, **removals first**, and is marked applied only in the batch that completes it; a partial group is recomputed from D1 and continued;
- when the budget runs out, the connection's alarm continues in a fresh invocation about 50 ms later, until the outbox is empty.

What the directory sees: while earlier changes are still being applied, a new change gets **503** with `Retry-After` and is not staged. A change whose remaining work is only group **additions** is answered at once and finishes in the background. A user change, or group work that still has **removals** to apply, gets 503 until it is applied, because removals reduce access. A resync answers with `pending`, the number of resources still queued. Workerd tests apply 1,200 just-in-time links in one resync and add and remove 3,000 mapped memberships this way.

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
- **A change that can never apply** (a poisoned entry) would answer 503 to every later change forever. Under **Reconciliation outbox**, Studio shows the outbox head (`GET /studio/api/scim/outbox?id=<id>`): each queued resource, what it is (user name, active, deleted; or group name and member count), its attempts and last error. **Skip the failing head entry** (`CONFIRM SKIP USER|GROUP <id>`) drops exactly that entry, and only if it is the current head at the sequence you reviewed and has failed at least once. Nathan does **not** apply a skipped change: if it deactivated or deleted a user, that user is **not** blocked, so block them by hand. The skip is audited (`scim_outbox_skip`) and logged in the connection's error log; the resource is applied again when it changes in the directory or on a resync.
- **Unlinking** a single user: Directory user overrides → Unlink.
