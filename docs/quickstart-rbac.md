# Protect a Worker and check a permission in 5 minutes

You have a private Cloudflare Worker (here `my-dashboard`) and a running Nathan at `login.example.com`. When you finish, only people you grant a role can reach the Worker, and the Worker can ask `user.can("invoices:write")`.

New applications deny everyone until you grant a role. Blocked users and disabled applications are always denied.

## 1. Declare permissions and roles (30 seconds)

In `nathan.config.json`, add an `rbac` section to the application:

```json
{
  "id": "dashboard",
  "kind": "worker",
  "workerName": "my-dashboard",
  "hostname": "app.example.com",
  "protection": "gateway",
  "rbac": {
    "permissions": {
      "invoices:read": "Read invoices",
      "invoices:write": "Create and edit invoices"
    },
    "roles": {
      "viewer": { "description": "Read-only", "permissions": ["invoices:read"] },
      "editor": { "description": "Edit invoices", "permissions": ["invoices:read", "invoices:write"] }
    }
  }
}
```

A permission key is lowercase segments separated by colons (`resource:action`), without wildcards. A role key is lowercase letters, digits, `-` or `_`. Every permission a role uses must be declared. Grants (who holds a role) are never code.

## 2. Sync them to Nathan (30 seconds)

```sh
CLOUDFLARE_API_TOKEN=… node scripts/nathan.mjs rbac plan dashboard          # read-only diff
CLOUDFLARE_API_TOKEN=… node scripts/nathan.mjs rbac sync dashboard --apply  # apply, after confirmation
```

If `dashboard` is not registered yet, sync registers it **disabled** in the `approved` access mode. The sync is idempotent and audited as `cli:<accountId>`. Cloudflare's D1 REST API runs one statement per call, so a sync is not one transaction: the CLI audits `attempted` before the first change, then `succeeded`, or `partial`/`failed` with how many statements were applied. A failure part-way only ever leaves less access, and re-running the sync converges. `--prune` also deletes code-managed roles and permissions that you removed from the file; it asks you to type `PRUNE`, because deleting a role deletes its grants. You can paste the same `rbac` object into **Identity Studio → Roles and access → Permissions and roles as code** instead.

## 3. Put the gateway in front (2 minutes)

```sh
node scripts/nathan.mjs protect dashboard           # prints the plan
node scripts/nathan.mjs protect dashboard --apply   # deploys after proving the upstream is private
```

The gateway gets a service binding `NATHAN` to your identity Worker (entrypoint `NathanVerifier`, pinned to this app with `"props": {"applicationId": "dashboard"}`), a fresh `NATHAN_PRINCIPAL_KEY`, and `ACCESS_CACHE_TTL_SECONDS=30`. With your confirmation, the CLI puts the same `NATHAN_PRINCIPAL_KEY` on the upstream Worker as a secret. The key is never written to disk.

Add two plain variables to the upstream Worker's `wrangler.jsonc`:

```jsonc
"vars": { "NATHAN_APPLICATION_ID": "dashboard", "NATHAN_GATEWAY_ORIGIN": "https://app.example.com" }
```

## 4. Check a permission in the Worker (1 minute)

```js
// Copy Nathan's src/sdk/nathan.mjs, src/shared/principal.mjs and src/shared/policy.mjs into
// nathan/sdk/ and nathan/shared/ (the relative layout matters) and add the `jose` package.
import { nathan } from "./nathan/sdk/nathan.mjs";

export default {
  async fetch(request, env) {
    const user = await nathan(request, env);   // verifies the gateway-signed principal
    const denied = user.require("invoices:write");
    if (denied) return denied;                  // 401 if unauthenticated, 403 if not permitted
    return new Response("Hello " + user.email + ", you are " + user.roles.join(", "));
  }
};
```

`user` has `sub`, `email`, `roles`, `permissions`, `hasRole(role)`, `can(permission)`, `require(permission)`, `requireRole(role)` and `forbidden()`. Trust only `nathan(request, env)`. The plain `X-Nathan-Subject` and `X-Nathan-Email` headers remain for older upstreams; they are only safe if nothing but the gateway can reach the Worker.

## 5. Grant a role and enable the app (1 minute)

In **Identity Studio → Roles and access**:

1. Enter `dashboard` and choose **Load roles and grants**.
2. Under **Grants**, grant `editor` to a user's exact email, or create a group, add members, and grant the role to the group.
3. Under **Protected applications**, enable `dashboard` (confirmation required).

Or, from the CLI with a Cloudflare API token that has D1 edit on the Nathan account (no Studio session; see [account-token administration](security.md#account-token-administration)):

```sh
node scripts/nathan.mjs user find --email ada@example.com                                # prints the Nathan user id (read-only)
node scripts/nathan.mjs rbac grant dashboard editor --user ada@example.com --apply       # or --user <user id>, or --group <group>
node scripts/nathan.mjs app enable dashboard --apply                                     # asks you to type CONFIRM ENABLE dashboard
node scripts/nathan.mjs rbac revoke dashboard editor --user ada@example.com --apply
```

Each command plans without `--apply`. With it, the CLI runs Studio's own validation (unknown apps, roles, users and groups are refused, and refusals are audited `rejected`), asks for confirmation, and commits the change, its change-feed entry and Studio's `succeeded` audit row in one D1 batch, after an `attempted` row; all are audited as `cli:<accountId>`.

Open `https://app.example.com`, sign in, and the Worker sees `user.can("invoices:write") === true`. Revoke the grant, and within `ACCESS_CACHE_TTL_SECONDS` (at most 60 s) the gateway answers 403.

## Other ways in

- **Any signed-in user.** Set the access mode to *Any signed-in user* (Studio asks for confirmation; the CLI asks you to type the app id). Everyone who can sign in gets in, with no roles unless granted.
- **APIs with bearer tokens.** Set `NATHAN_ISSUER` (for example `https://login.example.com/api/auth`) and `NATHAN_AUDIENCE` on the Worker, and bind `NATHAN` to the identity Worker's `NathanVerifier` entrypoint, pinned to the app: `{"binding": "NATHAN", "service": "<name>-auth", "entrypoint": "NathanVerifier", "props": {"applicationId": "dashboard"}}`. `nathan(request, env)` then verifies a Nathan user `at+jwt` access token and gets roles from the same evaluator. Without that binding, or with a pin for another app, a valid token authenticates but grants nothing. Machine (client-credentials) tokens and DPoP-bound (`cnf`) tokens are refused on this path. Register the API as a token audience in Identity Studio so clients can get tokens for it. A token `roles` claim is only a hint ([gatekeeper.md](gatekeeper.md)); the SDK ignores it.
- **Gatekeeper.** For conditions, approvals and resource rules, Gatekeeper reads these roles from Nathan's directory API. See [rbac.md](rbac.md#directory-api-for-gatekeeper).

See [rbac.md](rbac.md) for the model, the legacy migration, the signed principal format and the directory API.
