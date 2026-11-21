# Remote MCP servers protected by Nathan

Any Cloudflare Worker can be a remote [Model Context Protocol](https://modelcontextprotocol.io/specification/2025-11-25) server with Nathan as its OAuth authorization server (NATH-14). Users choose exactly which scopes a client gets on Nathan's consent page. A client can never do more than the user can: at every token issuance and every request, its scopes are cut down to the user's current permissions on the app.

The design follows ForgeGraph's remote MCP (FORGE-396 granular scopes and consent, FORGE-401 Full access and sensitive scopes). Status: implemented source, tested in workerd. Not yet verified on a deployed Nathan or with third-party MCP products (see [Verification](#verification)).

## Protect a remote MCP server on Workers in 5 minutes

You need a Nathan installation (`https://login.example.com`), an Identity Studio administrator with completed enrollment, and a Worker on the same Cloudflare account.

**1. Declare the app and its permissions.** The MCP server is a Nathan application. Its permission keys are its MCP scopes. Use `nathan rbac sync` with a manifest ([RBAC quickstart](quickstart-rbac.md)) or Identity Studio → **Roles and access**:

```json
{
  "app": "notes",
  "permissions": {
    "notes:read": "Read notes",
    "notes:write": "Create and edit notes",
    "notes:export": "Download every note"
  },
  "roles": { "writer": ["notes:read", "notes:write"], "owner": ["notes:read", "notes:write", "notes:export"] }
}
```

Grant the roles to users or groups. A user without a role on the app gets no access through MCP either.

**2. Register the MCP server.** Identity Studio → **Remote MCP servers**: the resource is the exact HTTPS URL of the MCP endpoint, for example `https://notes.example.com/mcp`, the application is `notes`. Optional catalog metadata:

```json
{
  "aliases": { "notes:basic": ["notes:read", "notes:write"] },
  "scopes": {
    "notes:read": { "label": "Read notes", "description": "List and read your notes.", "group": "notes" },
    "notes:write": { "label": "Write notes", "description": "Create and edit notes.", "group": "notes", "requires": ["notes:read"] },
    "notes:export": { "label": "Export every note", "description": "Download all notes at once.", "group": "bulk", "sensitive": true }
  }
}
```

Set **Full access marker** to `notes:full` if you want a Full access checkbox. Registering creates an NATH-15 token audience bound to the app, is audited, and returns the protected-resource metadata the Worker will serve.

**3. Write the Worker.**

```js
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
// Copy Nathan's src/sdk/mcp.mjs and src/shared/security.mjs into nathan/sdk/ and nathan/shared/
// (the relative layout matters) and add the `jose` and `@modelcontextprotocol/sdk` packages.
import { nathanMcp } from "./nathan/sdk/mcp.mjs";

export default {
  fetch(request, env) {
    const mcp = nathanMcp(env, { resource: "https://notes.example.com/mcp", resourceName: "Notes",
      scopes: ["notes:read", "notes:write", "notes:export"] });
    return mcp.handle(request, async user => {
      const server = new McpServer({ name: "notes", version: "1.0.0" });
      if (user.can("notes:read")) server.registerTool("notes_list", { description: "List notes" }, async () => ({ content: [{ type: "text", text: "[]" }] }));
      if (user.can("notes:write")) server.registerTool("notes_write", { description: "Write a note" }, async () => ({ content: [{ type: "text", text: "ok" }] }));
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      return transport.handleRequest(request);
    });
  }
};
```

`mcp.handle` serves `/.well-known/oauth-protected-resource` (and `/.well-known/oauth-protected-resource/mcp`), answers requests without a usable token with a 401 challenge, and calls your handler with a `user`. Inside, `user.can(scope)` and `user.require(scope)` (a 403 `insufficient_scope` response, or `null`) read the scopes Nathan reports for this token now. List and run a tool only when its scope is there, like the example.

**4. Bind it to Nathan.** In the Worker's Wrangler config:

```jsonc
{
  "vars": { "NATHAN_ISSUER": "https://login.example.com/api/auth" },
  "services": [{ "binding": "NATHAN", "service": "nathan-auth", "entrypoint": "NathanVerifier", "props": { "applicationId": "notes" } }]
}
```

The service binding is the fast, private path for the grant check. Like every `NathanVerifier` call it is app-scoped ([rbac.md](rbac.md)): a binding answers only for MCP servers of the application pinned in its `props`, and an unpinned binding answers nothing. Without it (a Worker on another account), the SDK verifies the token against `https://login.example.com/api/auth/jwks` and asks `POST https://login.example.com/mcp-oauth/grant`, authenticated with the token itself.

**5. Connect a client.** Add `https://notes.example.com/mcp` as a remote MCP server in a client that supports Streamable HTTP and OAuth. It discovers Nathan, registers itself, and opens Nathan's consent page in the browser. Sign in, tick what the client may do, choose **Allow selected access**. Users manage their connections at `https://login.example.com/connections`.

## How it works

| What | Where |
| --- | --- |
| Protected resource (your Worker) | `https://notes.example.com/mcp`, metadata at `/.well-known/oauth-protected-resource[/mcp]` |
| Authorization server issuer | `https://login.example.com/mcp-oauth` |
| Authorization server metadata (RFC 8414) | `https://login.example.com/.well-known/oauth-authorization-server/mcp-oauth` |
| Dynamic registration (RFC 7591) | `POST /mcp-oauth/register` |
| Authorization and consent | `GET` / `POST /mcp-oauth/authorize` |
| Code exchange and refresh | `POST /mcp-oauth/token` |
| Revocation (RFC 7009) | `POST /mcp-oauth/revoke` |
| Grant check for Workers without a binding | `POST /mcp-oauth/grant` (Bearer token, `resource=`) |
| A user's connections | `GET` / `POST /connections` |

- **Authorization code with S256 PKCE only**, public clients only (`token_endpoint_auth_method: none`), exact registered redirect URIs: HTTPS, or HTTP on `localhost`, `127.0.0.1` or `[::1]`. Every parameter must appear once. The redirect carries `iss` (RFC 9207).
- **`resource` is mandatory** on authorization, code exchange and refresh, and must name a registered, enabled MCP server (RFC 8707). Anything else is `invalid_target`.
- **Access tokens** are NATH-15 RFC 9068 JWTs signed with Nathan's keys: `typ: at+jwt`, `iss` `https://login.example.com/api/auth`, `aud` the MCP resource, `sub` the user, `client_id`/`azp` the MCP client, `scope` the effective scopes, `principal_kind: "agent"`, `nathan_grant` the grant id, and a `roles` hint for the app. They live 300 s (Gatekeeper's cap is 900 s). They verify with the [Gatekeeper provider entry](gatekeeper.md#gatekeeper-identity-provider-entry) when its `audience` is the MCP resource, as Gatekeeper kind `agent`.
- **Refresh tokens** rotate on every use. A consumed refresh token presented again revokes the whole grant, and so does a replayed authorization code. This holds for concurrent requests too: a code or refresh token is consumed in one D1 batch that turns it into its used marker and stores the grant or next refresh token only for the request that turned it, so exactly one of two simultaneous requests succeeds and the other revokes the grant.
- **Nothing usable now does not burn the refresh token.** If the user currently holds none of the grant's scopes, the refresh fails with `invalid_scope` (`503 temporarily_unavailable` with `Retry-After` while the user is banned) before the refresh token is consumed, so it works again once access is back and is never mistaken for reuse. A code exchange in that state is refused the same way and creates no grant.
- A refresh may send `scope` to narrow the new access token (RFC 6749 §6): the request is intersected with what the grant holds now, so a client that still asks for a scope the user removed keeps working with the rest. It fails with `invalid_scope` only when nothing remains. Without `scope` it gets the whole grant.
- **Lifetimes:** consent ticket 10 minutes, code 5 minutes, access token 300 s, grant 30 days (absolute; the user consents again), client registration 180 days, or 24 hours if the client never obtains a grant.

### Effective scopes and the 60-second guarantee

Effective scopes = the scopes in the token ∩ what the grant holds now (the user may edit it) ∩ the user's current permissions on the app (NATH-13 evaluator: roles, groups, app enabled, user not banned) ∩ the current catalog. Admin-only scopes also need a current Nathan administrator. Nathan computes this at code exchange, at every refresh and at every grant check.

Grant edits, disconnects, client and administrator revocation, permission changes and disabling the server reach the Worker within 60 seconds: the SDK asks Nathan about each token and caches the answer for at most 30 s (`cacheSeconds`, clamped to 0–30). Without the check, a revoked token could live for its full 300 s, so the SDK never skips it. If Nathan cannot be reached the SDK answers 503 (fail closed). The short token lifetime limits what a token is worth outside a Nathan-checked server, for example at Gatekeeper, which verifies the signature only.

## Scope catalog

The catalog is the app's permissions, read live, plus metadata stored with the MCP server (migration 0015):

- **label** and one-sentence **description** for the consent page, and a **group** (`[a-z][a-z0-9_-]*`) it is shown under. Without metadata a permission is shown with its key and its RBAC description.
- **requires**: implied scopes, added transitively when the user allows. They are added only if the user holds them.
- **sensitive**: never implied. No alias, no Full access marker and no `requires` covers a sensitive scope. Studio refuses aliases or `requires` that name one. It is granted only when the user ticks it on its own, and a client that names it in the request sees it preselected but not otherwise.
- **adminOnly**: offered to, and usable by, current Nathan administrators only. Admin-only implies sensitive.
- **aliases**: names for sets of non-sensitive scopes (`notes:basic`). Requests expand them; tokens list concrete scopes.
- **Full access marker** (`notes:full`): stored in the grant as the marker, so it covers every non-sensitive scope, including permissions the app adds later.
- **Reserved**: `openid`, `profile`, `email`, `address`, `phone`, `offline_access` and every `nathan:*` scope are never MCP scopes. A permission with such a key is left out of the catalog. `offline_access` in a request is accepted and ignored (refresh tokens are always issued).

### Consent page

The consent page runs no script. It shows the client's self-reported name and id, the MCP server, the signed-in user and the callback origin, and one checkbox per scope the user can grant now, preselected from the request. The user can untick any of them or tick others, and tick Full access (which makes the server ignore the individual non-sensitive boxes). Requested scopes the user does not hold are listed as unavailable. A request naming a scope outside the catalog is refused with `invalid_scope` before the page; a user with nothing to grant sends the client `access_denied`.

- The page carries a single-use ticket bound to the user and the browser session that loaded it. The answer must come from Nathan's origin (`Origin` and `Sec-Fetch-Site` checked). A missing or opaque `Origin: null` is refused.
- The consent and connections pages are served with `Referrer-Policy: same-origin`, not `no-referrer`: under `no-referrer` browsers send `Origin: null` with a same-origin HTML form post (verified in Chromium; `fetch()` is unaffected), so Allow, Deny, Save and Disconnect would all be refused. `same-origin` still sends no referrer to the client's callback or any other site. The workerd tests derive each form post's `Origin` from the page's policy rather than setting it by hand.
- An empty or invalid selection re-renders the page with an error and leaves the ticket usable. A used, expired or foreign ticket is refused and grants nothing.
- The CSP is `default-src 'none'; script-src 'none'; form-action 'self' <callback origin>`. WebKit applies `form-action` to the redirect after the POST, so the exact, already validated callback origin is allowed. Safari's behavior here is not yet tested in a real browser.
- If the user is not signed in, Nathan stores the authorization URL in a 10-minute `__Host-nathan-mcp-return` cookie, sends them to `/sign-in`, and continues after sign-in. Only `/mcp-oauth/authorize?…` and `/connections` are accepted as return paths.

### Connections page

`/connections` lists the signed-in user's live grants: client, server, dates, the stored selection and what is usable now. **Save permissions** replaces the selection (same rules as consent), **Disconnect** revokes the grant and every token of it. Forms carry a per-session CSRF token and must come from Nathan's origin. Another user's grant looks exactly like a missing one. Administrators see every grant in Studio and can revoke any of them (`CONFIRM REVOKE <grant id>`).

## Client registration

`POST /mcp-oauth/register` accepts RFC 7591 metadata for public clients only: `redirect_uris` (1–5 exact URIs of at most 512 characters, as above), `token_endpoint_auth_method` `none`, `grant_types` from `authorization_code` and `refresh_token`, `response_types` `code`, `client_name` (at most 64 characters), and an optional `scope` (at most 1024 characters) that may name only MCP catalog scopes, aliases and Full access markers (never `openid`, `profile`, `email` or `nathan:*`). Nathan stores only the name, redirect URIs and scope, so one registration row stays under 4 KB. Every other field (informational URIs, contacts, `jwks_uri`, software statements, unknown extensions) is dropped and never stored or echoed; RFC 7591 lets a server ignore metadata it does not use.

Registration is anonymous, so it is bounded so that it cannot fill D1:

- **Unused registrations are short-lived.** A client that has not completed a code exchange within 24 hours of registering is deleted, by the scheduled handler and opportunistically (up to 100 at a time) on every registration. From its first grant on (`first_grant_at`), a registration lives its full 180 days, even if that grant is later revoked.
- **At most 1,000 unused registrations exist at once.** Beyond that, registration answers `503 temporarily_unavailable` with `Retry-After: 3600` until pruning makes room, and Nathan writes one `mcp_client_register` audit row with outcome `refused` per hour. Registered clients keep working.
- **Rate limits.** Every attempt, valid or not, counts toward 20 per minute per address. Only registrations that are about to be stored count toward the global 300 per minute, so a flood of invalid requests cannot lock out real clients.

These clients exist only for the MCP authorization server. They are not Better Auth OAuth clients and cannot use `/api/auth` or get OIDC scopes.

**Client ID Metadata Documents are not supported** (`client_id_metadata_document_supported: false`). Better Auth 1.7.14 offers only a discovery seam; the implementation is the separate `@better-auth/cimd` plugin, which needs resolve-once DNS handling that Workers' `fetch` does not provide. Clients fall back to dynamic registration.

## Studio API

`GET /studio/api/mcp` returns the MCP servers with their live catalogs and the live grants. `POST /studio/api/mcp` (administrator with completed enrollment and step-up, same-origin, JSON, audited) takes an `op`:

- `resource.register` `{identifier, app, name, full?, aliases?, scopes?}`. Identifiers follow the audience rules (exact `https`, no query, fragment or percent-encoding; Nathan's own `/mcp`, `/directory` and `/api/auth` are refused). An identifier that is already a Better Auth token audience is refused, so Better Auth never issues tokens for an MCP server. Moving a server to another application ends its connections.
- `resource.status` `{identifier, enabled, confirm: "CONFIRM ENABLE MCP <id>" | "CONFIRM DISABLE MCP <id>"}`. A disabled server gets no tokens and its tokens fail the grant check.
- `resource.remove` `{identifier, confirm: "CONFIRM REMOVE MCP <id>"}` removes the audience, the server and every grant.
- `grant.revoke` `{grantId, confirm: "CONFIRM REVOKE <grantId>"}`.

## Design decisions

**A Nathan-owned grant layer, not Better Auth's consent.** Better Auth 1.7.14's `oauthProvider` keeps a static scope list, validated at authorization and registration, so per-app permission scopes would collide across apps and need a redeploy. Its `/oauth2/consent` accepts only a subset of the originally requested scopes, so a user cannot add one. A refresh `scope` outside the grant is an error rather than an intersection, `resource` is optional on refresh, and nothing can cap the issued `scope` by the user's current permissions. Its database-backed resources can hold per-app audiences, but not per-app catalogs with these consent semantics. So `src/auth/mcp-oauth.ts` owns MCP clients, consent, grants, codes and refresh tokens, like ForgeGraph's `McpOAuth`, and signs access tokens with Better Auth's JWT plugin keys. One-time values are stored as SHA-256 hashes. Consent tickets are consumed with `DELETE … RETURNING`; codes and refresh tokens are turned into their used markers in the same D1 batch that stores what they produce, so a lost race is detected as reuse.

**One token issuer.** The authorization server has its own issuer, `https://login.example.com/mcp-oauth`, because Better Auth already serves `/.well-known/oauth-authorization-server/api/auth` for its own endpoints. Access tokens are issued under Nathan's token issuer, `https://login.example.com/api/auth`, with the same keys, so Gatekeeper, the Nathan SDKs and the directory see one issuer and one subject namespace (`<issuer>#<sub>`). An agent acting for Alice is `principal:<issuer>:sub:u-alice` with kind `agent` in Gatekeeper, not a second identity. MCP clients never read access tokens; resource servers are configured with `NATHAN_ISSUER`, and the authorization server metadata names the `jwks_uri`.

**Nathan's own `/mcp` stays on its current machinery.** The admin MCP endpoint ([mcp.md](mcp.md)) requires a verified, allowlisted administrator whose Better Auth session (`sid`) still exists and holds a recent passkey step-up (`mayAdminister`), and writes need a live session. MCP grants deliberately outlive browser sessions (30 days with refresh) and carry no `sid`, so moving `/mcp` onto them would weaken those checks. `nathan:read` and `nathan:admin` are also Nathan administration scopes, not app permissions. Its clients are still registered by administrators in Studio.

**Gatekeeper action catalogs (design only).** A later import can map a Gatekeeper `MCPProvider` action catalog onto this shape without changing the storage: each action becomes a permission key (the scope) on the app through the RBAC manifest, and its display data becomes scope metadata through `resource.register`:

```json
{ "source": "gatekeeper", "provider": "<MCPProvider id>", "app": "notes", "resource": "https://notes.example.com/mcp",
  "actions": [{ "scope": "notes:write", "label": "Write notes", "description": "Create and edit notes.", "group": "notes",
                "requires": ["notes:read"], "sensitive": false }] }
```

Nathan stays authentication plus roles: servers that need conditions, approvals or policy put Gatekeeper's MCP gateway in front, and Gatekeeper reads roles from Nathan's directory.

## Operations

- **Rate limits** (fixed windows in `nathan_mcp_limits`, keyed by hashes): registration 20/min per address (all attempts) and 300/min overall (stored registrations only), at most 1,000 registrations without a grant; token and revocation 120/min per address; consent pages and answers 30/min per user; connection changes 30/min per user; grant checks 600/min per address.
- **Audit** (`nathan_security_audit`): client registration, consent, grant creation, grant edits, revocation with its reason (`user_disconnect`, `client_revocation`, `refresh_reuse`, `code_replay`, `admin_revocation`), and every Studio change.
- **Storage** (migration 0015): `nathan_mcp_resources`, `nathan_mcp_scopes`, `nathan_mcp_clients`, `nathan_mcp_grants`, `nathan_mcp_artifacts`. Deleting a grant removes its tokens; removing the server, the app, the client or the user removes the grants. The scheduled handler prunes expired rows and registrations that never obtained a grant within 24 hours; expiry is enforced on every read.
- No CORS is granted, so browser-based MCP clients cannot call the token endpoint cross-origin.

## Verification

`tests/mcp-scopes.test.mjs` and `tests/mcp-sdk.test.mjs` (node) cover the catalog rules, registration rules, migration 0015 and the SDK's challenges, cache bound and fail-closed behavior. `tests/runtime/remote-mcp.test.mjs` runs the built identity Worker and a sample MCP server Worker (`tests/runtime/fixtures/mcp-server.mjs`, MCP SDK Web Standards transport) in workerd, once with the service binding and once over HTTPS. An MCP TypeScript SDK 1.32.2 client completes discovery, registration, consent narrowed to one scope and a tool call, and the token response's `scope` is what was granted. It also covers every rule above: registration bounds, the per-address and global limits (invalid attempts never count globally), the unused-registration cap with its once-an-hour audit, pruning at registration and in the scheduled handler, resource binding, catalog and reserved scopes, sensitive scopes vs alias and Full access, consent CSRF, ticket replay and empty selection, PKCE and code replay, refresh narrowing and reuse revocation, concurrent code exchanges and refreshes (exactly one wins, the grant is revoked), refreshes that keep their token while nothing is usable or the user is banned, grant edits and disconnect within the cache window, permission removal, revocation, and verification under the Gatekeeper provider entry as kind `agent`.

Not yet verified: a deployed Nathan and MCP server on Cloudflare, real browsers (including Safari's `form-action` behavior), and specific MCP products (Claude, ChatGPT, editors), whose OAuth behavior varies.
