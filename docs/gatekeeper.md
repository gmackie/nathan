# Gatekeeper and Nathan access tokens

Gatekeeper is the policy engine. It verifies Nathan's JWT access tokens as an external OIDC issuer and reads roles from Nathan's [directory API](rbac.md#directory-api-for-gatekeeper). Nathan authenticates and keeps roles; it does not decide policy.

This page covers what Nathan puts in its access tokens (NATH-15), how to set up a Gatekeeper audience, and the identity-provider entry to paste into Gatekeeper.

## What Better Auth 1.7.14 issues

Nathan uses `@better-auth/oauth-provider` 1.7.14. Without Nathan's additions it issues:

- **A JWT only for a configured resource.** The token request (or authorization request) must name an RFC 8707 `resource` that is a configured resource: one of the static resources in `src/auth/instance.ts` or an `oauthResource` row. Without a `resource`, the access token is opaque and has no `aud`. An unknown or disabled resource gets `invalid_target`. By default (`enforcePerClientResources`), the client must also be linked to the resource, or it gets `invalid_target`.
- **Header:** `{"typ":"at+jwt","alg":"EdDSA","kid":"…"}`. EdDSA (Ed25519) is the JWT plugin's default key algorithm. Keys rotate every 30 days with a 30-day grace period.
- **Claims:** `iss` (`https://<host>/api/auth`), `sub`, `aud`, `client_id`, `azp`, `scope`, `iat`, `exp`, `jti`, and `sid` for session-backed grants. `sub` is the Nathan user id for user grants, even when the client uses pairwise subjects (pairwise applies only to ID tokens), and the client id for client credentials.
- **Audience:** the requested resource identifier. If `openid` is also in scope, `aud` is an array that also holds `<issuer>/oauth2/userinfo`.
- **Lifetime:** the smallest of `accessTokenExpiresIn` (user grants) or `m2mAccessTokenExpiresIn` (client credentials) (both 3600 s by default), every `scopeExpirations` entry for the granted scopes, and the resource's `accessTokenTtl`.
- **Not issued:** `acr`, `amr`, `auth_time`, `nonce`, `token_use`, `act`. Better Auth reserves `acr`, `amr`, `auth_time` (and the other RFC 9068 names) for the authorization server and strips them from every claim source: `customAccessTokenClaims`, extension claims and resource `customClaims`. It does not set them on access tokens itself. ID tokens carry `acr: "0"` and `auth_time` set to the session's creation time; neither is authentication-method evidence.
- `cnf` only for DPoP-bound tokens, which Nathan does not configure. Gatekeeper rejects `cnf`.

## What Nathan adds

Through the supported oauth-provider `extensions[].claims.accessToken` hook (`src/auth/tokens.ts`, decisions in `src/shared/token-claims.mjs`). Extension claims are strictly additive: they cannot replace any claim Better Auth owns.

| Claim | When | Meaning |
| --- | --- | --- |
| `principal_kind` | every JWT access token | `user`, `machine` or `agent`, see below |
| `roles` | user and agent-for-user tokens whose requested audiences are **all** registered and bound to the **same** app, when the evaluator allows the user and they hold roles | sorted role keys from NATH-13's evaluator for that app. A **hint** for simple apps; omitted otherwise |
| `nathan_amr` | verified passkey evidence for this session | `["pop"]`, see below |
| `nathan_acr` | same | `urn:nathan:acr:passkey` |
| `nathan_auth_time` | same | when the passkey assertion was verified (seconds since epoch) |

Nathan also sets `accessTokenExpiresIn` and `m2mAccessTokenExpiresIn` to **900 s**. Better Auth takes the minimum of these, scope expirations and the resource's lifetime, so **no access token Nathan issues lives longer than 900 s**. This includes refreshed tokens, opaque tokens, user grants without a resource and resources whose stored `accessTokenTtl` was raised out of band (the runtime test covers each). Audiences registered in Studio are also stored with `accessTokenTtl` 900. The MCP and directory resources stay at 300 s.

**Several audiences in one request.** A token request may name more than one RFC 8707 `resource`; `aud` then lists them all (plus the userinfo URL with `openid`). Nathan adds `roles` only when every requested resource is a registered audience bound to the same app. If any of them is unbound, bound to another app or not a registered audience (Nathan's `/mcp`, say), the token has no `roles`, so one app's roles never reach another audience. Nathan checks every distinct resource Better Auth will put in `aud` (duplicates are collapsed, never truncated) and refuses a request naming more than 16 distinct resources with `invalid_target`, so padding cannot hide a registered audience from the live-session rule or the roles rule.

An example user token for the Gatekeeper audience, from the runtime test:

```json
{"typ":"at+jwt","alg":"EdDSA","kid":"XjOK…"}
{"principal_kind":"user","roles":["editor"],"nathan_amr":["pop"],"nathan_acr":"urn:nathan:acr:passkey","nathan_auth_time":1795292184,
 "sub":"u-alice","aud":["https://gatekeeper.example.com/api","https://login.example.com/api/auth/oauth2/userinfo"],
 "client_id":"WXyo…","azp":"WXyo…","scope":"openid profile","sid":"sess-…","iss":"https://login.example.com/api/auth",
 "iat":1795292244,"exp":1795293144,"jti":"9DGy…"}
```

### Principal kind

| Grant | Client attribute | `principal_kind` | `sub` |
| --- | --- | --- | --- |
| authorization code, or refresh from one (a signed-in human) | unset | `user` | Nathan user id |
| client credentials | unset | `machine` | client id |
| any | `agent` (set by an administrator) | `agent` | user id when acting for a user, otherwise client id |

- The only client attribute is `agent`, stored in `nathan_client_principals` (migration 0014). Only an administrator sets it, in Identity Studio. The change and its audit row commit together. A client can never be made a `user` by attribute.
- **A `user` token needs a live session.** Better Auth's refresh grant does not check that the sign-in session still exists. Nathan does: for every grant that carries a user (authorization code or refresh) and would produce a `user` token for a registered audience, the grant's Better Auth session must still exist, belong to the same user and be unexpired. Otherwise the token request fails with `invalid_grant`; Nathan does not quietly issue a `machine` or `agent` token instead. Signing out, revoking or deleting the session, its expiry and banning the user (Better Auth deletes a banned user's sessions) all stop new user tokens at once; already-issued access tokens expire within 900 s. The refusal happens before Better Auth rotates the refresh token.
- **A banned user gets no token at all** while the ban lasts (`banExpires` is honored), for any client, including agents (`invalid_grant`).
- **Agents keep offline access.** A client marked `agent` may refresh a user's delegation after the browser session ended (that is what `offline_access` is for). Those tokens say `principal_kind: agent`, carry no `sid` and no session evidence, and stop when the user is banned or the grant is revoked. Marking a client `agent` needs typed confirmation (`CONFIRM MARK AGENT <client id>`) and revokes the user grants it already holds, because they were issued as session-bound; users authorize it again.
- Mark every agent and remote MCP client as `agent`. An agent acting for Alice carries Alice's `sub` and `principal_kind: agent`. Nathan sends no `act` claim; Gatekeeper rejects `act`. Gatekeeper still gives both the **same principal id**, so a policy tells them apart only by kind (next section).
- A change applies to tokens issued from then on. Issued tokens keep their kind until they expire (at most 900 s). Classifying an agent by grant again (`auto`) also revokes its outstanding refresh and opaque tokens that carry `nathan:api`, which only agents may hold for a user.
- Machine `sub` values are client ids. The directory has no client principals, so `GET /directory/v1/principal` returns 404 for them, and Gatekeeper's PIP should treat machines as having no Nathan roles.

### The `nathan:api` scope

`nathan:api` is the scope for machine and agent calls to registered APIs and Gatekeeper. It is granted only:

- to client-credentials clients (`principal_kind: machine`, or `agent` when marked), through their `client_credentials_scopes`;
- to an administrator-marked `agent` client acting for a user (authorization code and refresh).

A client that is not marked `agent` cannot have a user delegate it. Asking for it at `/oauth2/authorize`, or omitting `scope` when the client's default scopes would include it (Better Auth's default is every provider scope), gets a 400 `invalid_scope` and no authorization code, so name scopes explicitly. As a backstop, the token endpoint refuses a JWT for a user grant with `nathan:api` from a client that is not an agent (`invalid_scope`), for example a code issued before the client was classified by grant again.

### Policies must check the principal kind

Gatekeeper's principal id is `principal:<url-encoded issuer>:sub:<url-encoded sub>`. It does **not** include the kind. An agent acting for Alice and Alice herself have the same principal id, so Gatekeeper's PIP returns the same directory roles for both, and decision caches and receipts keyed by principal id cover both. Nathan's `principal_kind` claim, mapped by `kindClaim` to Gatekeeper's `human`, `service` or `agent`, is the only thing that separates them. Every policy that should not let an agent do what the user can must say so with a `principal_kind` include:

```json
{
  "name": "Approve invoices (people only)",
  "decision": "allow",
  "include": [{"selector": "principal_kind", "values": ["human"]}],
  "require": [{"selector": "active_membership"}, {"selector": "role", "values": ["editor"]}],
  "obligations": []
}
```

Use `"values": ["human", "agent"]` only for actions an agent may perform for its user, and `["service"]` for machine-only actions (authorize those by `clientId` and scope, since machines have no directory roles). A principal Gatekeeper cannot classify is `unknown`; never include `unknown` for anything a user's agent must not do.

### Authentication-method claims

Nathan reports only evidence it holds. Today that is one thing: a `nathan_admin_assurance` row (migration 0008). Better Auth's after-hook on `/passkey/verify-authentication` writes it only after it verified a passkey (WebAuthn) assertion and created a new session. Enrolling a passkey never writes one. Nathan emits the claims only when the token's session (`sid`) has such a row for the same user and that Better Auth session is still live (present and unexpired). So client-credentials tokens never have them, user tokens cannot be refreshed once the session has ended (see above), and agent tokens refreshed after it ended carry none.

- `nathan_amr: ["pop"]`: RFC 8176 proof of possession of a key. It is not `hwk`, because synced passkeys are not hardware-bound. It is not `user`, `pin` or `mfa`, because Nathan asks for WebAuthn user verification as `preferred`, not `required`.
- `nathan_acr: "urn:nathan:acr:passkey"`: the session was created by a verified passkey sign-in. **It is not MFA and not NIST AAL2.**
- `nathan_auth_time`: when that assertion was verified.

Social, enterprise OIDC/SAML, email and TOTP sign-ins produce no evidence row, so their tokens carry none of these claims. Nathan does not yet hold verified provider authentication-method evidence.

The standard `amr`, `acr` and `auth_time` names cannot be emitted on Better Auth 1.7.14 access tokens (see above), so Nathan uses its own names. Gatekeeper's `mfa` mapping reads only `acr` (plus `auth_time`), so **Nathan tokens never set `principal.mfa` in Gatekeeper.** Leave `mfa` out of the provider entry. Put step-up requirements in Gatekeeper policy only once Nathan has evidence for them.

## Set up a Gatekeeper audience

In Identity Studio, under **Access tokens for Gatekeeper and APIs** (all writes are admin-only, need the current step-up, are same-origin and audited):

1. **Register audience** with Gatekeeper's API URL (an exact `https` URL without query, fragment or percent-encoding), for example `https://gatekeeper.example.com/api`. To get a `roles` hint, bind it to an application (optional). Registering creates a Better Auth resource with a 900 s lifetime, the scopes `openid profile email offline_access nathan:api`, and no resource-level custom claims (which would outrank Nathan's). Nathan's own `/mcp`, `/directory` and `/api/auth` identifiers are refused.
2. **Allow client to request this audience** for every web, SPA or agent client whose users call Gatekeeper. A client that is not linked gets `invalid_target`.
3. For services, **create a machine or agent client** for the audience. It is a confidential client-credentials client with scope `nathan:api`, and its secret is shown once.
4. **Set principal kind** to `agent` for agent and MCP clients.

Removing an audience disables its Better Auth resource and deletes every client link to it, in one audited step (the audit target records how many links were removed). New tokens are refused, and issued tokens expire within 900 s. Registering the same identifier again starts with **no** linked clients: link each client again on purpose. A client that was linked before cannot get tokens for it, and an old refresh token cannot be refreshed into it.

API: `GET /studio/api/tokens` returns audiences, their linked clients and every client's kind. `POST /studio/api/tokens` takes an `op`: `audience.register` `{identifier, app?}`, `audience.remove` `{identifier, confirm: "CONFIRM REMOVE AUDIENCE <identifier>"}` (returns `unlinkedClients`), `audience.link` or `audience.unlink` `{identifier, clientId}`, `client.kind` `{clientId, kind: "agent" | "auto", confirm}` (`"auto"` needs `confirm: "CONFIRM CLASSIFY BY GRANT <clientId>"` because it widens the client), and `machine.create` `{name, audience, kind?: "machine" | "agent", confirm: "CONFIRM MACHINE CLIENT <name>"}`.

Token requests:

```http
# A user, through the client's normal authorization code + PKCE flow:
GET /api/auth/oauth2/authorize?response_type=code&client_id=…&redirect_uri=…&scope=openid%20profile
    &code_challenge=…&code_challenge_method=S256&state=…&resource=https%3A%2F%2Fgatekeeper.example.com%2Fapi
POST /api/auth/oauth2/token   grant_type=authorization_code&code=…&code_verifier=…&redirect_uri=…&resource=https://gatekeeper.example.com/api

# A machine or agent:
POST /api/auth/oauth2/token   Authorization: Basic base64(client_id:client_secret)
grant_type=client_credentials&scope=nathan:api&resource=https://gatekeeper.example.com/api
```

## Gatekeeper identity-provider entry

Paste this into Gatekeeper's `GATEKEEPER_IDENTITY_PROVIDERS` array. Replace `login.example.com` with your Nathan host and the audience with the one you registered. Nothing else changes per install. The runtime test `tests/runtime/gatekeeper-tokens.test.mjs` reads this exact block.

<!-- gatekeeper-provider-entry -->
```json
{
  "id": "nathan",
  "kind": "oidc",
  "issuer": "https://login.example.com/api/auth",
  "jwksUri": "https://login.example.com/api/auth/jwks",
  "audience": "https://gatekeeper.example.com/api",
  "algorithms": ["EdDSA"],
  "accessTokenProfile": { "kind": "rfc9068" },
  "kindClaim": { "name": "principal_kind", "values": { "user": "human", "machine": "service", "agent": "agent" } },
  "maxTokenLifetimeSeconds": 900
}
```

- `issuer` is Nathan's OIDC issuer, the origin plus `/api/auth`, exactly as in `<issuer>/.well-known/openid-configuration`. `jwksUri` is its `jwks_uri`.
- `algorithms`: Nathan signs with EdDSA. Add another algorithm only if you change the JWT plugin's key configuration.
- `accessTokenProfile`: RFC 9068. Gatekeeper requires `typ: at+jwt`, `client_id` and `jti`, which Better Auth always sets. ID tokens have no `typ` and are refused, even if an entry were misconfigured with the client id as audience. Nathan does not emit a `token_use` marker, so do not use the `jwt-access-token` profile.
- `kindClaim`: a claim only Nathan's issuer logic sets, never user-editable profile data. Anything else becomes `unknown` in Gatekeeper, never `human`.
- `maxTokenLifetimeSeconds`: 900 matches Nathan's cap.
- Leave out `mfa` (see above). `allowedClientIds` is optional if you want to pin which clients may call Gatekeeper. Leave out `handleClaim`: Nathan access tokens carry no email.

Gatekeeper's principal id is `principal:<url-encoded issuer>:sub:<url-encoded sub>`, without the kind (see [Policies must check the principal kind](#policies-must-check-the-principal-kind)). Nathan's directory subject is `<issuer>#<sub>` with the same issuer and `sub`.

## Remote MCP tokens

Tokens from Nathan's MCP authorization server ([remote-mcp.md](remote-mcp.md), NATH-14) follow this profile with the same issuer and keys: `aud` is the MCP server's resource URL, `principal_kind` is always `agent`, `sub` is the user, `scope` holds the scopes effective at issuance, and they live 300 s. To accept them in Gatekeeper, use the entry above with `audience` set to the MCP resource. Gatekeeper sees the signature only; the MCP server's `nathanMcp()` additionally checks the live grant, so a revoked connection stops there within 60 s and at Gatekeeper when the token expires.

## Roles: read the directory, not the token

Token `roles` are hints for simple apps that cannot call Nathan. They can be up to 900 s stale and cover only the audience's app. Gatekeeper's PIP must read authoritative roles from the directory:

1. Register a directory client (Studio, **Gatekeeper directory access**). Get a token with `grant_type=client_credentials&scope=nathan:directory.read&resource=https://login.example.com/directory`.
2. For a principal with Gatekeeper kind `human` or `agent`, call `GET https://login.example.com/directory/v1/principal?subject=<url-encoded issuer>%23<sub>`. Use `applications[<app>].roles` / `.permissions` / `.allowed`. A 404 means no roles.
3. Treat data older than `maxAgeSeconds` (30), or an unreachable directory, as indeterminate. Never fall back to token `roles`.
4. Optionally follow `GET /directory/v1/changes?cursor=…` to invalidate caches early. Re-read on 410.
5. For `service` principals (`sub` is a client id), the directory has nothing. Authorize them in Gatekeeper policy by `clientId` and scope.

The directory HTTP API is the only way to read it. The app-scoped `NathanVerifier` service binding has no directory methods, so a same-account Gatekeeper uses the HTTP API with its own client credentials too.

## Verification

`tests/runtime/gatekeeper-tokens.test.mjs` runs in workerd against the built identity Worker. It mints a user token (authorization code + PKCE), a machine token and an agent token from the real token endpoint, and checks header, claims, lifetime, roles and evidence. It verifies them with the entry above using **Gatekeeper's own resolver**: an unmodified copy of Gatekeeper's `packages/identity/jwt.ts` and its dependencies, pinned in `tests/vendor/gatekeeper` (commit and file hashes in `SOURCE.md`, checked by the test). So CI exercises Gatekeeper's real config parsing, signature and lifetime checks, RFC 9068 profile, per-scope format and 256-scope limit, kind mapping and `mfa` rule with `auth_time` freshness, without a Gatekeeper checkout. It also checks that:

- the ID token, a token for another audience and an expired token are refused;
- Alice's passkey evidence comes from a real passkey sign-in: a software WebAuthn authenticator (ES256) signs Better Auth's challenge, and the Worker's own after-hook on `/passkey/verify-authentication` writes the evidence row;
- refresh stops for a deleted or expired session and for a banned user, while an agent's delegated refresh continues without the session but not past a ban;
- `nathan:api` is refused to user delegations through clients not marked `agent`, explicit or by default, and allowed for agents;
- requests naming several audiences get `roles` only when all are bound to the same app;
- refreshed tokens, user grants without a resource and a resource with a longer stored lifetime are still capped at 900 s;
- removing an audience drops its client links, and after re-registering it the old clients get `invalid_target`.

Not yet verified: tokens from a deployed Nathan on Cloudflare, a deployed Gatekeeper, and sign-ins with a hardware or platform passkey in a real browser.
