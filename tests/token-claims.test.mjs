import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import {
  principalKind, evidenceClaims, rolesClaim, audienceApp, validateAudience, PASSKEY_ACR, MAX_ACCESS_TOKEN_SECONDS, API_SCOPE,
  liveSession, userBanned, apiScopeAllowed, timestampMs
} from "../src/shared/token-claims.mjs";

test("principal kind: a human session is a user, a client-credentials grant is a machine, an admin-marked client is an agent", () => {
  assert.equal(principalKind({ hasUser: true }), "user");
  assert.equal(principalKind({ hasUser: false }), "machine");
  assert.equal(principalKind({ hasUser: false, clientKind: "agent" }), "agent");
  assert.equal(principalKind({ hasUser: true, clientKind: "agent" }), "agent", "an agent acting for a user is still an agent");
  // Unclassified input must never become a user.
  for (const input of [{}, { hasUser: "yes" }, { hasUser: 1 }, { hasUser: undefined, clientKind: "user" }, { hasUser: false, clientKind: "user" }])
    assert.notEqual(principalKind(input), "user", JSON.stringify(input));
  assert.equal(principalKind({ hasUser: false, clientKind: "human" }), "machine", "an unknown client attribute is ignored");
});

test("authentication-method claims come only from verified passkey sign-in evidence for this session and user", () => {
  const row = { session_id: "s1", user_id: "u1", method: "passkey", verified_at: 1_800_000_000 };
  assert.deepEqual(evidenceClaims(row, { userId: "u1", sessionId: "s1" }),
    { nathan_amr: ["pop"], nathan_acr: PASSKEY_ACR, nathan_auth_time: 1_800_000_000 });
  assert.deepEqual(evidenceClaims(null, { userId: "u1", sessionId: "s1" }), {});
  assert.deepEqual(evidenceClaims(row, { userId: "u2", sessionId: "s1" }), {}, "another user's evidence");
  assert.deepEqual(evidenceClaims(row, { userId: "u1", sessionId: "s2" }), {}, "another session's evidence");
  assert.deepEqual(evidenceClaims(row, { userId: "u1" }), {}, "no session (client credentials or a deleted session)");
  assert.deepEqual(evidenceClaims({ ...row, method: "totp" }, { userId: "u1", sessionId: "s1" }), {});
  assert.deepEqual(evidenceClaims({ ...row, verified_at: "soon" }, { userId: "u1", sessionId: "s1" }), {});
  assert.deepEqual(evidenceClaims({ ...row, verified_at: 0 }, { userId: "u1", sessionId: "s1" }), {});
  // Never the reserved RFC 9068 / OIDC names that would imply verified AAL or MFA.
  for (const key of ["amr", "acr", "auth_time"]) assert.ok(!(key in evidenceClaims(row, { userId: "u1", sessionId: "s1" })));
});

test("the roles claim is a hint: present only for an allowed principal with roles", () => {
  assert.deepEqual(rolesClaim({ allowed: true, roles: ["viewer", "editor"] }), ["editor", "viewer"]);
  assert.equal(rolesClaim({ allowed: true, roles: [] }), undefined);
  assert.equal(rolesClaim({ allowed: false, roles: ["editor"] }), undefined);
  assert.equal(rolesClaim(null), undefined);
  assert.equal(rolesClaim({ allowed: true, roles: ["ok", 7] }), undefined, "malformed evaluator output omits the claim");
});

test("a token's app: every requested resource must be a registered audience bound to the same app", () => {
  const billing = { identifier: "https://a", app_id: "billing" };
  assert.equal(audienceApp([billing], ["https://a"]), "billing");
  assert.equal(audienceApp([billing, { identifier: "https://b", app_id: "billing" }], ["https://a", "https://b"]), "billing");
  // An unbound second audience must not receive the first audience's app roles.
  assert.equal(audienceApp([billing, { identifier: "https://b", app_id: null }], ["https://a", "https://b"]), null, "unbound second audience");
  assert.equal(audienceApp([billing, { identifier: "https://b", app_id: "crm" }], ["https://a", "https://b"]), null, "differently bound");
  // A requested resource that is not a registered audience (Nathan's /mcp, say) is not bound to the app either.
  assert.equal(audienceApp([billing], ["https://a", "https://login.example.com/mcp"]), null, "unregistered second resource");
  assert.equal(audienceApp([billing, billing], ["https://a", "https://a"]), "billing", "a repeated resource is one audience");
  assert.equal(audienceApp([], []), null);
  assert.equal(audienceApp([billing], []), null, "no requested resource");
  assert.equal(audienceApp([{ identifier: "https://a", app_id: null }], ["https://a"]), null);
  assert.equal(audienceApp([billing]), null, "no resource list");
  assert.equal(audienceApp(null, ["https://a"]), null);
});

test("a user token needs a live, unexpired session of the same user", () => {
  const now = 1_800_000_000_000;
  const row = { id: "s1", userId: "u1", expiresAt: new Date(now + 60_000).toISOString() };
  assert.equal(liveSession(row, { userId: "u1", sessionId: "s1", now }), true);
  assert.equal(liveSession(null, { userId: "u1", sessionId: "s1", now }), false, "deleted or revoked session");
  assert.equal(liveSession(row, { userId: "u1", sessionId: undefined, now }), false, "grant without a session (sid null after deletion)");
  assert.equal(liveSession(row, { userId: "u2", sessionId: "s1", now }), false, "another user's session");
  assert.equal(liveSession(row, { userId: "u1", sessionId: "s2", now }), false, "another session");
  assert.equal(liveSession({ ...row, expiresAt: new Date(now - 1).toISOString() }, { userId: "u1", sessionId: "s1", now }), false, "expired");
  assert.equal(liveSession({ ...row, expiresAt: now + 60_000 }, { userId: "u1", sessionId: "s1", now }), true, "epoch milliseconds");
  assert.equal(liveSession({ ...row, expiresAt: "soon" }, { userId: "u1", sessionId: "s1", now }), false, "unparseable expiry");
  assert.equal(liveSession({ ...row, expiresAt: null }, { userId: "u1", sessionId: "s1", now }), false);
});

test("a banned user gets no new tokens until the ban expires", () => {
  const now = 1_800_000_000_000;
  assert.equal(userBanned({ banned: 1, banExpires: null }, now), true);
  assert.equal(userBanned({ banned: true }, now), true);
  assert.equal(userBanned({ banned: 1, banExpires: new Date(now + 1000).toISOString() }, now), true);
  assert.equal(userBanned({ banned: 1, banExpires: new Date(now - 1000).toISOString() }, now), false, "expired ban");
  assert.equal(userBanned({ banned: 0 }, now), false);
  assert.equal(userBanned({ banned: null }, now), false);
  assert.equal(userBanned(null, now), true, "a missing user row is treated as banned");
  assert.equal(timestampMs("2026-01-01T00:00:00.000Z"), Date.UTC(2026, 0, 1));
  assert.equal(timestampMs(1_800_000_000), 1_800_000_000_000, "epoch seconds");
  assert.ok(Number.isNaN(timestampMs(undefined)));
});

test("nathan:api is for client credentials and administrator-marked agents, never a plain user delegation", () => {
  assert.equal(apiScopeAllowed({ hasUser: false, clientKind: undefined, scopes: [API_SCOPE] }), true, "machine");
  assert.equal(apiScopeAllowed({ hasUser: false, clientKind: "agent", scopes: [API_SCOPE] }), true, "agent, client credentials");
  assert.equal(apiScopeAllowed({ hasUser: true, clientKind: "agent", scopes: ["openid", API_SCOPE] }), true, "agent acting for a user");
  assert.equal(apiScopeAllowed({ hasUser: true, clientKind: undefined, scopes: ["openid", API_SCOPE] }), false, "user delegation");
  assert.equal(apiScopeAllowed({ hasUser: true, clientKind: "human", scopes: [API_SCOPE] }), false, "unknown attribute");
  assert.equal(apiScopeAllowed({ hasUser: true, clientKind: undefined, scopes: ["openid", "profile"] }), true, "no nathan:api");
  assert.equal(apiScopeAllowed({ hasUser: true, clientKind: undefined, scopes: "openid nathan:api" }), false, "space-separated string");
});

test("token audiences are exact HTTPS resource identifiers that cannot shadow Nathan's own resources", () => {
  const origin = "https://login.example.com";
  assert.equal(validateAudience("https://gatekeeper.example.com/api", origin), "https://gatekeeper.example.com/api");
  for (const bad of ["http://gatekeeper.example.com/api", "https://gatekeeper.example.com/api#x", "https://u:p@gatekeeper.example.com/",
    "https://gatekeeper.example.com/api?x=1", "gatekeeper", "", "https://" + "a".repeat(600) + ".com",
    origin + "/mcp", origin + "/directory", origin + "/api/auth", origin + "/api/auth/oauth2/userinfo", "https://Gatekeeper.example.com/api",
    "https://gatekeeper.example.com/a b", "https://gatekeeper.example.com/a%2Fb", 42, null])
    assert.throws(() => validateAudience(bad, origin), /audience/i, String(bad));
});

test("the profile constants match Gatekeeper's defaults", () => {
  assert.equal(MAX_ACCESS_TOKEN_SECONDS, 900);
  assert.equal(API_SCOPE, "nathan:api");
});

test("migration 0014 stores audiences and admin-set client kinds; only 'agent' is a client kind", () => {
  const migrations = readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort();
  assert.equal(migrations.filter(f => f.startsWith("0014")).length, 1);
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of migrations) db.exec(readFileSync("migrations/" + file, "utf8"));
  db.prepare("INSERT INTO nathan_applications(id,hostname) VALUES ('billing','billing.example.test')").run();
  db.prepare("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES ('https://gk.example/api','billing','admin')").run();
  db.prepare('INSERT INTO "oauthClient"("id","clientId","redirectUris","createdAt","updatedAt") VALUES (\'c\',\'client-1\',\'[]\',0,0)').run();
  db.prepare("INSERT INTO nathan_client_principals(client_id,principal_kind,set_by) VALUES ('client-1','agent','admin')").run();
  assert.throws(() => db.prepare("INSERT INTO nathan_client_principals(client_id,principal_kind,set_by) VALUES ('client-1','user','admin')").run());
  db.prepare('DELETE FROM "oauthClient" WHERE "clientId"=\'client-1\'').run();
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_client_principals").get().n, 0, "deleting the client deletes its kind");
  db.prepare("DELETE FROM nathan_applications WHERE id='billing'").run();
  assert.equal(db.prepare("SELECT app_id FROM nathan_token_audiences").get().app_id, null, "deleting the app unbinds the audience");
});
