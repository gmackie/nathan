/**
 * The account-token CLI's privileged writes (scripts/lib/admin-cli.mjs): `app enable`, `rbac
 * grant|revoke`, `mcp register|status` and `user find`, against the real migrations in node:sqlite
 * through a stand-in for the Cloudflare D1 REST API. Validation is the Studio path's own
 * (src/shared/admin-ops.mjs); these tests pin the refusals and the audit rows.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { grantRole, revokeRole, setAppStatus, registerMcp, setMcpStatus, findUserIds, commitPlan, flag } from "../scripts/lib/admin-cli.mjs";
import { syncApplicationRbac } from "../scripts/lib/rbac-wizard.mjs";

const ORIGIN = "https://login.example.com";
const ACTOR = "cli:acct";
const RESOURCE = "https://lms.example.com/mcp";
const yes = async () => true;
const app = {
  id: "lms", kind: "external", hostname: "lms.example.com",
  rbac: {
    permissions: {
      "lms:read": "Read", "lms:draft": "Draft", "lms:write": "Write", "mcp:tools": "Tools"
    },
    roles: { teacher: { permissions: ["lms:read", "lms:draft", "lms:write", "mcp:tools"] } }
  }
};

/** A Cloudflare D1 REST stand-in backed by node:sqlite with the real migrations; a batch is one transaction. */
function fakeApi() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort()) db.exec(readFileSync("migrations/" + file, "utf8"));
  const writes = [];
  const api = {
    db, writes, failBatch: false,
    async queryDatabase(_id, sql, params = []) {
      assert.ok(sql.length <= 5000 && params.length <= 10, "within the D1 REST helper's limits");
      if (!/^SELECT/i.test(sql)) writes.push(sql);
      return db.prepare(sql).all(...params);
    },
    async batchDatabase(_id, statements) {
      db.exec("BEGIN");
      try {
        const out = statements.map(s => { writes.push(s.sql); return db.prepare(s.sql).all(...s.params); });
        if (api.failBatch) throw Error("Cloudflare D1 batch failed");
        db.exec("COMMIT");
        return out;
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
  };
  return api;
}
const base = api => ({ api, databaseId: "db", actor: ACTOR });
const audits = api => api.db.prepare("SELECT actor, action, target, outcome FROM nathan_security_audit WHERE actor=? AND action NOT LIKE 'rbac_manifest%' AND action<>'application_upsert' ORDER BY rowid")
  .all(ACTOR).map(r => ({ ...r }));
function user(api, id, email, verified = 1) {
  api.db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)')
    .run(id, id, email, verified, new Date().toISOString(), new Date().toISOString());
}
async function seeded() {
  const api = fakeApi();
  await syncApplicationRbac({ api, databaseId: "db", app, actor: ACTOR, apply: true, confirm: yes });
  user(api, "user-1", "Teacher@Example.com");
  return api;
}

test("app enable is planned by default, needs Studio's typed confirmation, and writes Studio's audit and change-feed rows", async () => {
  const api = await seeded();
  const before = api.writes.length;
  const planned = await setAppStatus({ ...base(api), apply: false, id: "lms", enabled: true });
  assert.equal(planned.applied, false);
  assert.equal(api.writes.length, before, "a plan never writes");
  await assert.rejects(() => setAppStatus({ ...base(api), apply: true, id: "lms", enabled: true, confirmation: "yes" }), /Explicit confirmation required/);
  await assert.rejects(() => setAppStatus({ ...base(api), apply: true, id: "nope", enabled: true, confirmation: "CONFIRM ENABLE nope" }), /Unknown application/);
  await assert.rejects(() => setAppStatus({ ...base(api), apply: true, id: "Bad!", enabled: true, confirmation: "CONFIRM ENABLE Bad!" }), /Invalid application id/);
  const done = await setAppStatus({ ...base(api), apply: true, id: "lms", enabled: true, confirmation: "CONFIRM ENABLE lms" });
  assert.deepEqual(done.result, { id: "lms", enabled: true });
  assert.equal(api.db.prepare("SELECT enabled FROM nathan_applications WHERE id='lms'").get().enabled, 1);
  assert.deepEqual(audits(api).map(a => [a.action, a.target, a.outcome]), [["application_enable", "lms", "attempted"], ["application_enable", "lms", "succeeded"]]);
  assert.equal(api.db.prepare("SELECT actor FROM nathan_rbac_changes WHERE kind='app.enabled' AND app_id='lms'").get().actor, ACTOR);
});

test("rbac grant takes a user id or an email, refuses unknown apps, roles and users, and audits like Studio", async () => {
  const api = await seeded();
  const planned = await grantRole({ ...base(api), apply: false, app: "lms", role: "teacher", user: "user-1" });
  assert.equal(planned.applied, false);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants").get().n, 0, "a plan never grants");

  await assert.rejects(() => grantRole({ ...base(api), apply: true, app: "nope", role: "teacher", user: "user-1", confirm: yes }), /Unknown application/);
  await assert.rejects(() => grantRole({ ...base(api), apply: true, app: "lms", role: "admin", user: "user-1", confirm: yes }), /Unknown role/);
  await assert.rejects(() => grantRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "ghost", confirm: yes }), /User not found/);
  await assert.rejects(() => grantRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "ghost@example.com", confirm: yes }), /User not found/);
  await assert.rejects(() => grantRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "user-1", confirm: async () => false }), /Cancelled/);
  assert.deepEqual(audits(api).map(a => [a.action, a.target, a.outcome]), [
    ["rbac_grant_create", "nope:teacher", "rejected"], ["rbac_grant_create", "lms:admin", "rejected"],
    ["rbac_grant_create", "lms:teacher", "rejected"], ["rbac_grant_create", "lms:teacher", "rejected"]
  ], "refusals are audited 'rejected' with Studio's target; a declined confirmation writes nothing");

  const granted = await grantRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "teacher@example.com", confirm: yes });
  assert.equal(granted.result.principalId, "user-1");
  const row = api.db.prepare("SELECT app_id, role_key, principal_type, principal_id, created_by FROM nathan_rbac_grants").get();
  assert.deepEqual({ ...row }, { app_id: "lms", role_key: "teacher", principal_type: "user", principal_id: "user-1", created_by: ACTOR });
  assert.deepEqual(audits(api).slice(-2).map(a => [a.action, a.target, a.outcome]),
    [["rbac_grant_create", "lms:teacher:user:user-1", "attempted"], ["rbac_grant_create", "lms:teacher:user:user-1", "succeeded"]]);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_rbac_changes WHERE kind='grant.created' AND principal_id='user-1' AND actor=?").get(ACTOR).n, 1);

  const again = await grantRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "user-1", confirm: yes });
  assert.equal(again.applied, false);
  assert.equal(again.result.note, "Already granted");

  const revoked = await revokeRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "user-1", confirm: yes });
  assert.equal(revoked.result.revoked, true);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants").get().n, 0);
  assert.deepEqual(audits(api).at(-1), { actor: ACTOR, action: "rbac_grant_revoke", target: "lms:teacher:user:user-1", outcome: "succeeded" });
  await assert.rejects(() => revokeRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "user-1", confirm: yes }), /Unknown grant/);
});

test("a failed commit is rolled back and audited 'attempted' then 'failed'", async () => {
  const api = await seeded();
  api.failBatch = true;
  await assert.rejects(() => grantRole({ ...base(api), apply: true, app: "lms", role: "teacher", user: "user-1", confirm: yes }), /batch failed/);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants").get().n, 0);
  assert.deepEqual(audits(api).map(a => a.outcome), ["attempted", "failed"]);
});

const CATALOG = {
  name: "LMS",
  scopes: {
    "lms:read": { label: "Read", group: "lms" },
    "lms:draft": { label: "Draft", group: "lms", requires: ["lms:read"] },
    "lms:write": { label: "Write", group: "lms", sensitive: true }
  }
};

test("mcp register enforces the Studio identifier, audience and catalog rules", async () => {
  const api = await seeded();
  const register = body => registerMcp({ ...base(api), apply: true, issuerOrigin: ORIGIN, body: { identifier: RESOURCE, app: "lms", ...CATALOG, ...body }, confirm: yes });
  for (const [identifier, message] of [
    ["http://lms.example.com/mcp", /https only/],
    [RESOURCE + "?x=1", /without credentials, query or fragment/],
    ["https://LMS.example.com/mcp", /canonical form/],
    ["https://lms.example.com/m%63p", /Invalid audience/],
    [ORIGIN + "/mcp", /reserved by Nathan/],
    [ORIGIN + "/directory", /reserved by Nathan/],
    [ORIGIN + "/api/auth", /reserved by Nathan/],
    [ORIGIN + "/api/auth/oauth2/token", /reserved by Nathan/]
  ]) await assert.rejects(() => register({ identifier }), message, identifier);
  await assert.rejects(() => register({ app: "nope" }), /Unknown application/);
  await assert.rejects(() => register({ app: "Bad" }), /Invalid application id/);
  await assert.rejects(() => register({ name: "" }), /Invalid name/);
  await assert.rejects(() => register({ scopes: { "lms:delete": {} } }), /Unknown permission lms:delete/);
  await assert.rejects(() => register({ scopes: { "nathan:admin": {} } }), /reserved by Nathan/);
  await assert.rejects(() => register({ scopes: { "lms:draft": { requires: ["lms:write"] }, "lms:write": { sensitive: true } } }), /sensitive and never implied/);
  await assert.rejects(() => register({ full: "lms:read" }), /Full access marker/);

  // An identifier that is already a token audience (Nathan's or Better Auth's) is refused.
  api.db.prepare("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,?,?)").run("https://api.example.com", "lms", "admin");
  await assert.rejects(() => register({ identifier: "https://api.example.com" }), /already a token audience/);
  api.db.prepare('INSERT INTO "oauthResource"("id","identifier","name","createdAt","updatedAt") VALUES (?,?,?,?,?)').run("r1", "https://ba.example.com/api", "BA", new Date().toISOString(), new Date().toISOString());
  await assert.rejects(() => register({ identifier: "https://ba.example.com/api" }), /already a Better Auth token audience/);
  assert.equal(api.writes.filter(w => /nathan_mcp_resources/.test(w)).length, 0, "refusals write nothing");
  assert.deepEqual(audits(api), [], "MCP refusals are not audited, as in Studio");

  const planned = await registerMcp({ ...base(api), apply: false, issuerOrigin: ORIGIN, body: { identifier: RESOURCE, app: "lms", ...CATALOG } });
  assert.equal(planned.applied, false);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_mcp_resources").get().n, 0, "a plan never registers");

  const done = await register({});
  assert.equal(done.applied, true);
  const resource = api.db.prepare("SELECT app_id, name, enabled, created_by FROM nathan_mcp_resources WHERE identifier=?").get(RESOURCE);
  assert.deepEqual({ ...resource }, { app_id: "lms", name: "LMS", enabled: 1, created_by: ACTOR });
  assert.equal(api.db.prepare("SELECT app_id FROM nathan_token_audiences WHERE identifier=?").get(RESOURCE).app_id, "lms");
  assert.deepEqual(api.db.prepare("SELECT scope, sensitive, requires FROM nathan_mcp_scopes WHERE resource=? ORDER BY scope").all(RESOURCE).map(r => ({ ...r })), [
    { scope: "lms:draft", sensitive: 0, requires: '["lms:read"]' },
    { scope: "lms:read", sensitive: 0, requires: "[]" },
    { scope: "lms:write", sensitive: 1, requires: "[]" }
  ]);
  assert.deepEqual(audits(api).map(a => [a.action, a.target, a.outcome]), [
    ["mcp_resource_register", RESOURCE + " app=lms", "attempted"], ["mcp_resource_register", RESOURCE + " app=lms", "succeeded"]
  ]);
  // Re-registering an MCP server (its own audience) updates it.
  await register({ name: "LMS 2", scopes: {} });
  assert.equal(api.db.prepare("SELECT name FROM nathan_mcp_resources WHERE identifier=?").get(RESOURCE).name, "LMS 2");
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_mcp_scopes WHERE resource=?").get(RESOURCE).n, 0);
});

test("mcp status needs Studio's typed confirmation and an existing server", async () => {
  const api = await seeded();
  await registerMcp({ ...base(api), apply: true, issuerOrigin: ORIGIN, body: { identifier: RESOURCE, app: "lms", ...CATALOG }, confirm: yes });
  const status = (identifier, enabled, confirmation) => setMcpStatus({ ...base(api), apply: true, issuerOrigin: ORIGIN, identifier, enabled, confirmation });
  await assert.rejects(() => status("https://other.example.com/mcp", false, "CONFIRM DISABLE MCP https://other.example.com/mcp"), /Unknown MCP resource/);
  await assert.rejects(() => status(ORIGIN + "/mcp", false, "CONFIRM DISABLE MCP " + ORIGIN + "/mcp"), /reserved by Nathan/);
  await assert.rejects(() => status(RESOURCE, false, "yes"), /Explicit confirmation required/);
  await status(RESOURCE, false, "CONFIRM DISABLE MCP " + RESOURCE);
  assert.equal(api.db.prepare("SELECT enabled FROM nathan_mcp_resources WHERE identifier=?").get(RESOURCE).enabled, 0);
  await status(RESOURCE, true, "CONFIRM ENABLE MCP " + RESOURCE);
  assert.equal(api.db.prepare("SELECT enabled FROM nathan_mcp_resources WHERE identifier=?").get(RESOURCE).enabled, 1);
  assert.deepEqual(audits(api).filter(a => a.action === "mcp_resource_status").map(a => [a.target, a.outcome]), [
    [RESOURCE + " enabled=false", "attempted"], [RESOURCE + " enabled=false", "succeeded"],
    [RESOURCE + " enabled=true", "attempted"], [RESOURCE + " enabled=true", "succeeded"]
  ]);
});

test("user find prints ids only and is read-only", async () => {
  const api = await seeded();
  const before = api.writes.length;
  assert.deepEqual(await findUserIds({ ...base(api), email: " TEACHER@example.com " }), ["user-1"]);
  assert.deepEqual(await findUserIds({ ...base(api), email: "nobody@example.com" }), []);
  await assert.rejects(() => findUserIds({ ...base(api), email: "not-an-email" }), /exact email/);
  assert.equal(api.writes.length, before);
});

test("commitPlan refuses to write without --apply or confirmation", async () => {
  const api = fakeApi();
  const plan = { action: "x", target: "y", statements: [{ sql: "SELECT 1", params: [] }], result: {} };
  assert.equal((await commitPlan({ ...base(api), plan, apply: false })).applied, false);
  await assert.rejects(() => commitPlan({ ...base(api), plan, apply: true }), /Cancelled/);
  assert.deepEqual(api.writes, []);
});

test("flag values are required and never taken from the next flag", () => {
  assert.equal(flag(["grant", "--user", "u1"], "--user"), "u1");
  assert.equal(flag(["grant"], "--user"), undefined);
  assert.throws(() => flag(["grant", "--user", "--apply"], "--user"), /needs a value/);
});

test("Studio and the CLI share one implementation of these writes", () => {
  const rbac = readFileSync("src/auth/rbac.ts", "utf8");
  const mcp = readFileSync("src/auth/mcp-oauth.ts", "utf8");
  const admin = readFileSync("src/auth/admin-service.ts", "utf8");
  assert.match(rbac, /adminOps\.planGrantCreate\(/);
  assert.match(rbac, /adminOps\.planGrantRevoke\(/);
  assert.doesNotMatch(rbac, /INSERT INTO nathan_rbac_grants/, "the grant statement lives only in src/shared/admin-ops.mjs");
  assert.match(mcp, /planMcpRegister\(/);
  assert.match(mcp, /planMcpStatus\(/);
  assert.doesNotMatch(mcp, /INSERT INTO nathan_mcp_resources/, "the registration statements live only in src/shared/admin-ops.mjs");
  assert.match(admin, /planAppStatus\(/);
  assert.doesNotMatch(admin, /UPDATE nathan_applications SET enabled/);
});
