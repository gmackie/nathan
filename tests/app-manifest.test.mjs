/**
 * Per-application manifests (`nathan app apply`): one file in the app's own repository, applied
 * to the shared IdP through the same operations as the single commands.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { applyAppManifest, validateAppManifest, requiredConfirmations } from "../scripts/lib/app-manifest.mjs";

const ORIGIN = "https://login.example.com";
const ACTOR = "cli:acct";
const RESOURCE = "https://lms.example.com/mcp";
const MANIFEST = {
  id: "lms", hostname: "lms.example.com", enabled: true,
  rbac: {
    permissions: { "lms:read": "Read", "lms:draft": "Draft", "lms:write": "Write", "mcp:tools": "Tools" },
    roles: { teacher: { description: "Teacher", permissions: ["lms:read", "lms:draft", "lms:write", "mcp:tools"] } }
  },
  mcp: [{
    identifier: RESOURCE, name: "LMS",
    scopes: { "lms:draft": { requires: ["lms:read"] }, "lms:write": { sensitive: true } }
  }]
};

function fakeApi() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort()) db.exec(readFileSync("migrations/" + file, "utf8"));
  const api = {
    db, writes: [], failOn: null,
    async queryDatabase(_id, sql, params = []) {
      if (!/^SELECT/i.test(sql)) api.writes.push(sql);
      return db.prepare(sql).all(...params);
    },
    async batchDatabase(_id, statements) {
      if (api.failOn && statements.some(s => api.failOn.test(s.sql))) throw Error("Cloudflare D1 batch failed");
      db.exec("BEGIN");
      try { const out = statements.map(s => { api.writes.push(s.sql); return db.prepare(s.sql).all(...s.params); }); db.exec("COMMIT"); return out; }
      catch (error) { db.exec("ROLLBACK"); throw error; }
    }
  };
  return api;
}
const run = (api, extra = {}) => applyAppManifest({
  api, databaseId: "db", actor: ACTOR, issuerOrigin: ORIGIN, manifest: MANIFEST, apply: true,
  confirm: async plan => ({ confirmations: Object.fromEntries(requiredConfirmations(plan).map(c => [c, c])) }), ...extra
});

test("a manifest is validated before anything is read or written", () => {
  assert.throws(() => validateAppManifest({ ...MANIFEST, grants: [] }, ORIGIN), /grants are never part of a manifest/);
  assert.throws(() => validateAppManifest({ ...MANIFEST, id: "Bad" }, ORIGIN), /id must be/);
  assert.throws(() => validateAppManifest({ ...MANIFEST, hostname: "https://x" }, ORIGIN), /hostname/);
  assert.throws(() => validateAppManifest({ ...MANIFEST, extra: 1 }, ORIGIN), /unsupported field extra/);
  assert.throws(() => validateAppManifest({ ...MANIFEST, mcp: [{ identifier: ORIGIN + "/mcp", name: "x" }] }, ORIGIN), /reserved by Nathan/);
  assert.throws(() => validateAppManifest({ ...MANIFEST, mcp: [MANIFEST.mcp[0], MANIFEST.mcp[0]] }, ORIGIN), /duplicate/);
  assert.throws(() => validateAppManifest({ ...MANIFEST, rbac: { permissions: {}, roles: { x: { permissions: ["a:b"] } } } }, ORIGIN), /undeclared permission/);
});

test("the plan for a new app is read-only and already checks the MCP catalog against the manifest's permissions", async () => {
  const api = fakeApi();
  const { applied, plan } = await applyAppManifest({ api, databaseId: "db", actor: ACTOR, issuerOrigin: ORIGIN, manifest: MANIFEST, apply: false });
  assert.equal(applied, false);
  assert.equal(plan.register, true);
  assert.deepEqual(plan.mcp, [{ identifier: RESOURCE, register: "create" }]);
  assert.equal(plan.setEnabled, true);
  assert.deepEqual(requiredConfirmations(plan), ["CONFIRM ENABLE lms"]);
  assert.deepEqual(api.writes, []);
  const bad = structuredClone(MANIFEST);
  bad.mcp[0].scopes = { "lms:delete": {} };
  await assert.rejects(() => applyAppManifest({ api, databaseId: "db", actor: ACTOR, issuerOrigin: ORIGIN, manifest: bad, apply: false }), /Unknown permission lms:delete/);
});

test("apply registers, syncs, registers the MCP server and enables the app last, all audited as the CLI", async () => {
  const declined = fakeApi();
  await assert.rejects(() => run(declined, { confirm: async () => false }), /Cancelled/);
  assert.deepEqual(declined.writes, [], "a declined plan writes nothing");
  await assert.rejects(() => run(declined, { confirm: async () => ({ confirmations: {} }) }), /Explicit confirmation required/);
  // Without the typed enable confirmation the apply stops before enabling, and says so.
  assert.equal(declined.db.prepare("SELECT enabled FROM nathan_applications WHERE id='lms'").get().enabled, 0);
  assert.equal(declined.db.prepare("SELECT outcome FROM nathan_security_audit WHERE action='app_manifest_apply' ORDER BY rowid DESC LIMIT 1").get().outcome, "partial");

  const api = fakeApi();
  await run(api);
  assert.equal(api.db.prepare("SELECT enabled FROM nathan_applications WHERE id='lms'").get().enabled, 1);
  assert.deepEqual(api.db.prepare("SELECT permission_key FROM nathan_rbac_role_permissions WHERE app_id='lms' AND role_key='teacher' ORDER BY 1").all().map(r => r.permission_key),
    ["lms:draft", "lms:read", "lms:write", "mcp:tools"]);
  assert.deepEqual({ ...api.db.prepare("SELECT app_id, enabled FROM nathan_mcp_resources WHERE identifier=?").get(RESOURCE) }, { app_id: "lms", enabled: 1 });
  assert.equal(api.db.prepare("SELECT sensitive FROM nathan_mcp_scopes WHERE resource=? AND scope='lms:write'").get(RESOURCE).sensitive, 1);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants").get().n, 0, "a manifest never grants");
  const actions = api.db.prepare("SELECT action, outcome FROM nathan_security_audit WHERE actor=? ORDER BY rowid").all(ACTOR).map(r => r.action + ":" + r.outcome);
  const lastApply = actions.lastIndexOf("app_manifest_apply:attempted");
  assert.deepEqual(actions.slice(lastApply), ["app_manifest_apply:attempted",
    "rbac_manifest_sync:attempted", "application_upsert:succeeded", "rbac_manifest_sync:succeeded",
    "mcp_resource_register:attempted", "mcp_resource_register:succeeded",
    "application_enable:attempted", "application_enable:succeeded",
    "app_manifest_apply:succeeded"], "each step audited in order, enabling last");

  const again = await applyAppManifest({ api, databaseId: "db", actor: ACTOR, issuerOrigin: ORIGIN, manifest: MANIFEST, apply: false });
  assert.deepEqual({ rbac: again.plan.rbac, register: again.plan.register, setEnabled: again.plan.setEnabled }, { rbac: [], register: false, setEnabled: undefined });
  assert.deepEqual(again.plan.mcp, [{ identifier: RESOURCE, register: "update" }]);
});

test("a manifest disables an MCP server with Studio's typed confirmation, and a failure part-way is audited partial", async () => {
  const api = fakeApi();
  await run(api);
  const off = structuredClone(MANIFEST);
  off.mcp[0].enabled = false;
  const { plan } = await applyAppManifest({ api, databaseId: "db", actor: ACTOR, issuerOrigin: ORIGIN, manifest: off, apply: false });
  assert.deepEqual(requiredConfirmations(plan), ["CONFIRM DISABLE MCP " + RESOURCE]);
  await run(api, { manifest: off });
  assert.equal(api.db.prepare("SELECT enabled FROM nathan_mcp_resources WHERE identifier=?").get(RESOURCE).enabled, 0);

  api.failOn = /nathan_mcp_resources/;
  await assert.rejects(() => run(api, { manifest: { ...MANIFEST, rbac: { ...MANIFEST.rbac, permissions: { ...MANIFEST.rbac.permissions, "lms:grade": "Grade" } } } }), /batch failed/);
  const last = api.db.prepare("SELECT target, outcome FROM nathan_security_audit WHERE action='app_manifest_apply' ORDER BY rowid DESC LIMIT 1").get();
  assert.deepEqual({ ...last }, { target: "lms (stopped at mcp " + RESOURCE + ")", outcome: "partial" });
});
