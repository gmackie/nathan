import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { validateConfig } from "../scripts/lib/config.mjs";
import { syncApplicationRbac } from "../scripts/lib/rbac-wizard.mjs";
import { gatewayChecklist } from "../scripts/lib/protect-wizard.mjs";

const example = JSON.parse(readFileSync("nathan.config.example.json", "utf8"));
const dashboard = example.applications.find(a => a.id === "dashboard");

/** A Cloudflare D1 REST stand-in backed by node:sqlite with the real migrations. */
function fakeApi() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort()) db.exec(readFileSync("migrations/" + file, "utf8"));
  const queries = [];
  return {
    db, queries,
    async queryDatabase(_id, sql, params = []) {
      assert.ok(sql.length <= 5000 && params.length <= 10, "within the D1 REST helper's limits");
      queries.push(sql);
      return db.prepare(sql).all(...params);
    }
  };
}

test("the example config declares permissions and roles as code and validates", () => {
  assert.deepEqual(validateConfig(example), []);
  assert.ok(dashboard.rbac.permissions["invoices:write"]);
});

test("config validation reports invalid RBAC manifests per application", () => {
  const broken = structuredClone(example);
  broken.applications.find(a => a.id === "dashboard").rbac.roles.editor.permissions.push("undeclared:perm");
  assert.match(validateConfig(broken).join(" "), /dashboard: Invalid RBAC manifest/);
});

test("rbac plan is read-only; sync registers a missing app disabled and applies the plan as the CLI actor", async () => {
  const api = fakeApi();
  const planned = await syncApplicationRbac({ api, databaseId: "db", app: dashboard, actor: "cli:acct", apply: false });
  assert.equal(planned.registered, false);
  assert.ok(planned.ops.length > 0);
  assert.ok(api.queries.every(q => /^SELECT/i.test(q)), "plan never writes");

  const applied = await syncApplicationRbac({ api, databaseId: "db", app: dashboard, actor: "cli:acct", apply: true, confirm: async () => true });
  assert.equal(applied.registered, true);
  const app = api.db.prepare("SELECT enabled, access_mode AS m FROM nathan_applications WHERE id='dashboard'").get();
  assert.deepEqual({ ...app }, { enabled: 0, m: "approved" }, "registered disabled and deny-by-default");
  assert.deepEqual(api.db.prepare("SELECT key FROM nathan_rbac_roles WHERE app_id='dashboard' ORDER BY key").all().map(r => r.key), ["editor", "viewer"]);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE actor='cli:acct' AND action='rbac_manifest_sync'").get().n, 1);
  const again = await syncApplicationRbac({ api, databaseId: "db", app: dashboard, actor: "cli:acct", apply: true, confirm: async () => true });
  assert.deepEqual(again.ops, [], "idempotent");
});

test("sync stops without writing when the operator declines, and never grants access", async () => {
  const api = fakeApi();
  await assert.rejects(() => syncApplicationRbac({ api, databaseId: "db", app: dashboard, actor: "cli:acct", apply: true, confirm: async () => false }), /Cancelled/);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_rbac_roles").get().n, 0);
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_applications").get().n, 0);
  await syncApplicationRbac({ api, databaseId: "db", app: dashboard, actor: "cli:acct", apply: true, confirm: async () => true });
  assert.equal(api.db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants").get().n, 0);
});

test("an app without an rbac section or hostname cannot be synced", async () => {
  await assert.rejects(() => syncApplicationRbac({ api: fakeApi(), databaseId: "db", app: { id: "x", kind: "worker" }, actor: "cli:a", apply: false }), /rbac/);
  await assert.rejects(() => syncApplicationRbac({ api: fakeApi(), databaseId: "db", app: { id: "x", kind: "worker", rbac: dashboard.rbac }, actor: "cli:a", apply: true, confirm: async () => true }), /hostname/);
});

test("the protect checklist names the signed principal and the upstream secrets", () => {
  const plan = gatewayChecklist({ hostname: "login.example.com" }, dashboard);
  assert.equal(plan.principal.header, "X-Nathan-Principal");
  assert.deepEqual(plan.principal.upstreamBindings, ["NATHAN_PRINCIPAL_KEY (secret)", "NATHAN_APPLICATION_ID=dashboard", "NATHAN_GATEWAY_ORIGIN=https://app.example.com"]);
  assert.match(plan.principal.next, /rbac sync dashboard/);
});
