import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { validateManifest, currentStateQueries, currentState, planSync, syncStatements } from "../src/shared/rbac-manifest.mjs";
import { accessQueries, decideFromRows } from "../src/shared/rbac-store.mjs";

const manifest = {
  permissions: { "invoices:read": "Read invoices", "invoices:write": "Create and edit invoices" },
  roles: {
    viewer: { description: "Read-only", permissions: ["invoices:read"] },
    editor: { description: "Edit invoices", permissions: ["invoices:read", "invoices:write"] }
  }
};

function database() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort()) db.exec(readFileSync("migrations/" + file, "utf8"));
  db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)').run("u1", "U", "u1@example.test", 1, 0, 0);
  db.prepare("INSERT INTO nathan_applications(id,hostname,enabled) VALUES ('billing','billing.example.test',1)").run();
  return db;
}
const run = (db, statements) => statements.map(s => db.prepare(s.sql).all(...s.params));
const state = db => currentState(run(db, currentStateQueries("billing")));
const sync = (db, value, options = {}) => {
  const ops = planSync(state(db), validateManifest(value), options);
  run(db, syncStatements("billing", ops, "cli:test"));
  return ops;
};

test("manifest validation accepts the documented format and normalizes it", () => {
  const normalized = validateManifest({ ...manifest, accessMode: "approved" });
  assert.equal(normalized.accessMode, "approved");
  assert.deepEqual(normalized.permissions.map(p => p.key), ["invoices:read", "invoices:write"]);
  assert.deepEqual(normalized.roles.find(r => r.key === "editor").permissions, ["invoices:read", "invoices:write"]);
  assert.equal(validateManifest({ permissions: {}, roles: {} }).accessMode, undefined);
});

test("manifest validation rejects anything ambiguous", () => {
  const bad = [
    null, [], "x", {},
    { permissions: [], roles: {} },
    { permissions: { "Invoices:Write": "x" }, roles: {} },
    { permissions: { "invoices:*": "x" }, roles: {} },
    { permissions: { "a:b": 7 }, roles: {} },
    { permissions: { "a:b": "bad\u0000desc" }, roles: {} },
    { permissions: { "a:b": "x".repeat(201) }, roles: {} },
    { permissions: {}, roles: { Admin: { permissions: [] } } },
    { permissions: {}, roles: { admin: { permissions: ["undeclared:perm"] } } },
    { permissions: {}, roles: { admin: { permissions: "a:b" } } },
    { permissions: {}, roles: {}, accessMode: "everyone" },
    { permissions: {}, roles: {}, grants: [] },
    { permissions: Object.fromEntries(Array.from({ length: 257 }, (_, i) => ["p" + i + ":x", ""])), roles: {} }
  ];
  for (const value of bad) assert.throws(() => validateManifest(value), /manifest/i, JSON.stringify(value)?.slice(0, 80));
});

test("sync creates permissions and roles as code, audits and records the change feed", () => {
  const db = database();
  const ops = sync(db, manifest);
  assert.deepEqual(ops.map(o => o.op), ["permission.upsert", "permission.upsert", "role.upsert", "role.upsert"]);
  assert.deepEqual(db.prepare("SELECT key, source FROM nathan_rbac_roles ORDER BY key").all().map(r => [r.key, r.source]), [["editor", "code"], ["viewer", "code"]]);
  db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g','billing','editor','user','u1','t')");
  assert.deepEqual(decideFromRows(run(db, accessQueries("billing", "u1"))).permissions, ["invoices:read", "invoices:write"]);
  const audit = db.prepare("SELECT actor, action, target, outcome FROM nathan_security_audit WHERE action='rbac_manifest_sync'").all();
  assert.deepEqual(audit.map(a => ({ ...a })), [{ actor: "cli:test", action: "rbac_manifest_sync", target: "billing", outcome: "succeeded" }]);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_rbac_changes WHERE app_id='billing' AND actor='cli:test'").get().n, 4);
});

test("sync is idempotent and only changes what differs", () => {
  const db = database();
  sync(db, manifest);
  assert.deepEqual(planSync(state(db), validateManifest(manifest)), []);
  const changed = structuredClone(manifest);
  changed.roles.viewer.permissions = ["invoices:read", "invoices:write"];
  changed.permissions["invoices:read"] = "View invoices";
  const ops = sync(db, changed);
  assert.deepEqual(ops.map(o => o.op + ":" + o.key), ["permission.upsert:invoices:read", "role.upsert:viewer"]);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_rbac_role_permissions WHERE role_key='viewer'").get().n, 2);
  assert.deepEqual(planSync(state(db), validateManifest(changed)), []);
});

test("removed entries are pruned only with prune, and only when they came from code", () => {
  const db = database();
  sync(db, manifest);
  db.exec("INSERT INTO nathan_rbac_roles(app_id,key,source) VALUES ('billing','studio-made','studio')");
  db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g','billing','editor','user','u1','t')");
  const smaller = { permissions: { "invoices:read": "Read invoices" }, roles: { viewer: manifest.roles.viewer } };
  assert.deepEqual(planSync(state(db), validateManifest(smaller)), []);
  const ops = sync(db, smaller, { prune: true });
  assert.deepEqual(ops.map(o => o.op + ":" + o.key), ["role.delete:editor", "permission.delete:invoices:write"]);
  assert.deepEqual(db.prepare("SELECT key FROM nathan_rbac_roles ORDER BY key").all().map(r => r.key), ["studio-made", "viewer"]);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants").get().n, 0, "a pruned role takes its grants with it");
});

test("access mode changes only when the manifest states it", () => {
  const db = database();
  sync(db, manifest);
  assert.equal(db.prepare("SELECT access_mode AS m FROM nathan_applications").get().m, "approved");
  const ops = sync(db, { ...manifest, accessMode: "any_signed_in" });
  assert.deepEqual(ops, [{ op: "access_mode", key: "any_signed_in", accessMode: "any_signed_in" }]);
  assert.equal(db.prepare("SELECT access_mode AS m FROM nathan_applications").get().m, "any_signed_in");
  assert.deepEqual(planSync(state(db), validateManifest(manifest)), [], "omitting accessMode leaves it alone");
});

test("planning for an unknown application fails", () => {
  const db = database();
  assert.throws(() => planSync(currentState(run(db, currentStateQueries("missing"))), validateManifest(manifest)), /not registered/);
});
