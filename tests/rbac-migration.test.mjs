import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { accessQueries, decideFromRows, directoryQueries, directoryView, changeQueries, changePage, changeStatement, pruneChangeStatements } from "../src/shared/rbac-store.mjs";

const ISSUER = "https://login.example.test/api/auth";
const migrations = readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort();
const before0011 = migrations.filter(f => f < "0011");

function database(files) {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of files) db.exec(readFileSync("migrations/" + file, "utf8"));
  return db;
}
const run = (db, statements) => statements.map(s => db.prepare(s.sql).all(...s.params));
const decide = (db, app, user) => decideFromRows(run(db, accessQueries(app, user)));

function addUser(db, id, role, banned = 0) {
  db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role","banned") VALUES (?,?,?,?,?,?,?,?)')
    .run(id, id, id + "@example.test", 1, 0, 0, role, banned);
}
function addApp(db, id, roles, enabled = 1) {
  db.prepare("INSERT INTO nathan_applications(id,hostname,roles,enabled) VALUES (?,?,?,?)").run(id, id + ".example.test", roles, enabled);
}
/** NathanVerifier.authorize() before NATH-13: the single global Better Auth role against the app's list. */
function legacyAuthorize(db, appId, userId) {
  const user = db.prepare('SELECT "role" FROM "user" WHERE "id"=?').get(userId);
  if (!user) return false;
  const role = user.role ?? "user";
  const row = db.prepare("SELECT roles, enabled FROM nathan_applications WHERE id=?").get(appId);
  if (!row || row.enabled !== 1) return false;
  let required;
  try { required = JSON.parse(row.roles); } catch { return false; }
  return Array.isArray(required) && required.every(r => typeof r === "string") && (required.length === 0 || required.includes(role));
}

test("0011 is the only new migration and applies after 0010", () => {
  assert.ok(migrations.includes("0011_rbac.sql"));
  assert.equal(migrations.filter(f => f.startsWith("0011")).length, 1);
});

test("legacy grant ids are unambiguous: (a, b-c) and (a-b, c) both keep their grant", () => {
  const db = database(before0011);
  addUser(db, "ann", "b-c");
  addUser(db, "cal", "c");
  // 'legacy-'||app||'-'||role would give both grants the id legacy-a-b-c, and INSERT OR IGNORE
  // would silently drop the second one, so cal would lose access to a-b.
  addApp(db, "a", '["b-c"]');
  addApp(db, "a-b", '["c"]');
  const expected = { "a/ann": legacyAuthorize(db, "a", "ann"), "a-b/cal": legacyAuthorize(db, "a-b", "cal") };
  assert.deepEqual(expected, { "a/ann": true, "a-b/cal": true });
  db.exec(readFileSync("migrations/0011_rbac.sql", "utf8"));
  const grants = db.prepare("SELECT id, app_id AS app, role_key AS role FROM nathan_rbac_grants WHERE created_by='migration:0011' ORDER BY app_id").all();
  assert.deepEqual(grants.map(g => [g.app, g.role]), [["a", "b-c"], ["a-b", "c"]]);
  assert.equal(new Set(grants.map(g => g.id)).size, 2, "distinct ids");
  assert.equal(decide(db, "a", "ann").allowed, true);
  assert.equal(decide(db, "a-b", "cal").allowed, true);
  db.close();
});

test("migrating legacy role lists keeps every current access decision", () => {
  const db = database(before0011);
  addUser(db, "root", "admin");
  addUser(db, "alice", "user");
  addUser(db, "bob", null);
  addUser(db, "carol", "admin,user");
  addUser(db, "dave", "editor");
  addApp(db, "open", "[]");
  addApp(db, "admins", '["admin"]');
  addApp(db, "staff", '["admin","user"]');
  addApp(db, "editors", '["editor"]');
  addApp(db, "closed", '["admin"]', 0);
  addApp(db, "broken", "not json");
  addApp(db, "object", '{"admin":true}');
  const users = ["root", "alice", "bob", "carol", "dave", "nobody"];
  const apps = ["open", "admins", "staff", "editors", "closed", "broken", "object", "missing"];
  const expected = new Map();
  for (const app of apps) for (const user of users) expected.set(app + "/" + user, legacyAuthorize(db, app, user));

  db.exec(readFileSync("migrations/0011_rbac.sql", "utf8"));
  for (const app of apps) for (const user of users)
    assert.equal(decide(db, app, user).allowed, expected.get(app + "/" + user), app + "/" + user);

  assert.equal(db.prepare("SELECT access_mode AS m FROM nathan_applications WHERE id='open'").get().m, "any_signed_in");
  for (const id of ["admins", "staff", "editors", "closed", "broken", "object"])
    assert.equal(db.prepare("SELECT access_mode AS m FROM nathan_applications WHERE id=?").get(id).m, "approved", id);
  // Legacy roles become app roles, so upstreams can check hasRole("admin").
  assert.deepEqual(decide(db, "admins", "root").roles, ["admin"]);
  assert.deepEqual(decide(db, "staff", "alice").roles, ["user"]);
  // Group membership is a snapshot: the global admin role no longer grants app access by itself.
  addUser(db, "erin", "admin");
  assert.equal(decide(db, "admins", "erin").allowed, false);
  const audit = db.prepare("SELECT actor, action, outcome FROM nathan_security_audit WHERE action='rbac_legacy_migration'").all();
  assert.equal(audit.length, 1);
  assert.equal(audit[0].actor, "migration:0011");
  db.close();
});

test("new applications default to approved mode and deny everyone", () => {
  const db = database(migrations);
  addUser(db, "alice", "admin");
  addApp(db, "fresh", "[]");
  assert.equal(db.prepare("SELECT access_mode AS m FROM nathan_applications WHERE id='fresh'").get().m, "approved");
  assert.deepEqual(decide(db, "fresh", "alice"), { allowed: false, reason: "no_grant", roles: [], permissions: [] });
  db.close();
});

test("schema enforces modes, principals and cascades, and passes the foreign-key check", () => {
  const db = database(migrations);
  addUser(db, "alice", "user");
  addApp(db, "billing", "[]");
  db.exec("UPDATE nathan_applications SET access_mode='approved', enabled=1 WHERE id='billing'");
  assert.throws(() => db.exec("UPDATE nathan_applications SET access_mode='everyone' WHERE id='billing'"), /CHECK/);
  db.exec("INSERT INTO nathan_rbac_permissions(app_id,key,description) VALUES ('billing','invoices:read','Read'),('billing','invoices:write','Write')");
  db.exec("INSERT INTO nathan_rbac_roles(app_id,key,description) VALUES ('billing','editor','Edit')");
  db.exec("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('billing','editor','invoices:read'),('billing','editor','invoices:write')");
  assert.throws(() => db.exec("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('billing','editor','missing:perm')"), /FOREIGN KEY/);
  assert.throws(() => db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g0','billing','ghost','user','alice','t')"), /FOREIGN KEY/);
  assert.throws(() => db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g0','billing','editor','robot','alice','t')"), /CHECK/);
  db.exec("INSERT INTO nathan_groups(id,name,created_by) VALUES ('finance','Finance','t')");
  db.exec("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('finance','alice','t')");
  assert.throws(() => db.exec("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('finance','ghost','t')"), /FOREIGN KEY/);
  db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','billing','editor','group','finance','t')");
  assert.throws(() => db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g2','billing','editor','group','finance','t')"), /UNIQUE/);
  assert.deepEqual(decide(db, "billing", "alice").permissions, ["invoices:read", "invoices:write"]);
  // Removing a permission removes it from roles; deleting a role removes its grants.
  db.exec("DELETE FROM nathan_rbac_permissions WHERE app_id='billing' AND key='invoices:write'");
  assert.deepEqual(decide(db, "billing", "alice").permissions, ["invoices:read"]);
  db.exec("DELETE FROM nathan_rbac_roles WHERE app_id='billing' AND key='editor'");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants").get().n, 0);
  // Deleting a user removes their memberships.
  db.exec('DELETE FROM "user" WHERE "id"=\'alice\'');
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_group_members").get().n, 0);
  assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
  db.close();
});

test("app suspension and restoration reach the directory even when Studio owns the member grant", () => {
  const db = database(migrations);
  addUser(db, "alice", "user");
  addApp(db, "school", "[]");
  db.exec("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('school','member')");
  db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g','school','member','user','alice','studio')");
  db.exec("INSERT INTO nathan_app_provisions(app_id,external_id_hash,subject_hash,user_id,email) VALUES ('school','key','sub','alice','alice@example.test')");
  const roleSet = db.prepare("UPDATE nathan_app_provisions SET grant_revision=?,desired_roles=? WHERE user_id='alice'");
  const directory = () => directoryView({issuer:ISSUER,observedAt:"now",results:run(db,directoryQueries("alice"))});
  assert.equal(directory().applications.school.allowed,true);
  roleSet.run(1,"[]");
  assert.equal(directory().applications.school.allowed,false);
  assert.deepEqual(directory().applications.school.roles,[]);
  roleSet.run(2,"[]");
  roleSet.run(3,'["member"]');
  assert.equal(directory().applications.school.allowed,true);
  const events = changePage({issuer:ISSUER,observedAt:"now",cursor:0,limit:10,results:run(db,changeQueries(0,10))}).changes;
  assert.deepEqual(events.map(e => [e.kind,e.app,e.principal?.id]),[
    ["app.membership_suspended","school","alice"],["app.membership_restored","school","alice"]
  ]);
  assert.equal(db.prepare("SELECT created_by FROM nathan_rbac_grants WHERE id='g'").get().created_by,"studio");
  db.close();
});

test("directory view uses the evaluator's answers and the change feed pages and prunes", () => {
  const db = database(migrations);
  addUser(db, "alice", "user");
  addUser(db, "bob", "user", 1);
  addApp(db, "billing", "[]");
  addApp(db, "wiki", "[]");
  db.exec("UPDATE nathan_applications SET enabled=1, access_mode='approved' WHERE id='billing'");
  db.exec("UPDATE nathan_applications SET enabled=1, access_mode='any_signed_in' WHERE id='wiki'");
  db.exec("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES ('billing','invoices:read')");
  db.exec("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('billing','viewer')");
  db.exec("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('billing','viewer','invoices:read')");
  db.exec("INSERT INTO nathan_groups(id,name,created_by) VALUES ('finance','Finance','t')");
  db.exec("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('finance','alice','t'),('finance','bob','t')");
  db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','billing','viewer','group','finance','t')");
  for (let i = 0; i < 3; i++) { const s = changeStatement({ kind: "grant.created", appId: "billing", principalType: "group", principalId: "finance", actor: "t" }); db.prepare(s.sql).run(...s.params); }

  const view = directoryView({ issuer: ISSUER, observedAt: "2026-11-21T00:00:00.000Z", results: run(db, directoryQueries("alice")) });
  assert.equal(view.subject, ISSUER + "#alice");
  assert.equal(view.active, true);
  assert.deepEqual(view.groups.map(g => g.id), ["finance"]);
  assert.deepEqual(view.grants, [{ app: "billing", role: "viewer", via: { type: "group", id: "finance" } }]);
  assert.equal(view.cursor, "3");
  for (const app of ["billing", "wiki"]) {
    const { enabled, accessMode, ...decision } = view.applications[app];
    assert.deepEqual(decision, decide(db, app, "alice"), app);
  }
  const blocked = directoryView({ issuer: ISSUER, observedAt: "x", results: run(db, directoryQueries("bob")) });
  assert.equal(blocked.active, false);
  assert.equal(blocked.applications.billing.allowed, false);
  assert.equal(blocked.applications.billing.reason, "user_blocked");
  assert.equal(directoryView({ issuer: ISSUER, observedAt: "x", results: run(db, directoryQueries("ghost")) }), null);

  const first = changePage({ issuer: ISSUER, observedAt: "x", cursor: 0, limit: 2, results: run(db, changeQueries(0, 2)) });
  assert.deepEqual(first.changes.map(c => c.seq), ["1", "2"]);
  assert.equal(first.hasMore, true);
  const second = changePage({ issuer: ISSUER, observedAt: "x", cursor: 2, limit: 2, results: run(db, changeQueries(2, 2)) });
  assert.deepEqual(second.changes.map(c => c.seq), ["3"]);
  assert.equal(second.hasMore, false);
  assert.deepEqual(second.changes[0].principal, { type: "group", id: "finance" });

  db.exec("UPDATE nathan_rbac_changes SET created_at=created_at-40*24*3600 WHERE seq<=2");
  run(db, pruneChangeStatements());
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_rbac_changes").get().n, 1);
  assert.equal(changePage({ issuer: ISSUER, observedAt: "x", cursor: 1, limit: 2, results: run(db, changeQueries(1, 2)) }).resync, true);
  assert.equal(changePage({ issuer: ISSUER, observedAt: "x", cursor: 2, limit: 2, results: run(db, changeQueries(2, 2)) }).changes.length, 1);
  db.close();
});

test("the change feed records ban/unban and the memberships and grants of deleted users", () => {
  const db = database(migrations);
  addUser(db, "fay", "user");
  addUser(db, "gus", "user");
  addApp(db, "crm", "[]");
  db.exec("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('crm','viewer')");
  db.exec("INSERT INTO nathan_groups(id,name,created_by) VALUES ('sales','Sales','t'),('ops','Ops','t')");
  db.exec("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('sales','fay','t'),('ops','fay','t'),('sales','gus','t')");
  db.exec("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('gf','crm','viewer','user','fay','t'),('gg','crm','viewer','user','gus','t')");
  const feed = () => changePage({ issuer: ISSUER, observedAt: "now", cursor: 0, limit: 500, results: run(db, changeQueries(0, 500)) }).changes
    .map(c => [c.kind, c.app, c.principal?.id, c.detail]);
  assert.deepEqual(feed(), []);

  db.exec('UPDATE "user" SET "banned"=1 WHERE "id"=\'fay\'');
  db.exec('UPDATE "user" SET "banned"=1 WHERE "id"=\'fay\'');        // no change, no entry
  db.exec('UPDATE "user" SET "name"=\'Fay\' WHERE "id"=\'fay\'');   // not access-relevant
  db.exec('UPDATE "user" SET "banned"=0 WHERE "id"=\'fay\'');
  db.exec('UPDATE "user" SET "banned"=NULL WHERE "id"=\'fay\'');     // NULL and 0 are both "not banned"
  assert.deepEqual(feed(), [["user.banned", null, "fay", {}], ["user.unbanned", null, "fay", {}]]);
  const banned = db.prepare("SELECT actor FROM nathan_rbac_changes WHERE kind='user.banned'").get();
  assert.equal(banned.actor, "system:user-state");

  db.exec('DELETE FROM "user" WHERE "id"=\'fay\'');
  assert.deepEqual(feed().slice(2), [
    ["member.removed", null, "fay", { group: "ops", cause: "user.deleted" }],
    ["member.removed", null, "fay", { group: "sales", cause: "user.deleted" }],
    ["grant.revoked", "crm", "fay", { role: "viewer", cause: "user.deleted" }],
    ["user.deleted", null, "fay", {}]
  ]);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_group_members WHERE user_id='fay'").get().n, 0);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants WHERE principal_id='fay'").get().n, 0, "no orphaned user grants");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_rbac_grants WHERE principal_id='gus'").get().n, 1, "other users untouched");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_group_members WHERE user_id='gus'").get().n, 1);
  db.close();
});
