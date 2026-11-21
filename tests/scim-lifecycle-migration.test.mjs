/** NATH-11: migration 0016 constraints that keep SCIM identity links and group mappings safe. */
import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";

const migrations = readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort();
function database() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of migrations) db.exec(readFileSync("migrations/" + file, "utf8"));
  db.exec("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES ('acme','acme.example','t'),('acme2','acme.example','t')");
  db.exec('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u1\',\'u1\',\'u1@acme.example\',1,0,0)');
  return db;
}
const link = (db, connection, scimId, externalId, userId) => db.prepare(
  "INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state) VALUES (?,?,?,?,1,?,'linked')"
).run(connection, scimId, externalId, "u1@acme.example", userId);

test("0016 is the only 0016 migration and is packaged with the release", () => {
  assert.equal(migrations.filter(f => f.startsWith("0016")).length, 1);
  assert.ok(migrations.includes("0016_scim_lifecycle.sql"));
  for (const script of ["scripts/pack-release.mjs", "scripts/verify-release.mjs"])
    assert.match(readFileSync(script, "utf8"), /0016_scim_lifecycle\.sql/, script + " lists migration 0016");
});

test("new connections keep linking and just-in-time creation off", () => {
  const db = database();
  assert.deepEqual({ ...db.prepare("SELECT linking_enabled, jit_enabled FROM nathan_scim_connections WHERE id='acme'").get() },
    { linking_enabled: 0, jit_enabled: 0 });
});

test("a Nathan user is linked at most once and a link never moves to another connection", () => {
  const db = database();
  link(db, "acme", "s1", "ext-1", "u1");
  assert.throws(() => link(db, "acme2", "s9", "ext-1", "u1"), /UNIQUE/, "same user in another connection");
  assert.throws(() => link(db, "acme", "s2", "ext-2", "u1"), /UNIQUE/, "same user twice in one connection");
  assert.throws(() => link(db, "acme", "s3", "ext-1", null), /UNIQUE/, "externalId is unique per connection among live identities");
  // Unlinked rows (no Nathan user) do not collide.
  db.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active) VALUES ('acme2','s4','ext-4','x@acme.example',1)").run();
  db.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active) VALUES ('acme2','s5','ext-5','y@acme.example',1)").run();
});

test("deleting the Nathan user clears the link but keeps the evidence that blocks an automatic re-link", () => {
  // Intended behavior (src/auth/scim/lifecycle.ts decideLink): a live directory identity whose Nathan
  // account was deleted is an orphan; neither its own connection nor any other connection links its
  // email again without an administrator's approved review (tests/scim-apply.test.mjs and the
  // workerd test prove the behavior; this proves the data it relies on survives the deletion).
  const db = database();
  db.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,linked_email,linked_at) VALUES ('acme','s1','ext-1','u1@acme.example',1,'u1','linked','u1@acme.example',100)").run();
  db.exec('DELETE FROM "user" WHERE "id"=\'u1\'');
  assert.deepEqual({ ...db.prepare("SELECT user_id, linked_email, linked_at FROM nathan_scim_users WHERE scim_id='s1'").get() },
    { user_id: null, linked_email: "u1@acme.example", linked_at: 100 });
  const orphans = db.prepare("EXPLAIN QUERY PLAN SELECT connection_id FROM nathan_scim_users WHERE user_id IS NULL AND deleted=0 AND linked_email IN ('u1@acme.example')").all();
  assert.ok(orphans.some(r => /nathan_scim_users_orphan/.test(r.detail)), "orphan lookups use their index");
});

test("a deleted directory identity releases its externalId for a rehire in the same connection", () => {
  const db = database();
  link(db, "acme", "s1", "ext-1", "u1");
  db.exec("UPDATE nathan_scim_users SET deleted=1 WHERE scim_id='s1'");
  db.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active) VALUES ('acme','s2','ext-1','u1@acme.example',1)").run();
  assert.throws(() => db.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active) VALUES ('acme','s3','ext-1','u1@acme.example',1)").run(), /UNIQUE/,
    "but only one live identity per externalId");
});

test("administrator review items: one open item per directory user and action, known states only", () => {
  const db = database();
  const review = (id, action, state = "pending") => db.prepare(
    "INSERT INTO nathan_scim_reviews(id,connection_id,scim_id,user_id,action,reason,revision,state) VALUES (?,'acme','s1','u1',?,'r',1,?)").run(id, action, state);
  review("r1", "deprovision");
  assert.throws(() => review("r2", "deprovision"), /UNIQUE/, "no second open item for the same change");
  assert.throws(() => review("r3", "deprovision", "approved"), /UNIQUE/);
  review("r4", "link");
  review("r5", "deprovision", "dismissed");
  assert.throws(() => review("r6", "ban"), /CHECK/);
  db.exec('DELETE FROM "user" WHERE "id"=\'u1\'');
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_scim_reviews").get().n, 0, "items go with the Nathan user");
});

test("the apply guard rejects a lost compare-and-set", () => {
  const db = database();
  link(db, "acme", "s1", "ext-1", "u1");
  assert.throws(() => db.exec("UPDATE nathan_scim_users SET apply_seq=-1 WHERE scim_id='s1'"), /CHECK/);
});

test("a Nathan group is fed by at most one SCIM group mapping, which goes with the group", () => {
  const db = database();
  db.exec("INSERT INTO nathan_groups(id,name,source,created_by) VALUES ('eng','Engineering','scim','t')");
  const map = (id, connection, value) => db.prepare(
    "INSERT INTO nathan_scim_group_mappings(id,connection_id,ref_type,ref_value,group_id,created_by) VALUES (?,?,'externalId',?,'eng','t')"
  ).run(id, connection, value);
  map("m1", "acme", "grp-1");
  assert.throws(() => map("m2", "acme2", "grp-2"), /UNIQUE/);
  assert.throws(() => db.prepare("INSERT INTO nathan_scim_group_mappings(id,connection_id,ref_type,ref_value,group_id,created_by) VALUES ('m3','acme','name','x','eng','t')").run(), /CHECK/);
  db.exec("DELETE FROM nathan_groups WHERE id='eng'");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_scim_group_mappings").get().n, 0);
});

test("back-channel deliveries start pending and only take known states", () => {
  const db = database();
  db.exec("INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,reason) VALUES ('d1','c1','u1','scim.deprovisioned')");
  assert.equal(db.prepare("SELECT state, attempts FROM nathan_backchannel_deliveries").get().state, "pending");
  assert.throws(() => db.exec("UPDATE nathan_backchannel_deliveries SET state='lost'"), /CHECK/);
});
