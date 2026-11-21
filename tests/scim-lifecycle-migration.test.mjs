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
  assert.throws(() => link(db, "acme", "s3", "ext-1", null), /UNIQUE/, "externalId is unique per connection");
  // Unlinked rows (no Nathan user) do not collide.
  db.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active) VALUES ('acme2','s4','ext-4','x@acme.example',1)").run();
  db.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active) VALUES ('acme2','s5','ext-5','y@acme.example',1)").run();
  // Deleting the Nathan user clears the link instead of leaving a dangling id.
  db.exec('DELETE FROM "user" WHERE "id"=\'u1\'');
  assert.equal(db.prepare("SELECT user_id FROM nathan_scim_users WHERE scim_id='s1'").get().user_id, null);
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
