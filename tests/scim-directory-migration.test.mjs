/**
 * NATH-11 review fix: the per-connection Durable Object's SQLite schema moves soft-deleted SCIM
 * resources to tombstone tables so a rehire can reuse userName/externalId (and a group its
 * displayName). Runs the same SQL the Durable Object runs (src/auth/scim/schema.mjs) on node:sqlite,
 * against a directory as it existed before the fix, with data in it.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { DIRECTORY_SCHEMA, DIRECTORY_LIFECYCLE_SCHEMA, DIRECTORY_TOMBSTONE_SCHEMA, DIRECTORY_TOMBSTONE_MIGRATION } from "../src/auth/scim/schema.mjs";

/** A directory with live and soft-deleted users and groups, as NATH-11 before the fix left it. */
function existingDirectory() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  db.exec(DIRECTORY_SCHEMA);
  db.exec(DIRECTORY_LIFECYCLE_SCHEMA);
  const user = (id, name, deleted) => db.prepare("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,active,deleted,revision,created_at,updated_at) VALUES (?,?,?,?,'[]',?,?,?,1,2)")
    .run(id, "ext-" + name, name + "@acme.example", name, deleted ? 0 : 1, deleted ? 1 : 0, deleted ? 3 : 1);
  user("u-live", "live", false); user("u-gone", "gone", true); user("u-other", "other", false);
  const group = (id, name, deleted) => db.prepare("INSERT INTO scim_groups(id,display_name,external_id,deleted,revision,created_at,updated_at) VALUES (?,?,?,?,?,1,2)")
    .run(id, name, "g-" + name, deleted ? 1 : 0, deleted ? 2 : 1);
  group("g-live", "Live", false); group("g-gone", "Gone", true);
  db.exec("INSERT INTO scim_group_members(group_id,user_id) VALUES ('g-live','u-live'),('g-live','u-other')");
  db.exec("INSERT INTO scim_outbox(kind,resource_id,revision,created_at) VALUES ('User','u-gone',3,1)");
  db.exec("INSERT INTO scim_meta(key,value) VALUES ('connection','acme')");
  return db;
}
function migrate(db) {
  db.exec(DIRECTORY_TOMBSTONE_SCHEMA);
  db.exec("BEGIN");
  try { db.exec(DIRECTORY_TOMBSTONE_MIGRATION); db.exec("COMMIT"); } catch (error) { db.exec("ROLLBACK"); throw error; }
}
const rows = (db, sql) => db.prepare(sql).all().map(r => ({ ...r }));

test("before the fix, a soft-deleted user blocks a rehire with UNIQUE", () => {
  const db = existingDirectory();
  assert.throws(() => db.prepare("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,created_at,updated_at) VALUES ('u-new','ext-gone','gone@acme.example','x','[]',1,1)").run(), /UNIQUE/);
});

test("the migration moves soft-deleted resources to tombstones and keeps everything live intact", () => {
  const db = existingDirectory();
  migrate(db);
  assert.deepEqual(rows(db, "SELECT id FROM scim_users ORDER BY id").map(r => r.id), ["u-live", "u-other"]);
  assert.deepEqual(rows(db, "SELECT id, user_name, external_id, revision FROM scim_user_tombstones"),
    [{ id: "u-gone", user_name: "gone@acme.example", external_id: "ext-gone", revision: 3 }]);
  assert.deepEqual(rows(db, "SELECT id FROM scim_groups").map(r => r.id), ["g-live"]);
  assert.deepEqual(rows(db, "SELECT id, display_name FROM scim_group_tombstones"), [{ id: "g-gone", display_name: "Gone" }]);
  assert.equal(rows(db, "SELECT * FROM scim_group_members").length, 2, "memberships of live resources survive");
  assert.equal(rows(db, "SELECT * FROM scim_outbox").length, 1, "pending reconciliation of the deleted user is kept");
  assert.deepEqual(rows(db, "SELECT value FROM scim_meta WHERE key='tombstones'"), [{ value: "1" }]);
  assert.deepEqual(rows(db, "PRAGMA foreign_key_check"), []);
  // Running it again (a later activation) changes nothing.
  migrate(db);
  assert.equal(rows(db, "SELECT * FROM scim_user_tombstones").length, 1);
  assert.equal(rows(db, "SELECT * FROM scim_users").length, 2);
});

test("after the migration a rehire reuses the userName and externalId, and a group its displayName", () => {
  const db = existingDirectory();
  migrate(db);
  db.prepare("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,created_at,updated_at) VALUES ('u-new','ext-gone','gone@acme.example','x','[]',1,1)").run();
  db.prepare("INSERT INTO scim_groups(id,display_name,external_id,created_at,updated_at) VALUES ('g-new','Gone','g-gone',1,1)").run();
  // Live resources stay unique.
  assert.throws(() => db.prepare("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,created_at,updated_at) VALUES ('u-dup','ext-live','x@acme.example','x','[]',1,1)").run(), /UNIQUE/);
  assert.throws(() => db.prepare("INSERT INTO scim_groups(id,display_name,external_id,created_at,updated_at) VALUES ('g-dup','Live','other',1,1)").run(), /UNIQUE/);
});
