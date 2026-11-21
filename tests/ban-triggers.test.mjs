/**
 * NATH-18 (c): schema test for the user-state triggers that downstream consumers depend on:
 * migration 0011's change-feed triggers (bans, unbans, deletions) and 0016's SCIM ban-change trigger.
 * A migration that drops or renames one would silently stop Gatekeeper's feed or SCIM override records.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";

const migrations = readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort();
function database() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of migrations) db.exec(readFileSync("migrations/" + file, "utf8"));
  return db;
}
const EXPECTED = {
  nathan_rbac_feed_user_ban: { file: "0011_rbac.sql", timing: /AFTER UPDATE OF "banned" ON "user"/ },
  nathan_rbac_feed_user_delete: { file: "0011_rbac.sql", timing: /BEFORE DELETE ON "user"/ },
  nathan_scim_ban_changed: { file: "0016_scim_lifecycle.sql", timing: /AFTER UPDATE OF "banned","banReason","banExpires" ON "user"/ }
};

test("the 0011 and 0016 user-state triggers exist after all migrations, on the user table", () => {
  const db = database();
  const triggers = Object.fromEntries(db.prepare("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger'").all().map(t => [t.name, t]));
  for (const [name, { file, timing }] of Object.entries(EXPECTED)) {
    assert.ok(triggers[name], name + " exists");
    assert.equal(triggers[name].tbl_name, "user", name);
    assert.match(triggers[name].sql, timing, name);
    assert.match(readFileSync("migrations/" + file, "utf8"), new RegExp("CREATE TRIGGER IF NOT EXISTS " + name + "\\b"), name + " is defined in " + file);
  }
  // No later migration drops or replaces them.
  for (const file of migrations.filter(f => f > "0016"))
    for (const name of Object.keys(EXPECTED)) assert.doesNotMatch(readFileSync("migrations/" + file, "utf8"), new RegExp("DROP TRIGGER[^;]*" + name), file);
});

test("ban, unban and delete fire the feed triggers for the value types Better Auth writes", () => {
  const db = database();
  db.exec('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u1\',\'u1\',\'u1@example.test\',1,0,0)');
  const kinds = () => db.prepare("SELECT kind FROM nathan_rbac_changes WHERE principal_id='u1' ORDER BY seq").all().map(r => r.kind);
  db.exec('UPDATE "user" SET "banned"=1, "banReason"=\'x\' WHERE "id"=\'u1\'');
  db.exec('UPDATE "user" SET "banReason"=\'y\' WHERE "id"=\'u1\'');
  db.exec('UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL WHERE "id"=\'u1\'');
  db.exec('UPDATE "user" SET "banned"=\'1\' WHERE "id"=\'u1\'');
  db.exec('UPDATE "user" SET "banned"=NULL WHERE "id"=\'u1\'');
  assert.deepEqual(kinds(), ["user.banned", "user.unbanned", "user.banned", "user.unbanned"]);
  db.exec('DELETE FROM "user" WHERE "id"=\'u1\'');
  assert.equal(kinds().at(-1), "user.deleted");
});
