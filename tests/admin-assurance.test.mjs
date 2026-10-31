import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";
test("admin authentication evidence is tied to an exact session, not enrollment",()=>{
  const db=new DatabaseSync(":memory:");
  db.exec(readFileSync("migrations/0008_admin_assurance.sql","utf8"));
  db.prepare("INSERT INTO nathan_admin_assurance(session_id,user_id,method,verified_at) VALUES(?,?,?,?)")
    .run("session-1","admin-1","passkey",1000);
  const valid=db.prepare("SELECT session_id FROM nathan_admin_assurance WHERE session_id=? AND user_id=? AND method='passkey' AND verified_at>=?")
    .get("session-1","admin-1",900);
  assert.equal(valid.session_id,"session-1");
  assert.equal(db.prepare("SELECT session_id FROM nathan_admin_assurance WHERE session_id=? AND user_id=?").get("session-2","admin-1"),undefined);
  assert.equal(db.prepare("SELECT session_id FROM nathan_admin_assurance WHERE session_id=? AND user_id=? AND verified_at>=?").get("session-1","admin-1",1900),undefined);
  db.close();
});
