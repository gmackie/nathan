import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";
test("admin grants are explicit, unique and revocable by user",()=>{
  const db=new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  db.exec(readFileSync("migrations/0002_better_auth.sql","utf8"));
  db.exec(readFileSync("migrations/0009_admin_grants.sql","utf8"));
  db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES(?,?,?,?,?,?,?)')
    .run("u1","A","a@example.com",1,0,0,"admin");
  db.prepare("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES(?,?,?)")
    .run("u1","a@example.com","root");
  assert.throws(()=>db.prepare("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES(?,?,?)")
    .run("u1","other@example.com","root"),/UNIQUE/);
  assert.equal(db.prepare("SELECT enabled FROM nathan_admin_grants WHERE user_id='u1'").get().enabled,1);
  db.prepare("UPDATE nathan_admin_grants SET enabled=0 WHERE user_id='u1'").run();
  assert.equal(db.prepare("SELECT enabled FROM nathan_admin_grants WHERE user_id='u1'").get().enabled,0);
  db.close();
});
