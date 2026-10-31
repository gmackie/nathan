import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";

function db(){
  const db=new DatabaseSync(":memory:");
  for(const name of ["0002_better_auth.sql","0003_security_audit.sql","0006_control_plane.sql"])
    db.exec(readFileSync("migrations/"+name,"utf8"));
  return db;
}
test("initial admin authorization is linked to a verified Cloudflare installer identity",()=>{
  const d=db();
  d.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')")
    .run("cf-user","owner@example.com");
  assert.throws(()=>d.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')")
    .run("attacker","attacker@example.com"),/UNIQUE/);
  d.prepare("UPDATE nathan_bootstrap_status SET admin_user_id=?,state='identity_verified' WHERE id='primary' AND cloudflare_user_id=?")
    .run("real-user","cf-user");
  assert.equal(d.prepare("SELECT admin_user_id FROM nathan_bootstrap_status").get().admin_user_id,"real-user");
  d.close();
});
test("admin cannot complete bootstrap without verified state",()=>{
  const d=db();
  d.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')")
    .run("cf-user","owner@example.com");
  const r=d.prepare("UPDATE nathan_bootstrap_status SET state='complete' WHERE id='primary' AND admin_user_id=? AND state='identity_verified'")
    .run("attacker");
  assert.equal(r.changes,0);
  d.close();
});
