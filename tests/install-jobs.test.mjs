import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
const sql=readFileSync("migrations/installer/0002_jobs.sql","utf8");
function create(){
  const db=new DatabaseSync(":memory:");
  db.exec(sql);
  db.exec(readFileSync("migrations/installer/0003_realm.sql","utf8"));
  return db;
}
const example={
  id:"e32b74f0-382d-4ef4-8b42-aa477f21fd50",
  owner:"cf-user-1",email:"owner@example.com",account:"a".repeat(32),
  zone:"b".repeat(32),hostname:"auth.example.com",worker:"nathan-auth"
};
function insert(db,other={}){
  const obj={...example,...other};
  db.prepare("INSERT INTO nathan_install_jobs"+
    "(id,owner_user_id,owner_email,account_id,zone_id,hostname,worker_name,admin_email,profile,enterprise_sso,release_id)"+
    " VALUES(?,?,?,?,?,?,?,?,?,?,?)").run(
    obj.id,obj.owner,obj.email,obj.account,obj.zone,obj.hostname,obj.worker,obj.email,"business",1,"0.1.0+commit"
  );
}
test("resumable install starts at database stage",()=>{
  const db=create();insert(db);
  const row=db.prepare("SELECT stage,enterprise_sso,locked_until FROM nathan_install_jobs").get();
  assert.deepEqual({...row},{stage:"database",enterprise_sso:1,locked_until:0});
  db.close();
});
test("two jobs cannot claim same worker in one account",()=>{
  const db=create();insert(db);
  assert.throws(()=>insert(db,{id:"2",hostname:"auth2.example.com"}),/UNIQUE/);
  db.close();
});
test("two jobs cannot claim same hostname in one account",()=>{
  const db=create();insert(db);
  assert.throws(()=>insert(db,{id:"2",worker:"other-worker"}),/UNIQUE/);
  db.close();
});
test("jobs store references, not provider/client secrets",()=>{
  const db=create();
  const columns=db.prepare("PRAGMA table_info(nathan_install_jobs)").all().map(x=>x.name);
  for(const sensitive of ["client_secret","oauth_token","password","better_auth_secret","refresh_token"])
    assert.ok(!columns.includes(sensitive),sensitive+" should not be stored");
  db.close();
});
test("unsupported high-assurance profile is refused at schema",()=>{
  const db=create();
  db.prepare("INSERT INTO nathan_install_jobs(id,owner_user_id,owner_email,account_id,zone_id,hostname,worker_name,admin_email,profile,release_id)"+
    " VALUES (?,?,?,?,?,?,?,?,?,?)");
  assert.throws(()=>db.prepare("INSERT INTO nathan_install_jobs(id,owner_user_id,owner_email,account_id,zone_id,hostname,worker_name,admin_email,profile,release_id)"+
    " VALUES (?,?,?,?,?,?,?,?,?,?)").run("1","u","u@example.com","a","b","h.example.com","w","u@example.com","high","v"),/CHECK/);
  db.close();
});

test("installation migration can store canonical root-domain SSO realm",()=>{
  const db=create();insert(db);
  db.prepare("UPDATE nathan_install_jobs SET realm_apex=? WHERE id=?").run("example.com",example.id);
  assert.equal(db.prepare("SELECT realm_apex FROM nathan_install_jobs").get().realm_apex,"example.com");
  db.close();
});
