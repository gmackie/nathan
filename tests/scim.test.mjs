import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";
import {DIRECTORY_SCHEMA} from "../src/auth/scim/schema.mjs";
import {validateScimConnection,validateScimUser,validateScimGroup,parseFilter,pagination,SCIM_USER,SCIM_GROUP} from "../src/auth/scim/validation.mjs";
test("SCIM registry and transactional directory schemas are valid SQLite",()=>{
  const db=new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON;");
  db.exec(DIRECTORY_SCHEMA);
  db.prepare("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
    .run("u1","corp:1001","a@example.com","A","[]",100,100);
  assert.throws(()=>db.prepare("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
    .run("u2","corp:1001","b@example.com","B","[]",100,100),/UNIQUE/);
  db.exec("INSERT INTO scim_groups(id,display_name,created_at,updated_at) VALUES('g1','Engineering',100,100)");
  db.exec("INSERT INTO scim_group_members(group_id,user_id) VALUES('g1','u1')");
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM scim_group_members").get().n,1);
  assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(),[]);
  db.close();
  const r=new DatabaseSync(":memory:");
  r.exec(readFileSync("migrations/0007_scim_registry.sql","utf8"));
  const names=r.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(x=>x.name);
  assert.ok(names.includes("nathan_scim_connections")&&names.includes("nathan_scim_credentials"));
  r.close();
});
test("SCIM must not auto-link unverified identity based on email",()=>{
  assert.deepEqual(validateScimConnection({id:"acme-hr",domain:"acme.example"}),
    {id:"acme-hr",domain:"acme.example",organizationId:null});
  assert.throws(()=>validateScimConnection({id:"ACME",domain:"acme.example"}));
  assert.throws(()=>validateScimUser({schemas:[SCIM_USER],userName:"alice@example.com"}),/externalId/);
  const value=validateScimUser({schemas:[SCIM_USER],userName:"alice@example.com",externalId:"aad-sub-001",active:false});
  assert.equal(value.active,false);
  assert.equal(value.externalId,"aad-sub-001");
});
test("SCIM group membership must use stable UUID resource IDs",()=>{
  assert.throws(()=>validateScimGroup({schemas:[SCIM_GROUP],displayName:"Engineering",members:[{value:"../../etc"}]}));
  assert.deepEqual(validateScimGroup({schemas:[SCIM_GROUP],displayName:"Team",members:[]}).members,[]);
});
test("only strict parameterized SCIM filters and bounded paging are allowed",()=>{
  assert.deepEqual(parseFilter('externalId eq "user:123"'),{field:"externalId",value:"user:123"});
  for(const f of ["userName co \"bad\"","userName eq 123","emails.value eq \"a@b.com\"","userName eq \"x\" OR 1=1"])
    assert.throws(()=>parseFilter(f));
  assert.deepEqual(pagination(new URLSearchParams("startIndex=2&count=20")),{start:2,count:20});
  assert.throws(()=>pagination(new URLSearchParams("count=5000")));
});
