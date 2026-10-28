import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { validateAccountId, validateHostname, validateInstallPlan, validateWorkerName, isAllowedOrigin } from "../src/installer/validation.mjs";
test("installer rejects malicious account names and origins",()=>{
  assert.equal(validateAccountId("a".repeat(32)),"a".repeat(32));
  assert.throws(()=>validateAccountId("a".repeat(31)));
  assert.throws(()=>validateHostname("auth.example.com.attacker."));
  assert.throws(()=>validateHostname("Auth.EXAMPLE.com"));
  assert.throws(()=>validateWorkerName("../../a"));
  assert.equal(isAllowedOrigin("https://install.example.com","https://install.example.com"),true);
  assert.equal(isAllowedOrigin("https://evil.example.com","https://install.example.com"),false);
});
test("installer validates hostname, profile and account",()=>{
  const data=validateInstallPlan({accountId:"a".repeat(32),hostname:"auth.example.com",name:"nathan-auth",securityProfile:"business"});
  assert.equal(data.name,"nathan-auth");
  assert.throws(()=>validateInstallPlan({...data,hostname:"//evil.com"}));
  assert.throws(()=>validateInstallPlan({...data,securityProfile:"insecure"}));
});
test("installer state and sessions have appropriate database columns",()=>{
  const db=new DatabaseSync(":memory:");
  db.exec(readFileSync("migrations/installer/0001_sessions.sql","utf8"));
  const table=db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(x=>x.name);
  assert.ok(table.includes("nathan_installer_state"));
  assert.ok(table.includes("nathan_installer_sessions"));
  const columns=db.prepare("PRAGMA table_info(nathan_installer_state)").all().map(x=>x.name);
  assert.ok(columns.includes("consumed_at"));
  db.close();
});
