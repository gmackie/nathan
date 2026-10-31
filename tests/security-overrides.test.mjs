import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";
test("security tightening uses durable boolean overrides, not disabling TLS or token checks",()=>{
  const d=new DatabaseSync(":memory:");
  d.exec(readFileSync("migrations/0010_security_overrides.sql","utf8"));
  d.prepare("INSERT INTO nathan_security_overrides(id,modified_by,require_both_admin_authenticators,require_recent_admin_passkey) VALUES('primary','owner',1,1)").run();
  const row=d.prepare("SELECT * FROM nathan_security_overrides WHERE id='primary'").get();
  assert.equal(row.require_both_admin_authenticators,1);
  assert.equal(row.require_recent_admin_passkey,1);
  assert.throws(()=>d.prepare("UPDATE nathan_security_overrides SET require_recent_admin_passkey=2").run(),/CHECK/);
  d.close();
});
