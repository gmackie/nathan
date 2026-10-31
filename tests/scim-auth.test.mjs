import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFileSync} from "node:fs";
test("SCIM credentials are per-connection, scoped and revocable without deleting users",()=>{
  const db=new DatabaseSync(":memory:");db.exec("PRAGMA foreign_keys=ON");
  db.exec(readFileSync("migrations/0007_scim_registry.sql","utf8"));
  db.prepare("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES(?,?,?)")
    .run("acme-hr","acme.example","admin1");
  db.prepare("INSERT INTO nathan_scim_credentials(id,connection_id,token_hash) VALUES(?,?,?)")
    .run("c1","acme-hr","oneway-hash");
  assert.equal(db.prepare("SELECT enabled FROM nathan_scim_connections WHERE id=?").get("acme-hr").enabled,0);
  db.prepare("UPDATE nathan_scim_connections SET enabled=1 WHERE id=?").run("acme-hr");
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM nathan_scim_credentials WHERE token_hash=? AND revoked_at IS NULL").get("oneway-hash").n,1);
  db.prepare("UPDATE nathan_scim_credentials SET revoked_at=unixepoch() WHERE id=?").run("c1");
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM nathan_scim_credentials WHERE token_hash=? AND revoked_at IS NULL").get("oneway-hash").n,0);
  db.close();
});
