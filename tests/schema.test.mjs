import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function migration(path) {
  return readFileSync(resolve(path),"utf8");
}
test("Nathan and Better Auth migrations apply to SQLite without foreign-key errors",()=>{
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON;");
  db.exec(migration("migrations/0001_nathan_registry.sql"));
  db.exec(migration("migrations/0002_better_auth.sql"));
  db.exec(migration("migrations/0003_security_audit.sql"));
  db.exec(migration("migrations/0004_mcp_limits.sql"));
  db.exec(migration("migrations/0005_domain_realm.sql"));
  db.exec(migration("migrations/0006_control_plane.sql"));
  db.exec(migration("migrations/0007_scim_registry.sql"));
  const names = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r=>r.name);
  for(const required of ["user","session","oauthClient","jwks","twoFactor","passkey","ssoProvider","nathan_applications","nathan_security_audit","nathan_domain_realms","nathan_realm_clients","nathan_oauth_providers","nathan_bootstrap_status","nathan_scim_connections","nathan_scim_credentials","rateLimit"]) {
    assert.ok(names.includes(required), "Missing "+required);
  }
  assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
  assert.equal(db.prepare("SELECT COUNT(*) as count FROM nathan_security_audit").get().count,0);
  db.close();
});
test("gateway session migration applies with strict deletion support",()=>{
  const db=new DatabaseSync(":memory:");
  db.exec(migration("migrations/gateway/0001_sessions.sql"));
  const names=db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r=>r.name);
  assert.ok(names.includes("nathan_gateway_sessions"));
  assert.ok(names.includes("nathan_gateway_logout_jti"));
  db.prepare("INSERT INTO nathan_gateway_sessions (id_hash,subject,issuer,client_id,expires_at) VALUES (?,?,?,?,?)")
    .run("test-digest","subject1","https://auth.example.com/api/auth","client1",123);
  db.exec("DELETE FROM nathan_gateway_sessions WHERE expires_at <= unixepoch()");
  assert.equal(db.prepare("SELECT COUNT(*) as count FROM nathan_gateway_sessions").get().count,0);
  db.close();
});

test("realm schema prevents duplicate hosts and cross-realm foreign keys",()=>{
  const db=new DatabaseSync(":memory:");db.exec("PRAGMA foreign_keys=ON");
  for(const file of ["0001_nathan_registry.sql","0002_better_auth.sql","0003_security_audit.sql","0004_mcp_limits.sql","0005_domain_realm.sql"])
    db.exec(migration("migrations/"+file));
  db.prepare("INSERT INTO nathan_domain_realms(apex,issuer_hostname,account_id,zone_id,registered_by) VALUES (?,?,?,?,?)")
    .run("example.com","login.example.com","a".repeat(32),"b".repeat(32),"test");
  db.prepare("INSERT INTO nathan_realm_clients(hostname,realm_apex,kind,callback_uri,status,requested_by) VALUES(?,?,?,?,?,?)")
    .run("example.com","example.com","web","https://example.com/auth/callback","creating","admin");
  assert.throws(()=>db.prepare("INSERT INTO nathan_realm_clients(hostname,realm_apex,kind,callback_uri,status,requested_by) VALUES(?,?,?,?,?,?)")
    .run("app.example.com","another.example.com","worker","https://app.example.com/auth/callback","creating","admin"),/FOREIGN KEY/);
  assert.throws(()=>db.prepare("INSERT INTO nathan_realm_clients(hostname,realm_apex,kind,callback_uri,status,requested_by) VALUES(?,?,?,?,?,?)")
    .run("example.com","example.com","web","https://example.com/other","creating","admin"),/UNIQUE/);
  db.close();
});
