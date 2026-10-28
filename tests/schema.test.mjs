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
  const names = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r=>r.name);
  for(const required of ["user","session","oauthClient","jwks","twoFactor","passkey","ssoProvider","nathan_applications","nathan_security_audit","rateLimit"]) {
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
