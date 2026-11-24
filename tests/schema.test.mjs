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
  db.exec(migration("migrations/0008_admin_assurance.sql"));
  db.exec(migration("migrations/0009_admin_grants.sql"));
  db.exec(migration("migrations/0010_security_overrides.sql"));
  db.exec(migration("migrations/0013_saml.sql"));
  const names = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r=>r.name);
  for(const required of ["user","session","oauthClient","jwks","twoFactor","passkey","ssoProvider","nathan_applications","nathan_security_audit","nathan_domain_realms","nathan_realm_clients","nathan_oauth_providers","nathan_bootstrap_status","nathan_scim_connections","nathan_scim_credentials","nathan_admin_grants","nathan_security_overrides","nathan_saml_connections","rateLimit"]) {
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
test("realm client creation is disabled on insertion and reconciles earlier disabled inventory", () => {
  const db = new DatabaseSync(":memory:");
  const apply = name => db.exec(migration("migrations/" + name));
  apply("0002_better_auth.sql");
  apply("0003_security_audit.sql");
  apply("0005_domain_realm.sql");
  db.exec("INSERT INTO nathan_domain_realms(apex,issuer_hostname,account_id,zone_id,registered_by) VALUES ('example.com','login.example.com','account','zone','installer')");
  db.exec("INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('admin','Admin','admin@example.com',1,0,0)");
  const client = (id, hostname, metadata = null) => db.prepare('INSERT INTO "oauthClient"(id,clientId,userId,redirectUris,disabled,metadata) VALUES (?,?,\'admin\',?,0,?)')
    .run(id, id, JSON.stringify(["https://" + hostname + "/cb"]), metadata);
  const reserve = (host, status, id) => db.prepare("INSERT INTO nathan_realm_clients(hostname,realm_apex,kind,callback_uri,status,requested_by,oauth_client_id) VALUES (?,'example.com','web',?,?,'admin',?)")
    .run(host, "https://" + host + "/cb", status, id);
  const disabled = id => db.prepare('SELECT disabled FROM "oauthClient" WHERE clientId=?').get(id).disabled;
  client("waiting", "waiting.example.com");
  reserve("waiting.example.com", "disabled", "waiting");
  client("active", "active.example.com");
  reserve("active.example.com", "registered", "active");
  reserve("partial.example.com", "creating", null);
  client("earlier-rp", "partial.example.com");
  db.prepare('UPDATE oauthClient SET createdAt=? WHERE clientId=?').run("2025-01-01T00:00:00Z", "earlier-rp");
  client("unlinked", "partial.example.com");
  client("also-unlinked", "partial.example.com");
  apply("0019_realm_client_activation.sql");
  assert.equal(disabled("waiting"), 1);
  assert.equal(disabled("active"), 0);
  assert.deepEqual(db.prepare("SELECT target FROM nathan_security_audit WHERE action='realm_client_activation_reconciled'").all().map(row => row.target), ["waiting"]);
  assert.equal(disabled("earlier-rp"), 0);
  assert.equal(disabled("unlinked"), 1);
  assert.equal(disabled("also-unlinked"), 1);
  assert.deepEqual(db.prepare("SELECT target FROM nathan_security_audit WHERE action='realm_client_review_required' ORDER BY target").all().map(r => r.target), ["also-unlinked", "unlinked"]);

  reserve("new.example.com", "creating", null);
  db.prepare("UPDATE nathan_realm_clients SET registration_id='registration' WHERE hostname='new.example.com'").run();
  client("ordinary", "new.example.com");
  client("managed", "new.example.com", JSON.stringify({ nathan_realm_registration: "registration" }));
  assert.equal(disabled("ordinary"), 0);
  assert.equal(disabled("managed"), 1);
  db.prepare('UPDATE "oauthClient" SET disabled=0 WHERE clientId=?').run("managed");
  assert.equal(disabled("managed"), 0);
  // During rollout, an older Worker can still finish a pre-migration reservation.
  reserve("rolling.example.com", "creating", null);
  client("rolling", "rolling.example.com");
  assert.equal(disabled("rolling"), 1);
  client("new-independent", "rolling.example.com", JSON.stringify({ nathan_registration_kind: "independent" }));
  assert.equal(disabled("new-independent"), 0);
  // The old Worker expects one D1 change when linking an already disabled registration.
  const totalChanges = () => db.prepare("SELECT total_changes() AS n").get().n;
  const beforeLink = totalChanges();
  db.prepare("UPDATE nathan_realm_clients SET status='disabled',oauth_client_id=? WHERE hostname=?").run("rolling", "rolling.example.com");
  assert.equal(totalChanges() - beforeLink, 1);
  // Its provider insert could also precede 0019, with the old Worker's inventory link landing later.
  client("in-flight", "in-flight.example.com");
  reserve("in-flight.example.com", "creating", null);
  db.prepare("UPDATE nathan_realm_clients SET status='disabled',oauth_client_id=? WHERE hostname=?").run("in-flight", "in-flight.example.com");
  assert.equal(disabled("in-flight"), 1);
  db.close();
});
