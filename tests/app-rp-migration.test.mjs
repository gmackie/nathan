import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

const cleanup = "0026_legacy_erasure_deliveries.sql";
const participation = "0023_app_rp_sessions.sql";
const apply = (db, name) => db.exec(readFileSync("migrations/" + name, "utf8"));

for (const ledger of ["wrangler", "installer", "manual"]) {
  test("0026 retires unproven erasure sessions with " + ledger + " migration tracking", () => {
    const db = new DatabaseSync(":memory:");
    try {
      for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql") && f < cleanup).sort()) apply(db,file);
      const cutover = 1700000000;
      if (ledger === "wrangler") {
        db.exec("CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,applied_at TIMESTAMP NOT NULL)");
        db.prepare("INSERT INTO d1_migrations(name,applied_at) VALUES (?,datetime(?,'unixepoch'))").run(participation,cutover);
      } else if (ledger === "installer") {
        db.exec("CREATE TABLE nathan_release_migrations(name TEXT PRIMARY KEY,sha256 TEXT NOT NULL,applied_at INTEGER NOT NULL)");
        db.prepare("INSERT INTO nathan_release_migrations VALUES (?,'checksum',?)").run(participation,cutover);
      }
      db.exec("INSERT INTO oauthClient(id,clientId,redirectUris,backchannelLogoutSessionRequired) VALUES " +
        "('a','required','[]',1),('b','subject','[]',0)");
      const insert = db.prepare("INSERT INTO nathan_backchannel_deliveries " +
        "(id,client_id,user_id,session_id,issued_subject,state,reason,created_at) VALUES (?,?, 'erased',?,?,?,?,?)");
      const erased = "app-account-erased";
      insert.run("older","required","guessed",null,"pending",erased,cutover-1);
      insert.run("equal","required","uncertain",null,"pending",erased,cutover);
      insert.run("later","required","from-stored-token",null,"pending",erased,cutover+1);
      insert.run("exact","required","issued-sid","issued-sub","pending",erased,cutover);
      insert.run("wide","subject","guessed",null,"pending",erased,cutover-1);
      insert.run("no-sid","required",null,null,"pending",erased,cutover-1);
      insert.run("missing-client","removed","old",null,"pending",erased,cutover-1);
      insert.run("delivered","required","old",null,"delivered",erased,cutover-1);
      insert.run("other","required","old",null,"pending","app-session-end",cutover-1);
      db.exec("INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('u','Member','m@example.test',1,0,0);" +
        "INSERT INTO nathan_app_rp_sessions VALUES ('u','required','s','u','rp-sid');" +
        "INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,session_id,reason,created_at) " +
        "VALUES ('participation','required','u','rp-sid','app-account-erased',0);");
      apply(db,cleanup);
      const row = id => db.prepare("SELECT state,session_id,last_status,attempts FROM nathan_backchannel_deliveries WHERE id=?").get(id);
      for (const id of ["older","equal","no-sid","missing-client"]) {
        assert.equal(row(id).state,"failed",id);
        assert.equal(row(id).last_status,"unproven_erasure_session");
        assert.equal(row(id).attempts,0);
      }
      assert.equal(row("later").state,ledger === "manual" ? "failed" : "pending");
      assert.equal(row("exact").state,"pending");
      assert.equal(row("exact").session_id,"issued-sid");
      assert.equal(row("wide").state,"pending");
      assert.equal(row("wide").session_id,null);
      assert.equal(row("other").state,"pending");
      assert.equal(row("delivered").state,"delivered");
      assert.equal(row("participation").state,"pending");
      apply(db,cleanup);
      const audit = db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action='backchannel_logout_retired'").get();
      assert.equal(audit.n,ledger === "manual" ? 5 : 4);
    } finally {
      db.close();
    }
  });
}

test("upgrading 0022 retains proven historical recipients without assigning consent an unrelated session", () => {
  const db = new DatabaseSync(":memory:"), migration = "0023_app_rp_sessions.sql";
  try {
    for (const name of readdirSync("migrations").filter(f => f.endsWith(".sql") && f < migration).sort())
      db.exec(readFileSync("migrations/" + name, "utf8"));
    db.exec("INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('u','Member','m@example.test',1,0,0);" +
      "INSERT INTO nathan_app_provisions(app_id,external_id_hash,subject_hash,user_id,email) VALUES ('cc','external','subject','u','m@example.test');" +
      "INSERT INTO session(id,token,userId,createdAt,updatedAt,expiresAt) VALUES ('real','one','u',0,0,9999999999),('other','two','u',0,0,9999999999);");
    for (const [client,required] of [["wide",0],["known",1],["consent-only",1]])
      db.prepare("INSERT INTO oauthClient(id,clientId,redirectUris,backchannelLogoutUri,backchannelLogoutSessionRequired) VALUES(?,?,'[]',?,?)")
        .run(client,client,"https://rp.example.test/" + client,required);
    db.exec("INSERT INTO oauthConsent(id,clientId,userId,scopes,createdAt,updatedAt) VALUES " +
      "('a','wide','u','[]',0,0),('b','consent-only','u','[]',0,0);" +
      "INSERT INTO oauthRefreshToken(id,token,clientId,userId,sessionId,scopes,expiresAt,createdAt) VALUES ('r','r','known','u','real','[]',9999999999,0);" +
      "INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,session_id,reason) VALUES ('pending','wide','previous','guessed','app-account-erased');");
    db.exec(readFileSync("migrations/" + migration,"utf8"));
    assert.equal(db.prepare("SELECT session_id FROM nathan_backchannel_deliveries WHERE id='pending'").get().session_id, null);
    db.exec("DELETE FROM session WHERE userId='u'; DELETE FROM oauthConsent; DELETE FROM oauthRefreshToken;");
    db.exec("DELETE FROM user WHERE id='u'");
    const recipients = db.prepare("SELECT client_id,session_id FROM nathan_backchannel_deliveries WHERE user_id='u' ORDER BY client_id").all()
      .map(r => [r.client_id,r.session_id]);
    assert.deepEqual(recipients, [["known","real"],["wide",null]]);
    assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_app_rp_sessions").get().n, 0);
  } finally {
    db.close();
  }
});
