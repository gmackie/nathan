import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

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
