import assert from "node:assert/strict";
import test from "node:test";
import { readStage } from "../deploy/classcheck-id/bootstrap.mjs";
import { webLogout } from "../deploy/classcheck-id/web-logout.mjs";
import { freshInstallation, applyBatch } from "./fixtures/classcheck-install.mjs";

for (const stage of ["staging","production"]) {
  test("web logout configures only the exact " + stage + " return", async () => {
    const spec = await readStage(stage);
    assert.ok(spec.worker.triggers.crons.includes("* * * * *"), "retry due RP notifications every minute");
    const db = freshInstallation(spec);
    applyBatch(db, webLogout(spec));
    const read = () => db.prepare("SELECT enableEndSession,postLogoutRedirectUris FROM oauthClient WHERE clientId=?").get(spec.clientId);
    assert.equal(read().enableEndSession, 1);
    assert.deepEqual(JSON.parse(read().postLogoutRedirectUris),[spec.origin + "/sign-in"]);
    db.exec("UPDATE oauthClient SET enableEndSession=0");
    assert.throws(() => applyBatch(db, webLogout(spec)));
    assert.equal(read().enableEndSession, 0);
    db.close();
  });
}

test("a changed or disabled web registration is preserved", async () => {
  for (const change of ["disabled=1","skipConsent=1","postLogoutRedirectUris='[]'","enableEndSession=0"]) {
    const spec = await readStage("staging");
    const db = freshInstallation(spec);
    db.exec("UPDATE oauthClient SET " + change);
    assert.throws(() => applyBatch(db, webLogout(spec)));
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM nathan_security_audit WHERE action='classcheck_web_logout'").get().n, 0);
    db.close();
  }
});

test("resource policy expands the original API audience without adding client privileges", async () => {
  const spec = await readStage("staging");
  const db = freshInstallation(spec);
  const legacy = JSON.stringify(["openid","email","profile","offline_access"]);
  db.prepare("UPDATE oauthResource SET allowedScopes=?").run(legacy);
  applyBatch(db, webLogout(spec));
  assert.deepEqual(JSON.parse(db.prepare("SELECT allowedScopes FROM oauthResource").get().allowedScopes),
    ["openid","profile","email","offline_access","nathan:api"]);
  assert.equal(db.prepare("SELECT scopes FROM oauthClient").get().scopes, legacy);
  db.close();
});

test("a divergent resource policy rolls back the web logout upgrade", async () => {
  const spec = await readStage("staging");
  const db = freshInstallation(spec);
  db.exec("UPDATE oauthResource SET allowedScopes='[]'");
  assert.throws(() => applyBatch(db, webLogout(spec)));
  assert.equal(db.prepare("SELECT enableEndSession FROM oauthClient").get().enableEndSession, null);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action='classcheck_web_logout'").get().n, 0);
  db.close();
});
