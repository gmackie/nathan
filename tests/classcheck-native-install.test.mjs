import assert from "node:assert/strict";
import test from "node:test";
import { readStage } from "../deploy/classcheck-id/bootstrap.mjs";
import { nativeClients } from "../deploy/classcheck-id/native-clients.mjs";
import { freshInstallation, applyBatch } from "./fixtures/classcheck-install.mjs";

test("native registration keeps each app public, pinned to its stage, and preserves later revocations", async () => {
  for (const stage of ["staging","production"]) {
    const spec = await readStage(stage);
    const db = freshInstallation(spec);
    const ops = nativeClients(spec);
    applyBatch(db, ops);
    const clients = db.prepare("SELECT * FROM oauthClient WHERE applicationType='native' ORDER BY clientId").all();
    assert.equal(clients.length, 2);
    for (const app of ["parent","driver"]) {
      const client = clients.find(c => c.clientId === "classcheck-" + app + "-" + stage);
      assert.equal(client.clientSecret, null);
      assert.deepEqual(JSON.parse(client.redirectUris), ["io.classcheck." + app + ":/oauth"]);
      assert.equal(client.requirePKCE, 1);
      assert.equal(client.skipConsent, 0);
      assert.equal(client.subjectType, "public");
      assert.equal(client.tokenEndpointAuthMethod, "none");
      assert.equal(db.prepare("SELECT resourceId FROM oauthClientResource WHERE clientId=?").get(client.clientId).resourceId, spec.origin + "/api");
    }
    db.exec("UPDATE oauthClient SET disabled=1 WHERE applicationType='native'");
    assert.throws(() => applyBatch(db, ops));
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM oauthClient WHERE applicationType='native' AND disabled=1").get().n, 2);
    db.close();
  }
});

test("native registration on a disabled or previously claimed app aborts the batch", async () => {
  const spec = await readStage("staging");
  const db = freshInstallation(spec);
  db.exec("UPDATE nathan_applications SET enabled=0");
  assert.throws(() => applyBatch(db, nativeClients(spec)));
  db.exec("UPDATE nathan_applications SET enabled=1");
  db.prepare("INSERT INTO oauthClient(id,clientId,redirectUris) VALUES('taken',?,'[]')").run("classcheck-driver-staging");
  assert.throws(() => applyBatch(db, nativeClients(spec)));
  assert.equal(db.prepare("SELECT * FROM oauthClient WHERE clientId='classcheck-parent-staging'").get(), undefined);
  db.close();
});
