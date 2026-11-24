import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { installStatements, readStage, receiptId } from "../deploy/classcheck-id/bootstrap.mjs";

function database() {
  const db = new DatabaseSync(":memory:");
  const dir = new URL("../migrations/", import.meta.url);
  for (const name of readdirSync(dir).filter(name => name.endsWith(".sql")).sort())
    db.exec(readFileSync(new URL(name, dir), "utf8"));
  return db;
}

function apply(db, batch) {
  db.exec("BEGIN");
  try {
    for (const { sql, params } of batch) db.prepare(sql).run(...params);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

for (const stage of ["staging", "production"]) {
  test("install seeds only the dedicated " + stage + " issuer and preserves management enrollment", async () => {
    const spec = await readStage(stage);
    assert.equal(spec.worker.workers_dev, false);
    assert.equal(spec.worker.preview_urls, false);
    assert.deepEqual(spec.worker.routes, []);
    const db = database();
    const secret = randomBytes(40).toString("base64url");
    const owner = "operator@example.test";
    const batch = installStatements(spec, owner, secret);
    assert.equal(JSON.stringify(batch).includes(secret), false);
    apply(db, batch);
    const client = db.prepare("SELECT * FROM oauthClient").get();
    assert.equal(client.clientId, "classcheck-web-" + stage);
    assert.deepEqual(JSON.parse(client.redirectUris), [spec.origin + "/auth/callback"]);
    assert.equal(client.clientSecret, createHash("sha256").update(secret).digest("base64url"));
    assert.equal(client.requirePKCE, 1);
    assert.equal(client.skipConsent, 0);
    assert.equal(client.tokenEndpointAuthMethod, "client_secret_basic");
    assert.equal(client.subjectType, "public");
    assert.equal(db.prepare("SELECT app_id FROM nathan_token_audiences WHERE identifier=?").get(spec.origin + "/api").app_id, "classcheck");
    assert.equal(db.prepare("SELECT count(*) AS n FROM user").get().n, 0);
    assert.equal(db.prepare("SELECT state FROM nathan_bootstrap_status WHERE admin_email=?").get(owner).state, "pending");
    assert.equal(db.prepare("SELECT uses FROM nathan_invitations WHERE email=? AND expires_at>unixepoch()").get(owner).uses, 0);
    assert.equal(db.prepare("SELECT * FROM nathan_rbac_grants").all().length, 0);
    assert.deepEqual(db.prepare("SELECT permission_key FROM nathan_rbac_role_permissions WHERE role_key='member'").all().map(v => v.permission_key), ["profile:read"]);
    assert.equal(db.prepare("SELECT outcome FROM nathan_security_audit WHERE id=?").get(receiptId(stage)).outcome, "succeeded");
    db.prepare("UPDATE oauthClient SET disabled=1").run();
    assert.throws(() => apply(db, batch));
    assert.equal(db.prepare("SELECT disabled FROM oauthClient").get().disabled, 1);
    db.close();
  });
}

test("a conflicting registration rolls back the whole install", async () => {
  const spec = await readStage("staging");
  const db = database();
  db.prepare("INSERT INTO oauthClient(id,clientId,redirectUris) VALUES ('existing',?,'[]')").run(spec.clientId);
  assert.throws(() => apply(db, installStatements(spec, "operator@example.test", randomBytes(40).toString("base64url"))));
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_bootstrap_status").get().n, 0);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_applications").get().n, 0);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE id=?").get(receiptId(spec.stage)).n, 0);
  db.close();
});
