import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { applyBatch } from "./fixtures/classcheck-install.mjs";

const client = "educateos-web-staging";
const site = "https://staging.educateos.io";
const operator = "operator@example.test";

async function database(t) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const migrations = new URL("../migrations/", import.meta.url);
  for (const file of (await readdir(migrations)).filter(f => f.endsWith(".sql")).sort())
    db.exec(await readFile(new URL(file, migrations), "utf8"));
  return db;
}

test("the generated EducateOS Worker has private ingress and the dedicated D1 and Access audience", async () => {
  const { configuration } = await import("../deploy/educateos-id/cloudflare.config.ts");
  const config = await configuration();
  assert.deepEqual([config.account_id, config.name, config.d1_databases[0].database_id],
    ["c07a7e704db1808e1fff91bed2b1cd49", "nathan-educateos-stg-auth", "219478ac-318b-4af7-84d0-c8b83ebd7d70"]);
  assert.equal(config.d1_databases[0].database_name, config.name);
  assert.equal(config.vars.NATHAN_ACCESS_AUD, "794aa43e2e61b79b8dadef328f13e584717d032bc232dc76dd01a379f5a48685");
  assert.equal(config.vars.NATHAN_ADMIN_STEPUP_REQUIRED, "true");
  assert.equal(config.vars.NATHAN_BOOTSTRAP_REQUIRED, "true");
  assert.equal(config.vars.NATHAN_ISSUER, "https://id-stg.educateos.io");
  assert.equal(config.vars.NATHAN_ACCESS_TEAM_DOMAIN, "gmacko.cloudflareaccess.com");
  assert.equal(config.vars.NATHAN_APP_ORIGIN, site);
  assert.equal(config.vars.NATHAN_APP_ID, "educateos");
  assert.deepEqual(config.routes, []);
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.equal(config.vars.ENABLE_EMAIL_OTP, "true");
  for (const secret of ["EMAIL_FROM", "NATHAN_ADMIN_EMAILS", "BETTER_AUTH_SECRET", "NATHAN_CONFIG_KEY", "RESEND_API_KEY"]) {
    assert.equal(Object.hasOwn(config.vars, secret), false);
  }
});

test("bootstrap reserves only the member role and the exact web client, including signed logout", async t => {
  const { prepareInstall } = await import("../deploy/educateos-id/bootstrap.mjs");
  const secret = randomBytes(32).toString("base64url");
  const install = await prepareInstall(operator, secret);
  assert.ok(!JSON.stringify(install).includes(secret));
  const db = await database(t);
  applyBatch(db, install.batch);
  const row = db.prepare("SELECT * FROM oauthClient").get();
  assert.equal(row.clientId, client);
  assert.equal(row.clientSecret, createHash("sha256").update(secret).digest("base64url"));
  assert.equal(row.tokenEndpointAuthMethod, "client_secret_basic");
  assert.equal(row.subjectType, "public");
  assert.deepEqual(JSON.parse(row.scopes), ["openid", "email"]);
  assert.deepEqual(JSON.parse(row.grantTypes), ["authorization_code"]);
  assert.equal(row.requirePKCE, 1);
  assert.equal(row.skipConsent, 0);
  assert.deepEqual(JSON.parse(row.redirectUris), [site + "/auth/callback"]);
  assert.deepEqual(JSON.parse(row.postLogoutRedirectUris), [site + "/sign-in"]);
  assert.equal(row.enableEndSession, 1);
  assert.equal(row.backchannelLogoutUri, site + "/auth/backchannel-logout");
  assert.equal(row.backchannelLogoutSessionRequired, 0);
  assert.deepEqual(db.prepare("SELECT key FROM nathan_rbac_roles").all().map(r => r.key), ["member"]);
  assert.deepEqual(db.prepare("SELECT permission_key FROM nathan_rbac_role_permissions").all().map(r => r.permission_key), ["profile:read"]);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM nathan_rbac_grants").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM user").get().n, 0);
  assert.equal(db.prepare("SELECT email FROM nathan_invitations").get().email, operator);
  assert.equal(db.prepare(install.verify.sql).get(...install.verify.params).configured, 1);
  db.prepare("UPDATE oauthClient SET disabled=1").run();
  assert.equal(db.prepare(install.verify.sql).get(...install.verify.params).configured, 0);
  assert.throws(() => applyBatch(db, install.batch));
  assert.equal(db.prepare("SELECT disabled FROM oauthClient").get().disabled, 1);
});

test("an existing tenant or invitation aborts the whole EducateOS install", async t => {
  const { prepareInstall } = await import("../deploy/educateos-id/bootstrap.mjs");
  const db = await database(t);
  db.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('previous','existing@example.test','fixture',unixepoch()+500)").run();
  const install = await prepareInstall(operator, randomBytes(32).toString("base64url"));
  assert.throws(() => applyBatch(db, install.batch));
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM nathan_applications").get().n, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM nathan_security_audit WHERE id=?").get(install.receipt).n, 0);
});

test("batch export creates a new owner-only file and never prints credential material", async t => {
  const dir = await mkdtemp(join(tmpdir(), "educateos-install-"));
  t.after(() => rm(dir, { recursive: true }));
  const path = join(dir, "batch.json");
  const secret = randomBytes(32).toString("base64url");
  const run = () => spawnSync(process.execPath, ["deploy/educateos-id/bootstrap.mjs", "--batch-out", path], {
    input: secret, encoding: "utf8", env: { ...process.env, NATHAN_ADMIN_EMAILS: operator },
  });
  const first = run();
  assert.equal(first.status, 0);
  assert.ok(!first.stdout.includes(secret) && !first.stderr.includes(secret));
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  const batch = await readFile(path, "utf8");
  assert.ok(!batch.includes(secret));
  assert.equal(JSON.parse(batch).databaseId, "219478ac-318b-4af7-84d0-c8b83ebd7d70");
  assert.equal(run().status, 1);
  assert.equal(await readFile(path, "utf8"), batch);
});

test("bootstrap retries verify the original registration and a mismatched target receives no writes", async t => {
  const { applyInstall, prepareInstall } = await import("../deploy/educateos-id/bootstrap.mjs");
  const install = await prepareInstall(operator, randomBytes(32).toString("base64url"));
  const db = await database(t);
  let writes = 0;
  const api = {
    accountId: install.accountId,
    async databaseNamed(name) { assert.equal(name, "nathan-educateos-stg-auth"); return { uuid: install.databaseId }; },
    async queryDatabase(_, sql, params) { return db.prepare(sql).all(...params); },
    async batchDatabase(_, statements) {
      writes++;
      applyBatch(db, statements);
      // Simulate a disconnected writer after Cloudflare has committed.
      throw Error("Response interrupted");
    },
  };
  await assert.rejects(applyInstall({ ...api, databaseNamed: async () => ({ uuid: "unrelated" }) }, install), /identity mismatch/);
  await assert.rejects(applyInstall({ ...api, accountId: "unrelated" }, install), /identity mismatch/);
  await assert.rejects(applyInstall(api, install, true), /expected registration/);
  assert.equal(writes, 0);
  await applyInstall(api, install);
  await applyInstall(api, install);
  await applyInstall(api, install, true);
  assert.equal(writes, 1);
  db.prepare("UPDATE oauthClient SET disabled=1").run();
  await assert.rejects(applyInstall(api, install), /expected registration/);
  assert.equal(db.prepare("SELECT disabled FROM oauthClient").get().disabled, 1);
  assert.equal(writes, 1);
});
