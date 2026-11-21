import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { missingIdpSecrets, hostnameConflicts, ensureIdpSecrets, inspectDeployment } from "../scripts/lib/cloudflare.mjs";
import { redirectWithCookies, fetchNoRedirect } from "../src/shared/security.mjs";
import { EMPTY_DATABASE_SQL } from "../src/installer/validation.mjs";

test("CLI installs only the identity Worker secrets that are missing", () => {
  assert.deepEqual(missingIdpSecrets([]), ["BETTER_AUTH_SECRET", "NATHAN_CONFIG_KEY"]);
  assert.deepEqual(missingIdpSecrets(["BETTER_AUTH_SECRET"]), ["NATHAN_CONFIG_KEY"]);
  assert.deepEqual(missingIdpSecrets(["NATHAN_CONFIG_KEY", "BETTER_AUTH_SECRET", "OTHER"]), []);
});

test("the installation's own custom-domain DNS record is not a conflict on re-run", () => {
  const records = [{ id: "r1", type: "AAAA", name: "auth.example.com" }];
  assert.deepEqual(hostnameConflicts(records, [{ hostname: "auth.example.com", service: "acme-auth" }], "auth.example.com", "acme-auth"), []);
  assert.deepEqual(hostnameConflicts(records, [{ hostname: "auth.example.com", service: "someone-else" }], "auth.example.com", "acme-auth"), records);
  assert.deepEqual(hostnameConflicts(records, [], "auth.example.com", "acme-auth"), records);
});

test("cookie redirects keep mutable headers and every Set-Cookie", () => {
  const response = redirectWithCookies("https://idp.example.com/authorize?x=1", 302, ["__Host-a=1; Path=/", "__Host-b=2; Path=/"]);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "https://idp.example.com/authorize?x=1");
  assert.deepEqual(response.headers.getSetCookie(), ["__Host-a=1; Path=/", "__Host-b=2; Path=/"]);
  response.headers.set("Cache-Control", "no-store");
  assert.throws(() => redirectWithCookies("/relative"), "relative locations are rejected");
});

test("installer job lease migration applies on top of existing job rows", () => {
  const db = new DatabaseSync(":memory:");
  for (const file of ["0002_jobs.sql", "0003_realm.sql", "0004_scim_settings.sql"])
    db.exec(readFileSync("migrations/installer/" + file, "utf8"));
  db.prepare("INSERT INTO nathan_install_jobs(id,owner_user_id,owner_email,account_id,zone_id,hostname,worker_name,admin_email,profile,release_id) VALUES ('j','u','e@x.io','a','z','h','w','e@x.io','business','r')").run();
  db.exec(readFileSync("migrations/installer/0005_job_lease.sql", "utf8"));
  assert.deepEqual({ ...db.prepare("SELECT lease_token, database_create_started_at FROM nathan_install_jobs").get() },
    { lease_token: null, database_create_started_at: null });
});

test("the CLI never reports success while an identity secret is still missing", async () => {
  const bound = new Set(["BETTER_AUTH_SECRET"]);
  const put = [];
  const client = { workerSecretNames: async () => [...bound] };
  await ensureIdpSecrets(client, "acme-auth", async name => { put.push(name); bound.add(name); });
  assert.deepEqual(put, ["NATHAN_CONFIG_KEY"], "existing secrets are never replaced");
  const silentFailure = { workerSecretNames: async () => [] };
  await assert.rejects(ensureIdpSecrets(silentFailure, "acme-auth", async () => {}), /Refusing to publish/);
});

test("first-install discovery does not need Workers custom-domain permission", async () => {
  let domainCalls = 0;
  const client = {
    accountId: "a", zones: async () => [{ id: "z", name: "example.com", status: "active" }],
    workers: async () => [], databases: async () => [], dnsRecords: async () => [],
    workerDomains: async () => { domainCalls++; throw Error("forbidden"); }
  };
  const result = await inspectDeployment(client, { hostname: "auth.example.com", name: "acme", database: { name: "acme-db" } });
  assert.deepEqual(result.dnsConflicts, []);
  assert.equal(domainCalls, 0);
});

test("fetchNoRedirect forces manual redirects and fails closed on any redirect", async () => {
  const original = globalThis.fetch;
  try {
    let seen;
    globalThis.fetch = async (_url, init) => { seen = init.redirect; return new Response("ok"); };
    assert.equal(await (await fetchNoRedirect("https://idp.example/x", { redirect: "follow" })).text(), "ok");
    assert.equal(seen, "manual", "callers cannot re-enable redirects");
    globalThis.fetch = async () => new Response(null, { status: 302, headers: { Location: "https://evil.example/" } });
    await assert.rejects(fetchNoRedirect("https://idp.example/x"), /Unexpected redirect/);
    globalThis.fetch = async () => Object.defineProperty(new Response(null, { status: 200 }), "type", { value: "opaqueredirect" });
    await assert.rejects(fetchNoRedirect("https://idp.example/x"), /Unexpected redirect/);
  } finally { globalThis.fetch = original; }
});

test("the empty-database check counts look-alike names, views and triggers", () => {
  const count = setup => { const db = new DatabaseSync(":memory:"); db.exec(setup); return db.prepare(EMPTY_DATABASE_SQL).get().n; };
  assert.equal(count(""), 0);
  assert.equal(count("CREATE TABLE _cf_KV(k)"), 0, "Cloudflare internal tables are ignored");
  assert.equal(count("CREATE TABLE xcfusers(a); CREATE TABLE sqliteXdata(b)"), 2, "LIKE wildcards must not hide tables");
  assert.equal(count("CREATE VIEW v AS SELECT 1"), 1);
  assert.equal(count("CREATE TABLE _cf_t(a); CREATE TRIGGER trg AFTER INSERT ON _cf_t BEGIN SELECT 1; END"), 1);
});
