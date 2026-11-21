import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { missingIdpSecrets, hostnameConflicts, ensureIdpSecrets, inspectDeployment, CloudflareClient } from "../scripts/lib/cloudflare.mjs";
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
    workers: async () => [], databaseNamed: async () => null, dnsRecords: async () => [],
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

test("D1 lookup matches exactly and pages past the first 100 databases", async () => {
  const all = [...Array.from({ length: 130 }, (_, i) => ({ uuid: "u" + i, name: "acme-auth-old-" + i })), { uuid: "target", name: "acme-auth" }];
  const client = new CloudflareClient("token", "a".repeat(32));
  const seen = [];
  client.request = async path => {
    const url = new URL("https://x" + path);
    seen.push(url.searchParams.get("page"));
    const filtered = all.filter(d => d.name.includes(url.searchParams.get("name")));
    const page = Number(url.searchParams.get("page"));
    return filtered.slice((page - 1) * 100, page * 100);
  };
  assert.equal((await client.databaseNamed("acme-auth")).uuid, "target");
  assert.deepEqual(seen, ["1", "2"]);
  assert.equal(await client.databaseNamed("acme-auth-old-1x"), null);
});

test("installer re-run keeps an administrator's provider disable and audits the credential write", async () => {
  const { INSTALLER_PROVIDER_STATE_SQL, INSTALLER_PROVIDER_AUDIT_SQL } = await import("../src/installer/validation.mjs");
  const db = new DatabaseSync(":memory:");
  for (const f of ["0003_security_audit.sql", "0006_control_plane.sql", "0012_social_providers.sql"])
    db.exec(readFileSync("migrations/" + f, "utf8"));
  db.prepare(INSTALLER_PROVIDER_STATE_SQL).run("github", "installer:u1");
  assert.equal(db.prepare("SELECT enabled FROM nathan_provider_state WHERE id='github'").get().enabled, 1, "first install enables");
  db.prepare("UPDATE nathan_provider_state SET enabled=0, tested_at=1, tested_version='v1' WHERE id='github'").run();
  db.prepare(INSTALLER_PROVIDER_STATE_SQL).run("github", "installer:u1");
  const row = db.prepare("SELECT enabled, tested_at FROM nathan_provider_state WHERE id='github'").get();
  assert.deepEqual({ ...row }, { enabled: 0, tested_at: null }, "re-run keeps the disable and clears the stale test");
  db.prepare(INSTALLER_PROVIDER_AUDIT_SQL).run("a1", "installer:u1", "github");
  assert.deepEqual({ ...db.prepare("SELECT actor, action, target, outcome FROM nathan_security_audit").get() },
    { actor: "installer:u1", action: "oauth_provider_update", target: "github", outcome: "succeeded" });
});
