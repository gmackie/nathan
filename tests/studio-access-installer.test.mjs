import test from "node:test";
import assert from "node:assert/strict";
import { inspectStudioHostname, inspectStudioInstallation, rememberStudioDatabase, reconcileStudioAccess, studioAccessOptions, verifyIdentityUpload } from "../scripts/lib/studio-access.mjs";
import { validateConfig, buildPlan } from "../scripts/lib/config.mjs";
import { activateIdentityWorker, createGeneratedConfig } from "../scripts/lib/wrangler.mjs";
import { publishIdentityDomains } from "../scripts/lib/cloudflare.mjs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp, readFile, rm } from "node:fs/promises";

const idp = "462306b8-3172-49e5-be9d-5b2562d13db1";
const appId = "627cc38d-a62c-4b00-b8bc-808c15029294";
const cfg = { name: "studio-access-test", hostname: "login.example.com", accountId: "a".repeat(32), securityProfile: "standard",
  adminEmails: ["owner@example.com"], studioAccess: { identityProviderId: idp, emails: ["owner@example.com"] },
  database: { type: "d1", name: "test-auth" }, applications: [] };
const host = "admin.login.example.com";

function fixture() {
  const state = { apps: [], policies: [], writes: [], methods: ["totp"], type: "azureAD" };
  const api = { accountId: cfg.accountId, async request(path, init) {
    if (path.endsWith("/organizations")) return { auth_domain: "example.cloudflareaccess.com", mfa_config: { allowed_authenticators: state.methods } };
    if (path.endsWith("/identity_providers/" + idp)) return { id: idp, type: state.type };
    if (init) {
      assert.equal(init.method, "POST");
      assert.ok(path.endsWith("/apps"));
      state.writes.push(init.body);
      const app = { ...init.body, id: appId, aud: "a".repeat(64) };
      state.policies = app.policies.map(p => ({ ...p, id: crypto.randomUUID() }));
      app.policies = state.policies.map(p => ({ id: p.id }));
      state.apps.push(app);
      return app;
    }
    if (path.includes("/policies?")) return state.policies;
    if (path.includes("/apps?")) {
      const page = Number(new URL(path, "https://api.example").searchParams.get("page"));
      return state.apps.slice((page - 1) * 50, page * 50);
    }
    if (path.endsWith("/apps/" + appId)) return state.apps.find(a => a.id === appId);
    throw Error("Unexpected path: " + path);
  }};
  return { api, state };
}

test("Access plan, atomic creation and retry generate the exact admin route and bindings", async () => {
  const { api, state } = fixture();
  assert.deepEqual(validateConfig(cfg), []);
  assert.equal(buildPlan(cfg).find(s => s.resource === "studio-access-application").overwriteExisting, false);
  assert.equal((await reconcileStudioAccess(api, cfg)).operation, "create");
  assert.equal(state.writes.length, 0);
  const created = await reconcileStudioAccess(api, cfg, true);
  assert.equal((await reconcileStudioAccess(api, cfg, true)).operation, "validate");
  assert.equal(state.writes.length, 1);
  assert.deepEqual(state.writes[0].policies[0].include, [{ email: { email: "owner@example.com" } }]);
  const file = await createGeneratedConfig(cfg, crypto.randomUUID(), null, created.bindings);
  try {
    const worker = JSON.parse(await readFile(file));
    assert.deepEqual(worker.routes.map(r => r.pattern), [cfg.hostname, host]);
    assert.equal(worker.vars.NATHAN_ISSUER, "https://" + cfg.hostname);
    assert.equal(worker.vars.NATHAN_ADMIN_ORIGIN, "https://" + host);
    assert.equal(worker.vars.NATHAN_ACCESS_AUD, "a".repeat(64));
    assert.equal(worker.vars.NATHAN_ACCESS_TEAM_DOMAIN, "example.cloudflareaccess.com");
    assert.equal(worker.workers_dev, false);
    assert.equal(worker.preview_urls, false);
  } finally { await rm(file); }
});

test("existing path overlaps on later pages, policy drift and MFA exemptions prevent writes", async () => {
  for (const domain of [host + "/private", "*.login.example.com"]) {
    const { api, state } = fixture();
    state.apps.push(...Array.from({ length: 50 }, (_, i) => ({ id: String(i), domain: "other" + i + ".example.net" })));
    state.apps.push({ id: appId, domain });
    await assert.rejects(reconcileStudioAccess(api, cfg, true));
    assert.equal(state.writes.length, 0);
  }
  for (const edit of [
    s => s.policies.push({ id: "other", decision: "bypass" }),
    s => { s.policies[0].include = [{ everyone: {} }]; },
    s => { s.policies[0].mfa_config = { mfa_disabled: true }; },
    s => { s.apps[0].mfa_config.mfa_disabled = true; },
    s => { s.apps[0].allowed_idps = []; },
    s => { s.apps[0].options_preflight_bypass = true; },
    s => { s.apps[0].session_duration = "24h"; },
    s => { s.policies[0].session_duration = "24h"; }
  ]) {
    const { api, state } = fixture();
    await reconcileStudioAccess(api, cfg, true);
    edit(state);
    await assert.rejects(reconcileStudioAccess(api, cfg, true));
    assert.equal(state.writes.length, 1);
  }
});

test("organization MFA, an external provider and exact local administrator emails are required", async () => {
  for (const edit of [s => { s.methods = []; }, s => { s.type = "oidc"; }]) {
    const { api, state } = fixture();
    edit(state);
    await assert.rejects(reconcileStudioAccess(api, cfg, true));
    assert.equal(state.writes.length, 0);
  }
  assert.throws(() => studioAccessOptions({ ...cfg, adminEmails: [] }));
  assert.throws(() => studioAccessOptions({ ...cfg, hostname: "*.example.com" }));
});

test("installer refuses a colliding DNS record, Worker route or Worker custom domain", async () => {
  const api = { accountId: cfg.accountId, zones: async () => [{ id: "zone", status: "active", name: "example.com" }],
    dnsRecords: async () => [], request: async () => [] };
  const snapshot = { existingAuthWorker: false };
  await inspectStudioInstallation(api, cfg, snapshot);
  await assert.rejects(inspectStudioInstallation({ ...api, dnsRecords: async () => [{ type: "A" }] }, cfg, snapshot));
  for (const [match, row] of [["/workers/routes", { pattern: host + "/path/*" }], ["/workers/domains?", { hostname: host, service: "other" }]]) {
    await assert.rejects(inspectStudioInstallation({ ...api, request: async path => path.includes(match) ? [row] : [] }, cfg, snapshot));
  }
});

test("upgrade requires the existing Worker, database, seed and current local operator to agree", async () => {
  const snapshot = { existingAuthWorker: true, existingDatabase: { uuid: "db" } };
  const bindings = [{ type: "d1", name: "DB", id: "db" }, { type: "plain_text", name: "NATHAN_ISSUER", text: "https://" + cfg.hostname }];
  const owner = { state: "complete", admin_email: "owner@example.com", cloudflare_user_id: "cli:" + cfg.accountId };
  let granted = true;
  const api = { accountId: cfg.accountId, zones: async () => [{ id: "zone", name: "example.com", status: "active" }],
    dnsRecords: async () => [], request: async path => path.endsWith("/settings") ? { bindings } : [],
    queryDatabase: async (_db, sql) => sql.includes("cloudflare_user_id") ? [owner] : granted ? [{ id: "operator" }] : [] };
  const legacy = { ...cfg, studioAccess: undefined };
  for (const config of [legacy, cfg]) {
    await inspectStudioInstallation(api, config, snapshot);
    await assert.rejects(inspectStudioInstallation(api, config, { ...snapshot, existingDatabase: null }), /database/);
    bindings[0].id = "unrelated";
    await assert.rejects(inspectStudioInstallation(api, config, snapshot), /database/);
    bindings[0].id = "db";
    bindings[1].text = "https://other.example.com";
    await assert.rejects(inspectStudioInstallation(api, config, snapshot), /issuer/);
    bindings[1].text = "https://" + cfg.hostname;
    owner.cloudflare_user_id = "another installation";
    await assert.rejects(inspectStudioInstallation(api, config, snapshot), /owner/);
    owner.cloudflare_user_id = "cli:" + cfg.accountId;
    owner.admin_email = "elsewhere@example.test";
    await assert.rejects(inspectStudioInstallation(api, config, snapshot), /owner/);
    owner.admin_email = cfg.adminEmails[0];
  }
  granted = false;
  await assert.rejects(inspectStudioInstallation(api, cfg, snapshot), /grants/);
  owner.state = "pending";
  await inspectStudioInstallation(api, legacy, snapshot);
});

test("old manifests cannot implicitly remove an existing shared or dedicated Access boundary", async () => {
  const old = { ...cfg, studioAccess: undefined };
  const snapshot = { existingAuthWorker: true };
  const api = { request: async () => ({ bindings: [{ name: "NATHAN_ADMIN_ORIGIN", type: "plain_text" }] }) };
  await assert.rejects(inspectStudioInstallation(api, old, snapshot), /Restore/);
  await assert.rejects(inspectStudioInstallation({ request: async () => ({}) }, old, snapshot), /bindings/);
  await assert.rejects(inspectStudioInstallation({ request: async () => ({ bindings: [] }) }, old, snapshot), /database/);
});


test("only the recorded D1 can resume an interrupted Studio bootstrap before its first migration or seed", async () => {
  const folder = await mkdtemp(join(tmpdir(), "nathan-receipt-"));
  const zone = { id: "zone", name: "example.com", status: "active" };
  const api = { accountId: cfg.accountId, zones: async () => [zone], request: async () => [], dnsRecords: async () => [] };
  let hasSchema = false;
  api.queryDatabase = async (_id, sql) => {
    if (sql.includes("sqlite_master")) return hasSchema ? [{ name: "nathan_bootstrap_status" }] : [];
    if (sql.startsWith("SELECT id FROM")) return [];
    throw Error("Cannot resume unowned database");
  };
  try {
    const snapshot = { existingAuthWorker: false, existingDatabase: { uuid: "db" } };
    await rememberStudioDatabase(cfg, "db", folder);
    const legacy = { ...cfg, studioAccess: undefined };
    await inspectStudioInstallation(api, legacy, snapshot, folder);
    await assert.rejects(inspectStudioInstallation(api, legacy, { ...snapshot, existingDatabase: { uuid: "other" } }, folder));
    await inspectStudioInstallation(api, cfg, snapshot, folder);
    hasSchema = true;
    await inspectStudioInstallation(api, cfg, snapshot, folder);
    await assert.rejects(inspectStudioInstallation(api, cfg, { ...snapshot, existingDatabase: { uuid: "other" } }, folder));
    await assert.rejects(inspectStudioInstallation(api, { ...cfg, accountId: "b".repeat(32) }, snapshot, folder));
  } finally { await rm(folder, { recursive: true }); }
});

test("publishes only missing exact domains with all replacement flags disabled", async () => {
  const worker = cfg.name + "-auth";
  const zone = { id: "zone", name: "example.com", status: "active" };
  const domains = new Map([[cfg.hostname, { hostname: cfg.hostname, service: worker, zone_id: zone.id, environment: "production" }]]);
  const writes = [];
  let reject = true, environment = "production";
  const api = { accountId: cfg.accountId, zones: async () => [zone], async request(path, init) {
    if (!init) {
      const row = domains.get(new URL(path, "https://api.example").searchParams.get("hostname"));
      return row ? [row] : [];
    }
    assert.ok(path.endsWith("/scripts/" + worker + "/domains/records"));
    const { origins, ...flags } = init.body;
    assert.deepEqual(flags, { override_scope: false, override_existing_origin: false, override_existing_dns_record: false });
    assert.deepEqual(origins, [{ hostname: host, zone_id: zone.id, enabled: true, previews_enabled: false }]);
    writes.push(host);
    if (reject) throw Error("Conflicting DNS record");
    domains.set(host, { ...origins[0], service: worker, environment });
  }};
  await assert.rejects(publishIdentityDomains(api, cfg, [cfg.hostname, host]), /Conflicting/);
  assert.equal(domains.has(host), false);
  reject = false;
  await publishIdentityDomains(api, cfg, [cfg.hostname, host]);
  await publishIdentityDomains(api, cfg, [cfg.hostname, host]);
  assert.equal(writes.length, 2);
  domains.get(host).environment = "staging";
  await assert.rejects(publishIdentityDomains(api, cfg, [host]), /differs/);
  const discovery = { ...api, dnsRecords: async () => [], request: async path =>
    path.endsWith("/workers/routes") ? [] : [domains.get(host)] };
  await assert.rejects(inspectStudioHostname(discovery, cfg), /differs/);
  assert.equal(writes.length, 2);
  domains.delete(host);
  environment = "staging";
  await assert.rejects(publishIdentityDomains(api, cfg, [host]), /differs/);
  assert.equal(writes.length, 3);
});

test("last pre-upload discovery rejects inventory errors and an intervening Access cutover", async () => {
  const legacy = { ...cfg, studioAccess: undefined };
  const api = { accountId: cfg.accountId, databaseNamed: async () => ({ uuid: "db" }),
    zones: async () => [{ id: "zone", name: "example.com", status: "active" }], dnsRecords: async () => [],
    workers: async () => [{ id: cfg.name + "-auth" }], workerDomains: async () => [],
    request: async () => ({ bindings: [{ name: "DB", type: "d1", id: "db" },
      { type: "plain_text", name: "NATHAN_ISSUER", text: "https://" + cfg.hostname }] }),
    queryDatabase: async () => [{ admin_email: cfg.adminEmails[0], cloudflare_user_id: "cli:" + cfg.accountId }] };
  await verifyIdentityUpload(api, legacy, true, "db", null);
  api.workerDomains = async () => [{ hostname: cfg.hostname, service: cfg.name + "-auth", zone_id: "zone", environment: "staging" }];
  await assert.rejects(verifyIdentityUpload(api, legacy, true, "db", null), /domain differs/);
  api.workerDomains = async () => [];
  api.request = async () => ({ bindings: [{ name: "NATHAN_ADMIN_ORIGIN", type: "plain_text" }] });
  await assert.rejects(verifyIdentityUpload(api, legacy, true, "db", null), /Restore/);
  await assert.rejects(verifyIdentityUpload(api, legacy, false, "db", null), /resources changed/);
  api.workers = async () => ({ error: "cannot enumerate" });
  await assert.rejects(verifyIdentityUpload(api, legacy, true, "db", null), /inventory/);
});


test("script upload retains live bindings during activation and applies only outstanding Durable Object migrations", async () => {
  const worker = { name: "private-test", migrations: [{ tag: "one", new_sqlite_classes: ["One"] }, { tag: "two", new_classes: ["Two"] }] };
  const sends = [];
  const api = { accountId: "example", async request(path, init) {
    assert.equal(path, "/accounts/example/workers/scripts/private-test");
    assert.equal(init.method, "PUT");
    sends.push(JSON.parse(await init.body.get("metadata").text()));
  }};
  const form = new FormData();
  form.set("metadata", JSON.stringify({ main_module: "index.js", keep_bindings: ["json", "plain_text", "secret_text"], migrations: { stale: true } }));
  form.set("index.js", new File(["export default {}"], "index.js"));
  await activateIdentityWorker(api, worker, form, "one");
  assert.deepEqual(sends[0].migrations, { old_tag: "one", new_tag: "two", steps: [{ new_classes: ["Two"] }] });
  await activateIdentityWorker(api, worker, form, "two");
  assert.equal(sends[1].migrations, undefined);
  await activateIdentityWorker(api, worker, form, null);
  assert.deepEqual(sends[2].migrations.steps, [{ new_sqlite_classes: ["One"] }, { new_classes: ["Two"] }]);
  await assert.rejects(activateIdentityWorker(api, worker, form, "newer"), /unknown/);
  assert.equal(sends.length, 3);
});
