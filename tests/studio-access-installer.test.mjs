import test from "node:test";
import assert from "node:assert/strict";
import { inspectStudioInstallation, reconcileStudioAccess, studioAccessOptions } from "../scripts/lib/studio-access.mjs";
import { validateConfig, buildPlan } from "../scripts/lib/config.mjs";
import { createGeneratedConfig } from "../scripts/lib/wrangler.mjs";
import { readFile, rm } from "node:fs/promises";

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
    s => { s.apps[0].options_preflight_bypass = true; }
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
  await inspectStudioInstallation(api, cfg, snapshot);
  granted = false;
  await assert.rejects(inspectStudioInstallation(api, cfg, snapshot), /grants/);
  granted = true;
  owner.cloudflare_user_id = "another installation";
  await assert.rejects(inspectStudioInstallation(api, cfg, snapshot), /owner/);
  bindings[0].id = "unrelated";
  await assert.rejects(inspectStudioInstallation(api, cfg, snapshot), /database/);
});
