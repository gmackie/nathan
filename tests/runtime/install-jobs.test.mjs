import test, { after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { bundle, migrate, randomKey, cookiesOf, start } from "./helpers.mjs";

const INSTALLER = "https://install.example.test";
const ACCOUNT = "a".repeat(32), ZONE = "b".repeat(32);
const API = "https://api.cloudflare.com/client/v4";
const manifest = {
  version: 1, release: "0.0.0+runtime-test", builtAt: "2026-11-21T00:00:00Z",
  worker: { mainModule: "worker.js", compatibilityDate: "2026-10-27", compatibilityFlags: ["nodejs_compat"], observability: { enabled: true } },
  files: [{ type: "module", name: "worker.js", path: "modules/worker.js", sha256: "0".repeat(64), size: 1, contentType: "application/javascript+module" }]
};

/** A small stateful Cloudflare API fake. */
const cf = { databases: [], creates: 0, loseCreateResponse: false, manifestGate: null, manifestFetches: 0 };
beforeEach(() => Object.assign(cf, { databases: [], creates: 0, loseCreateResponse: false, manifestGate: null, manifestFetches: 0 }));
const ok = result => Response.json({ success: true, result });
async function cloudflare(request) {
  const url = new URL(request.url);
  if (url.origin === "https://dash.cloudflare.com" && url.pathname === "/oauth2/token")
    return Response.json({ access_token: "cf-access", refresh_token: "cf-refresh", expires_in: 3600 });
  if (url.origin !== new URL(API).origin) return new Response("unexpected " + url.href, { status: 599 });
  const path = url.pathname.replace("/client/v4", "") + url.search;
  if (path === "/user") return ok({ id: "cf-user-1", email: "owner@example.test" });
  if (path === "/accounts?per_page=100") return ok([{ id: ACCOUNT, name: "Test" }]);
  if (path.startsWith("/zones?account.id=")) return ok([{ id: ZONE, name: "example.test", status: "active" }]);
  if (path === "/accounts/" + ACCOUNT + "/workers/scripts") return ok([]);
  if (path === "/accounts/" + ACCOUNT + "/workers/domains") return ok([]);
  if (path.startsWith("/zones/" + ZONE + "/dns_records")) return ok([]);
  if (path === "/accounts/" + ACCOUNT + "/d1/database" && request.method === "GET") return ok(cf.databases);
  if (path === "/accounts/" + ACCOUNT + "/d1/database" && request.method === "POST") {
    cf.creates++;
    const db = { uuid: crypto.randomUUID(), name: (await request.json()).name };
    cf.databases.push(db);
    // The database exists, but the installer never sees the response.
    if (cf.loseCreateResponse) return Response.json({ success: false, errors: [{ message: "timeout" }] }, { status: 504 });
    return ok(db);
  }
  if (/\/d1\/database\/[a-f0-9-]{36}\/query$/.test(path)) return ok([{ success: true, results: [{ n: 0 }] }]);
  return new Response("unexpected " + request.method + " " + path, { status: 599 });
}
async function assets(request) {
  const path = new URL(request.url).pathname;
  if (path === "/release/manifest.json") {
    cf.manifestFetches++;
    if (cf.manifestGate && cf.manifestFetches === cf.manifestGate.fetch) await cf.manifestGate.promise;
    return Response.json(manifest);
  }
  return new Response("not found", { status: 404 });
}

let mf, cookie;
const instances = [];
after(() => Promise.all(instances.map(m => m.dispose())));
async function setup() {
  mf = await start({
    scriptPath: bundle("installer"),
    d1Databases: { INSTALLER_DB: "installer-db-" + crypto.randomUUID() },
    serviceBindings: { ASSETS: assets },
    outboundService: cloudflare,
    bindings: { PUBLIC_ORIGIN: INSTALLER, CF_OAUTH_CLIENT_ID: "cf-client", CF_OAUTH_CLIENT_SECRET: "cf-secret",
      CF_OAUTH_SCOPES: "user-details.read", INSTALLER_ENCRYPTION_KEY: randomKey() }
  });
  instances.push(mf);
  const db = await mf.getD1Database("INSTALLER_DB");
  for (const file of readdirSync("migrations/installer").filter(f => f.endsWith(".sql")).sort())
    await migrate(db, "migrations/installer/" + file);
  const begin = await mf.dispatchFetch(INSTALLER + "/api/login", { redirect: "manual" });
  const state = cookiesOf(begin)["__Host-nathan-installer-state"].value;
  const callback = await mf.dispatchFetch(INSTALLER + "/api/callback?code=c&state=" + state,
    { redirect: "manual", headers: { Cookie: "__Host-nathan-installer-state=" + state } });
  cookie = "__Host-nathan-installer=" + cookiesOf(callback)["__Host-nathan-installer"].value;
}
const post = (path, body) => mf.dispatchFetch(INSTALLER + path, {
  method: "POST", body: JSON.stringify(body),
  headers: { Cookie: cookie, Origin: INSTALLER, "Content-Type": "application/json" }
});
async function startInstall() {
  const response = await post("/api/install/start", {
    accountId: ACCOUNT, hostname: "auth.example.test", name: "nathan-test", realmEnabled: false,
    securityProfile: "business", adminEmail: "owner@example.test"
  });
  assert.equal(response.status, 200, await response.clone().text());
  return (await response.json()).job.id;
}
const status = async id => (await (await mf.dispatchFetch(INSTALLER + "/api/install/status?id=" + id, { headers: { Cookie: cookie } })).json()).job;

test("an interrupted D1 create is adopted on retry instead of failing forever", async () => {
  await setup();
  const id = await startInstall();
  cf.loseCreateResponse = true;
  const first = await post("/api/install/advance", { id });
  assert.equal(first.status, 409, "lost create response surfaces as a retryable error");
  cf.loseCreateResponse = false;
  const retry = await post("/api/install/advance", { id });
  assert.equal(retry.status, 200, await retry.clone().text());
  const job = await status(id);
  assert.equal(job.stage, "schema");
  assert.equal(job.error, null);
  assert.equal(cf.creates, 1, "the retry must adopt, not create a second database");
});

test("a request that read the job before another finished the stage does not re-run it", async () => {
  await setup();
  const id = await startInstall();
  let release;
  // Whichever advance request reaches the release manifest second is held between
  // reading the job and claiming its lease, until the other request has finished.
  cf.manifestGate = { fetch: cf.manifestFetches + 2, promise: new Promise(resolve => { release = resolve; }) };
  const requests = [post("/api/install/advance", { id }), post("/api/install/advance", { id })];
  const tagged = requests.map((p, i) => p.then(response => ({ response, i })));
  const winner = await Promise.race(tagged);
  const firstResponse = winner.response;
  assert.equal(firstResponse.status, 200, await firstResponse.clone().text());
  release();
  const secondResponse = await requests[1 - winner.i];
  assert.equal(secondResponse.status, 409);
  assert.match((await secondResponse.json()).error, /refresh/i);
  const job = await status(id);
  assert.equal(job.stage, "schema");
  assert.equal(job.error, null, "a stale request must not record an error on the job");
  assert.equal(cf.creates, 1);
});
