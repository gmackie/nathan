import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { COMPAT, bundle, enrollAdmin, insertSession, migrate, randomKey, start, studioPost, studioShell } from "./helpers.mjs";

const origin = "https://library.example.test";
const secret = randomKey() + randomKey();
const bindings = {
  NATHAN_ISSUER: origin, NATHAN_ADMIN_EMAILS: "admin@example.test",
  NATHAN_SECURITY_PROFILE: "business", NATHAN_INSTALL_ACTIVE: "true",
  ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false", BETTER_AUTH_SECRET: secret, NATHAN_CONFIG_KEY: randomKey()
};
const identity = (name, scriptPath, vars = {}) => ({
  name, modules: true, ...COMPAT, scriptPath, bindings: { ...bindings, ...vars },
  d1Databases: { DB: name }, durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } }
});
const peer = target => ({
  name: target + "-peer", modules: true, ...COMPAT,
  scriptPath: bundle("embedded-peer"),
  serviceBindings: { IDENTITY: { name: target, entrypoint: "NathanService" } }
});

let mf, app, rpc, db, admin, ordinaryAdminSession;
before(async () => {
  const mounted = bundle("embedded");
  mf = await start({ workers: [
    // The Node-to-workerd proxy also checks Origin against its test routes.
    { ...identity("library", mounted), routes: [origin + "/*", "https://alias.example.test/*"] },
    peer("library"), identity("inactive", mounted, { NATHAN_INSTALL_ACTIVE: "false" }),
    identity("standalone", bundle("auth"), { NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_STEPUP_REQUIRED: "true" }), peer("standalone")
  ] });
  app = await mf.getWorker("library");
  rpc = await mf.getWorker("library-peer");
  db = await mf.getD1Database("DB", "library");
  for (const name of ["library", "standalone"]) {
    const database = await mf.getD1Database("DB", name);
    const directory = name === "library" ? ".nathan/build-embedded/migrations" : "migrations";
    for (const file of readdirSync(directory).filter(f => f.endsWith(".sql")).sort()) await migrate(database, directory + "/" + file);
  }
  admin = await enrollAdmin(db, secret);
  ordinaryAdminSession = await insertSession(db, secret, "admin-1");
});
after(() => mf?.dispose());

test("the host owns its home and business routes, including names adjacent to Nathan routes", async () => {
  for (const path of ["/", "/healthz", "/api/books", "/api/authors", "/studio-news", "/.well-known/security.txt"]) {
    assert.equal(await (await app.fetch(origin + path)).text(), "library " + path);
  }
  assert.equal(await (await app.fetch(origin + "/", { method: "POST", body: "hello" })).text(), "hello");
  const cookies = admin.cookie + "; __Host-nathan-mcp-return=" + Buffer.from("/connections").toString("base64url");
  const resumed = await app.fetch(origin + "/", { headers: { Cookie: cookies }, redirect: "manual" });
  assert.equal(resumed.headers.get("Location"), origin + "/connections");
  assert.match(resumed.headers.get("Set-Cookie"), /Max-Age=0/);
  const expired = await app.fetch(origin + "/", { headers: { Cookie: "__Host-nathan-saml-idp=expired" } });
  assert.equal(await expired.text(), "library /");
  assert.equal((await (await app.fetch(origin + "/__nathan/healthz")).json()).system, "nathan");
});

test("the host reads an allowed principal only at its canonical origin", async () => {
  async function principal(cookie, base = origin, worker = app) {
    return (await worker.fetch(base + "/me", { headers: { Cookie: cookie } })).json();
  }
  assert.equal(await principal(admin.cookie), null);
  await db.prepare("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('library','library.example.test',1,'any_signed_in')").run();
  assert.deepEqual(await principal(admin.cookie), {
    sub: "admin-1", email: "admin@example.test", applicationId: "library", roles: [], permissions: []
  });
  const other = await mf.getWorker("standalone-peer");
  const separateSession = await other.fetch(origin + "/api/auth/get-session", { headers: { Cookie: admin.cookie } });
  assert.equal(await separateSession.json(), null);
  assert.equal(await principal(""), null);
  const expired = await insertSession(db, secret, "admin-1");
  await db.prepare('UPDATE "session" SET "expiresAt"=? WHERE "id"=?').bind(new Date(0).toISOString(), expired.id).run();
  assert.equal(await principal(expired.cookie), null);
  assert.equal(await principal(admin.cookie, "https://alias.example.test"), null);
  assert.equal(await principal(admin.cookie, origin, await mf.getWorker("inactive")), null);
  await db.prepare("UPDATE nathan_applications SET enabled=0 WHERE id='library'").run();
  assert.equal(await principal(admin.cookie), null);
});

test("scheduled events run both the host job and Nathan maintenance", async () => {
  await db.prepare("CREATE TABLE host_events(name TEXT)").run();
  await db.prepare("INSERT INTO nathan_mcp_limits(id,request_count,expires_at) VALUES ('expired',1,0)").run();
  await app.scheduled({ cron: "0 * * * *" });
  assert.equal((await db.prepare("SELECT name FROM host_events").first()).name, "library cron");
  assert.equal(await db.prepare("SELECT id FROM nathan_mcp_limits WHERE id='expired'").first(), null);
});

test("both Worker modes expose their canonical issuer through the named RPC entrypoint", async () => {
  for (const name of ["library", "library-peer", "standalone", "standalone-peer"]) {
    const worker = await mf.getWorker(name);
    const result = await worker.fetch(origin + "/api/auth/.well-known/openid-configuration");
    assert.equal((await result.json()).issuer, origin + "/api/auth", name);
    const misdirected = await worker.fetch("https://alias.example.test/sign-in");
    assert.equal(misdirected.status, 421);
    await misdirected.text();
  }
  const peerResponse = await rpc.fetch(origin + "/api/books");
  assert.equal(peerResponse.status, 404);
  await peerResponse.text();
  const disabled = await (await mf.getWorker("inactive")).fetch(origin + "/sign-in");
  assert.equal(disabled.status, 503);
});

test("RPC renders Kumo Studio and applies the same credential, step-up, origin and audit rules as HTTP", async () => {
  const path = "/studio/api/v1/apps";
  for (const worker of [app, rpc]) {
    const anonymous = await worker.fetch(origin + path);
    assert.equal(anonymous.status, 401);
    await anonymous.text();
    const stale = await worker.fetch(origin + path, { headers: { Cookie: ordinaryAdminSession.cookie } });
    assert.equal(stale.status, 403);
    assert.equal((await stale.json()).error.code, "step_up_required");
    const denied = await worker.fetch(origin + path, { method: "POST", headers: {
      Cookie: admin.cookie, Origin: "https://alias.example.test", "Content-Type": "application/json"
    }, body: "{}" });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).error.code, "cross_origin");
  }
  const shell = await rpc.fetch(origin + "/studio", { headers: { Cookie: admin.cookie } });
  await studioShell(rpc, origin, shell);
  const write = await studioPost(rpc, origin, path, { id: "reader", hostname: "reader.example.test" }, admin.cookie);
  assert.equal(write.status, 200, await write.text());
  const list = await app.fetch(origin + path, { headers: { Cookie: admin.cookie } });
  assert.ok((await list.json()).data.applications.some(row => row.id === "reader"));
  assert.equal((await db.prepare("SELECT actor FROM nathan_security_audit WHERE target='reader' AND outcome='succeeded'").first()).actor, "admin-1");
});

test("an RPC request uses Nathan's shared network rate limit", async () => {
  const response = await rpc.fetch(origin + "/mcp-oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "192.0.2.10" },
    body: JSON.stringify({ redirect_uris: ["https://reader.example.test/callback"] })
  });
  assert.equal(response.status, 201, await response.text());
  const hash = createHash("sha256").update("unknown").digest("base64url").slice(0, 22);
  const row = await db.prepare("SELECT count(*) AS n FROM nathan_mcp_limits WHERE id GLOB ?").bind("mcp-oauth:register:" + hash + ":*").first();
  assert.equal(row.n, 1);
});
