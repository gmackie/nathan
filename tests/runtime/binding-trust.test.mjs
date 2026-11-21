/**
 * NATH-18 in workerd:
 * (a) NathanVerifier.getPrincipal is app-scoped: a binding pinned to an application learns who holds
 *     a Nathan session cookie only when the evaluator allows that user for that application, and never
 *     learns the global Better Auth role;
 * (b) the per-connection SCIM Durable Object answers only the identity Worker: another Worker that
 *     binds the NathanScimDirectory class (cross-script binding) gets nothing.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { bundle, migrate, randomKey, start, COMPAT, insertSession } from "./helpers.mjs";

const HOST = "login.example.test";
const SECRET = randomKey() + randomKey();

const PROBE = 'export default { async fetch(request, env) {\n' +
  '  const { method, args } = await request.json();\n' +
  '  try { return Response.json({ ok: true, result: await env.NATHAN[method](...args) }); }\n' +
  '  catch (error) { return Response.json({ ok: false, error: String(error && error.message || error) }); }\n' +
  '} };';
const probe = (name, binding) => ({ name, modules: true, ...COMPAT, script: PROBE, serviceBindings: { NATHAN: binding } });
/** A Worker that binds the identity Worker's Durable Object class directly, as a misconfigured or hostile app could. */
const FOREIGN = 'export default { async fetch(request, env) {\n' +
  '  const { path, method, headers, rpc } = await request.json();\n' +
  '  const stub = env.DIR.getByName("connection:acme");\n' +
  '  try {\n' +
  '    if (rpc) return Response.json({ ok: true, result: await stub[rpc]() });\n' +
  '    const r = await stub.fetch(new Request("https://scim.internal" + path, { method, headers }));\n' +
  '    return Response.json({ ok: true, status: r.status, body: await r.text() });\n' +
  '  } catch (error) { return Response.json({ ok: false, error: String(error && error.message || error) }); }\n' +
  '} };';

let mf, db;
const cookies = {};
before(async () => {
  mf = await start({
    workers: [
      probe("billing-app", { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "billing" } }),
      probe("unpinned-app", { name: "auth", entrypoint: "NathanVerifier" }),
      { name: "foreign", modules: true, ...COMPAT, script: FOREIGN,
        durableObjects: { DIR: { className: "NathanScimDirectory", scriptName: "auth", useSQLite: true } } },
      {
        name: "auth", modules: true, ...COMPAT, scriptPath: bundle("auth"),
        d1Databases: { DB: "trust-auth-db" },
        durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
        bindings: {
          NATHAN_ISSUER: "https://" + HOST, NATHAN_ADMIN_EMAILS: "admin@example.test",
          NATHAN_SECURITY_PROFILE: "business", NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_INSTALL_ACTIVE: "true",
          NATHAN_MCP_WRITE_ENABLED: "false", NATHAN_REALM_APEX: "", ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false",
          NATHAN_ADMIN_STEPUP_REQUIRED: "true", BETTER_AUTH_SECRET: SECRET, NATHAN_CONFIG_KEY: randomKey()
        }
      }
    ]
  });
  db = await mf.getD1Database("DB", "auth");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(db, "migrations/" + file);
  const sql = (statement, ...params) => db.prepare(statement).bind(...params).run();
  const now = new Date().toISOString();
  // u-bill may use billing; u-pay may use payroll only; u-root is a global Better Auth admin without a billing grant.
  for (const [id, role] of [["u-bill", "user"], ["u-pay", "user"], ["u-root", "admin"]])
    await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,1,?,?,?)', id, id, id + "@example.test", now, now, role);
  for (const app of ["billing", "payroll"]) {
    await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES (?,?,1,'approved')", app, app + ".example.test");
    await sql("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES (?,'records:read')", app);
    await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES (?,'viewer')", app);
    await sql("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES (?,'viewer','records:read')", app);
  }
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','billing','viewer','user','u-bill','test')");
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g2','payroll','viewer','user','u-pay','test')");
  for (const id of ["u-bill", "u-pay", "u-root"]) cookies[id] = (await insertSession(db, SECRET, id)).cookie;
  // A SCIM connection with one staged user, written through the identity Worker's own SCIM route.
  await sql("INSERT INTO nathan_scim_connections(id,domain,enabled,created_by) VALUES ('acme','acme.example',1,'test')");
});
after(() => mf?.dispose());

async function call(worker, method, ...args) {
  return (await (await mf.getWorker(worker)).fetch("https://probe.internal/", { method: "POST", body: JSON.stringify({ method, args }) })).json();
}
async function foreign(body) {
  return (await (await mf.getWorker("foreign")).fetch("https://probe.internal/", { method: "POST", body: JSON.stringify(body) })).json();
}

test("getPrincipal answers only for users the pinned application allows, without the global role", async () => {
  const allowed = await call("billing-app", "getPrincipal", cookies["u-bill"]);
  assert.equal(allowed.ok, true, allowed.error);
  assert.equal(allowed.result.sub, "u-bill");
  assert.equal(allowed.result.email, "u-bill@example.test");
  assert.equal(allowed.result.applicationId, "billing");
  assert.deepEqual(allowed.result.roles, ["viewer"]);
  assert.deepEqual(allowed.result.permissions, ["records:read"]);
  assert.ok(!("role" in allowed.result), "the global Better Auth role is not disclosed to app Workers");
  for (const id of ["u-pay", "u-root"]) {
    const denied = await call("billing-app", "getPrincipal", cookies[id]);
    assert.equal(denied.ok, true, denied.error);
    assert.equal(denied.result, null, id + " has a valid Nathan session but no billing access: nothing is disclosed");
  }
  assert.equal((await call("billing-app", "getPrincipal", "garbage")).result, null);
  assert.equal((await call("unpinned-app", "getPrincipal", cookies["u-bill"])).result, null, "an unpinned binding learns nothing");
});

test("access() does not disclose the subject of a denied session either", async () => {
  const denied = await call("billing-app", "access", { cookie: cookies["u-pay"] });
  assert.equal(denied.result.allowed, false);
  assert.equal(denied.result.sub, null);
  assert.equal(denied.result.email, null);
  const allowed = await call("billing-app", "access", { cookie: cookies["u-bill"] });
  assert.equal(allowed.result.allowed, true);
  assert.equal(allowed.result.sub, "u-bill");
  assert.equal((await call("billing-app", "authorize", { cookie: cookies["u-pay"] })).result, false);
  assert.equal((await call("billing-app", "authorize", { cookie: cookies["u-bill"] })).result, true);
});

test("another Worker that binds the SCIM Durable Object class gets nothing from it", async () => {
  const base = { "X-Nathan-SCIM-Base": "https://" + HOST + "/scim/v2/acme" };
  for (const [path, method, headers] of [
    ["/Users", "GET", base],
    ["/ServiceProviderConfig", "GET", base],
    ["/__nathan/outbox", "GET", { ...base, "X-Nathan-SCIM-Admin": "outbox" }],
    ["/__nathan/resync", "POST", { ...base, "X-Nathan-SCIM-Admin": "resync" }]
  ]) {
    const answer = await foreign({ path, method, headers });
    assert.equal(answer.ok, true, answer.error);
    assert.equal(answer.status, 403, path + ": " + answer.body);
  }
  // RPC methods of the Durable Object are not an alternative way in.
  for (const rpc of ["resync", "reconcile", "pendingCount", "outboxHead"]) {
    const answer = await foreign({ rpc });
    assert.equal(answer.ok, false, rpc + " must not be callable over RPC: " + JSON.stringify(answer.result));
  }
});
