/**
 * NATH-13 security review (MEDIUM): the service binding that API Workers and gateways get to the
 * identity Worker answers only for the application the binding is pinned to (binding props), and
 * never exposes the directory. Probes are Workers bound exactly the way an app would be.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { bundle, migrate, randomKey, start, COMPAT } from "./helpers.mjs";

const HOST = "login.example.test";
const ISSUER = "https://" + HOST + "/api/auth";
const SECRET = randomKey() + randomKey();

/** Calls one RPC method on its NATHAN binding and reports the result or the error. */
const PROBE = 'export default { async fetch(request, env) {\n' +
  '  const { method, args } = await request.json();\n' +
  '  try { return Response.json({ ok: true, result: await env.NATHAN[method](...args) }); }\n' +
  '  catch (error) { return Response.json({ ok: false, error: String(error && error.message || error) }); }\n' +
  '} };';
const probe = (name, binding) => ({ name, modules: true, ...COMPAT, script: PROBE, serviceBindings: { NATHAN: binding } });

let mf, db;
before(async () => {
  mf = await start({
    workers: [
      probe("billing-app", { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "billing" } }),
      probe("unpinned-app", { name: "auth", entrypoint: "NathanVerifier" }),
      probe("malformed-app", { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "Billing!" } }),
      {
        name: "auth", modules: true, ...COMPAT, scriptPath: bundle("auth"),
        d1Databases: { DB: "binding-auth-db" },
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
  for (const id of ["u-bill", "u-pay"])
    await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,1,?,?)', id, id, id + "@example.test", now, now);
  for (const app of ["billing", "payroll"]) {
    await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES (?,?,1,'approved')", app, app + ".example.test");
    await sql("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES (?,'records:read')", app);
    await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES (?,'viewer')", app);
    await sql("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES (?,'viewer','records:read')", app);
  }
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','billing','viewer','user','u-bill','test')");
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g2','payroll','viewer','user','u-pay','test')");
});
after(() => mf?.dispose());

async function call(worker, method, ...args) {
  const response = await (await mf.getWorker(worker)).fetch("https://probe.internal/", { method: "POST", body: JSON.stringify({ method, args }) });
  return response.json();
}

test("a binding pinned to billing answers for billing users", async () => {
  const answer = await call("billing-app", "resolveAccess", { applicationId: "billing", subject: "u-bill" });
  assert.equal(answer.ok, true, answer.error);
  assert.equal(answer.result.allowed, true);
  assert.deepEqual(answer.result.roles, ["viewer"]);
});

test("a billing binding cannot read another application's decisions", async () => {
  const answer = await call("billing-app", "resolveAccess", { applicationId: "payroll", subject: "u-pay" });
  assert.equal(answer.ok, true, answer.error);
  assert.equal(answer.result.allowed, false);
  assert.deepEqual(answer.result.roles, []);
  assert.deepEqual(answer.result.permissions, []);
  assert.equal(answer.result.email, null, "no profile data from another app's decision");
  const cookie = await call("billing-app", "access", { applicationId: "payroll", cookie: "" });
  assert.equal(cookie.ok, true, cookie.error);
  assert.equal(cookie.result.allowed, false);
  assert.equal((await call("billing-app", "authorize", { applicationId: "payroll", cookie: "" })).result, false);
});

test("an app binding cannot read the directory", async () => {
  for (const [method, args] of [["directoryPrincipal", [ISSUER + "#u-pay"]], ["directoryChanges", [{}]]]) {
    const answer = await call("billing-app", method, ...args);
    assert.equal(answer.ok, false, method + " must not be callable over an app binding: " + JSON.stringify(answer.result));
  }
});

test("a binding without a valid pinned application gets no answers", async () => {
  for (const worker of ["unpinned-app", "malformed-app"]) {
    const answer = await call(worker, "resolveAccess", { applicationId: "billing", subject: "u-bill" });
    assert.equal(answer.ok, true, answer.error);
    assert.equal(answer.result.allowed, false, worker);
    assert.deepEqual(answer.result.roles, [], worker);
  }
});
