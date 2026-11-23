/**
 * NATH-24: the Identity Studio JSON API v1 in the built identity Worker, with real Better Auth
 * sessions and Better Auth's own admin client endpoints. The same writes go through the legacy
 * /studio/api/* routes and through /studio/api/v1 and must leave the same audit rows.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, randomKey, enrollAdmin, insertSession, studioPost } from "./helpers.mjs";

const HOST = "login.example.test";
const ORIGIN = "https://" + HOST;
const SECRET = randomKey() + randomKey();
let mf, db, admin, member, unstepped;
after(() => mf?.dispose());

const fetcher = { fetch: (url, init) => mf.dispatchFetch(url, init) };
const get = (path, cookie) => mf.dispatchFetch(ORIGIN + path, { headers: cookie ? { Cookie: cookie } : {} });
const auditSince = async rowid => (await db.prepare("SELECT rowid AS rowid, actor, action, target, outcome FROM nathan_security_audit WHERE rowid>? ORDER BY rowid")
  .bind(rowid).all()).results;
const lastRow = async () => (await db.prepare("SELECT coalesce(max(rowid),0) AS n FROM nathan_security_audit").first()).n;
const strip = rows => rows.map(({ rowid, ...rest }) => rest);

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET });
  db = await mf.getD1Database("DB");
  admin = await enrollAdmin(db, SECRET);
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (\'u-alice\',\'Alice\',\'alice@example.test\',1,?,?,\'user\')').bind(now, now).run();
  member = await insertSession(db, SECRET, "u-alice");
  unstepped = await insertSession(db, SECRET, "admin-1");
});

test("v1 refuses anonymous, non-admin and unstepped sessions with stable codes", async () => {
  const anon = await get("/studio/api/v1/users");
  assert.equal(anon.status, 401);
  assert.equal((await anon.json()).error.code, "unauthenticated");
  const user = await get("/studio/api/v1/users", member.cookie);
  assert.equal(user.status, 403);
  assert.equal((await user.json()).error.code, "not_admin");
  const noStep = await get("/studio/api/v1/users", unstepped.cookie);
  assert.equal(noStep.status, 403);
  assert.equal((await noStep.json()).error.code, "step_up_required");
  const write = await mf.dispatchFetch(ORIGIN + "/studio/api/v1/clients", { method: "POST", body: JSON.stringify({ name: "x" }),
    headers: { Cookie: admin.cookie, Origin: "https://evil.example", "Content-Type": "application/json" } });
  assert.equal(write.status, 403);
  assert.equal((await write.json()).error.code, "cross_origin");
});

test("v1 reads return the legacy payloads inside the ok envelope", async () => {
  for (const path of ["/users", "/admins", "/security-policy", "/status", "/apps", "/clients"]) {
    const legacy = await get("/studio/api" + path, admin.cookie);
    const v1 = await get("/studio/api/v1" + path, admin.cookie);
    assert.equal(legacy.status, 200, path);
    assert.equal(v1.status, 200, path);
    assert.deepEqual(await v1.json(), { ok: true, data: await legacy.json() }, path);
  }
});

test("client create and disable leave the same audit rows through legacy and v1 routes", async () => {
  const create = async (prefix, name) => {
    const before = await lastRow();
    const r = await studioPost(fetcher, ORIGIN, prefix + "/clients", { name, kind: "external", redirectUri: "https://" + name + ".example.test/cb" }, admin.cookie);
    assert.equal(r.status, 200, await r.clone().text());
    const json = await r.json();
    return { clientId: (json.data ?? json).client_id, rows: strip(await auditSince(before)) };
  };
  const legacy = await create("/studio/api", "legacy");
  const v1 = await create("/studio/api/v1", "modern");
  assert.deepEqual(v1.rows.map(r => ({ ...r, target: r.target.replace("modern", "X") })), legacy.rows.map(r => ({ ...r, target: r.target.replace("legacy", "X") })));
  assert.deepEqual(v1.rows.map(r => r.outcome), ["attempted", "succeeded"]);

  const disable = async (prefix, clientId) => {
    const before = await lastRow();
    const r = await studioPost(fetcher, ORIGIN, prefix + "/clients/status", { clientId, disabled: true }, admin.cookie);
    assert.equal(r.status, 200, await r.clone().text());
    return strip(await auditSince(before)).map(row => ({ ...row, target: row.target === clientId ? "<client>" : row.target }));
  };
  const legacyRows = await disable("/studio/api", legacy.clientId);
  const v1Rows = await disable("/studio/api/v1", v1.clientId);
  assert.deepEqual(v1Rows, [{ actor: "admin-1", action: "oauth_client_disable", target: "<client>", outcome: "succeeded" }]);
  assert.deepEqual(v1Rows, legacyRows);
  const disabled = await db.prepare('SELECT count(*) AS n FROM "oauthClient" WHERE "clientId" IN (?,?) AND "disabled"=1').bind(legacy.clientId, v1.clientId).first();
  assert.equal(disabled.n, 2);
});

test("v1 validation errors are 400 validation_failed before the service runs, and the refused write is audited", async () => {
  const before = await lastRow();
  const r = await studioPost(fetcher, ORIGIN, "/studio/api/v1/rbac", { op: "group.upsert", id: 12 }, admin.cookie);
  assert.equal(r.status, 400);
  const body = await r.json();
  assert.equal(body.error.code, "validation_failed");
  assert.ok(body.error.issues.some(i => i.path === "id"));
  const legacy = await studioPost(fetcher, ORIGIN, "/studio/api/rbac", { op: "group.upsert", id: 12 }, admin.cookie);
  assert.equal(legacy.status, 409);
  const rows = strip(await auditSince(before));
  // v1 refuses at the schema (the service never runs) and records it; the legacy route's service
  // still writes its own "rejected" row.
  assert.deepEqual(rows, [
    { actor: "admin-1", action: "rbac.apply", target: "studio_api_v1", outcome: "refused_schema" },
    { actor: "admin-1", action: "rbac_group_upsert", target: "-", outcome: "rejected" }
  ]);
});
