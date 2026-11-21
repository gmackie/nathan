/**
 * NATH-11 review fixes in workerd: reconciliation work per Durable Object invocation is bounded.
 * 1,200 directory users are created just in time by one resync and 3,000 mapped group memberships are
 * added and then removed, each spread over many invocations (RECONCILE_LIMITS: at most 100 statements
 * per D1 batch, 500 per invocation; the connection's alarm continues the backlog). A change that can
 * never be applied is shown at the head of the outbox and skipped by an administrator after review.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, enrollAdmin, studioPost } from "./helpers.mjs";

const HOST = "login.scale.test", ORIGIN = "https://" + HOST, SECRET = "s".repeat(32) + "t".repeat(32);
const USERS = 1200, GROUPS = [[0, 1000], [200, 1200], [100, 1100]];
let mf, db, auth, admin, token;
const ids = [], groups = [];

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const count = async (sql, ...params) => Number(Object.values(await db.prepare(sql).bind(...params).first())[0]);
const studio = (path, body) => studioPost(auth, ORIGIN, path, body, admin.cookie);
const scim = (method, path, body) => auth.fetch(ORIGIN + "/scim/v2/big" + path, {
  method, body: body === undefined ? undefined : JSON.stringify(body),
  headers: { Authorization: "Bearer " + token, ...(body === undefined ? {} : { "Content-Type": "application/scim+json" }) }
});
async function ok(response, status = 200) {
  const text = await response.text();
  assert.equal(response.status, status, text);
  return text ? JSON.parse(text) : null;
}
const outbox = async () => ok(await auth.fetch(ORIGIN + "/studio/api/scim/outbox?id=big", { headers: { Cookie: admin.cookie } }));
/** Waits for the connection's alarms to drain the outbox; returns how many polls saw work left. */
async function drained(limitMs = 180_000) {
  const deadline = Date.now() + limitMs;
  let polls = 0;
  for (;;) {
    const view = await outbox();
    if (view.pending === 0) return polls;
    if (view.head[0]?.attempts > 0) throw Error("reconciliation failed: " + JSON.stringify(view.head[0]));
    if (Date.now() > deadline) throw Error("outbox not drained: " + JSON.stringify(view).slice(0, 300));
    polls++;
    await sleep(100);
  }
}
async function inBatches(items, size, fn) {
  for (let i = 0; i < items.length; i += size) await Promise.all(items.slice(i, i + size).map(fn));
}

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, NATHAN_ADMIN_EMAILS: "admin@example.test", NATHAN_SCIM_RATE_LIMIT: "100000" });
  db = await mf.getD1Database("DB");
  // NATH-16: just-in-time creation at scale, in a self-service installation.
  await db.prepare("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','test')").run();
  // dispatchFetch keeps the Origin header (the worker proxy of getWorker() refuses it here).
  auth = { fetch: (url, init) => mf.dispatchFetch(url, init) };
  admin = await enrollAdmin(db, SECRET);
  await db.prepare('INSERT INTO "ssoProvider"("id","issuer","userId","providerId","domain","domainVerified") VALUES (\'sso-big\',\'https://idp.big.example\',\'admin-1\',\'big-sso\',\'big.example\',1)').run();
  token = (await ok(await studio("/studio/api/scim/connections", { id: "big", domain: "big.example" }))).bearerToken;
  await ok(await studio("/studio/api/scim/status", { id: "big", enabled: true, confirm: "CONFIRM ENABLE big" }));
  for (const [i] of GROUPS.entries())
    await db.prepare("INSERT INTO nathan_groups(id,name,created_by) VALUES (?,?,'test')").bind("team-" + i, "Team " + i).run();
});
after(() => mf?.dispose());

test("one resync creates 1,200 accounts just in time over many bounded invocations", async () => {
  // Staged while linking is off: each create applies one cheap row.
  const numbers = [...Array(USERS).keys()];
  await inBatches(numbers, 16, async i => {
    const email = "u" + i + "@big.example";
    const created = await ok(await scim("POST", "/Users", { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: email,
      externalId: "ext-" + i, displayName: "User " + i, emails: [{ value: email, primary: true }], active: true }), 201);
    ids[i] = created.id;
  });
  for (const [i] of GROUPS.entries())
    await ok(await studio("/studio/api/scim/mappings", { op: "map", connection: "big", refType: "externalId", ref: "g-" + i, group: "team-" + i,
      confirm: "CONFIRM MAP big/g-" + i + " TO team-" + i }));
  const saved = await ok(await studio("/studio/api/scim/settings", { id: "big", linking: true, jit: true, confirm: "CONFIRM SCIM SETTINGS big" }));
  assert.equal(saved.resync.applied, true);
  assert.ok(saved.resync.pending > 0, "more than one invocation's budget: the alarm continues (" + saved.resync.pending + " left)");
  await drained();
  assert.equal(await count("SELECT count(*) FROM nathan_scim_users WHERE connection_id='big' AND link_method='jit'"), USERS);
  assert.equal(await count('SELECT count(*) FROM "user" WHERE "email" LIKE \'%@big.example\''), USERS);
  assert.equal(await count("SELECT count(*) FROM nathan_rbac_changes WHERE kind='user.linked'"), USERS, "each link exactly once");
});

test("3,000 mapped memberships are added in bounded batches, each exactly once", async () => {
  for (const [i, [from, to]] of GROUPS.entries()) {
    const members = ids.slice(from, to).map(value => ({ value }));
    // Additions may finish in the background, so the directory gets its answer at once.
    const group = await ok(await scim("POST", "/Groups", { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "Group " + i,
      externalId: "g-" + i, members }), 201);
    groups.push(group);
    const applied = await count("SELECT count(*) FROM nathan_group_members WHERE group_id=?", "team-" + i);
    assert.ok(applied < 1000, "the request applied only part of a 1,000-member group itself (" + applied + ")");
    const polls = await drained();
    assert.ok(polls >= 1, "the connection's alarm finished the group");
    assert.equal(await count("SELECT count(*) FROM nathan_group_members WHERE group_id=?", "team-" + i), 1000);
  }
  assert.equal(await count("SELECT count(*) FROM nathan_group_members WHERE group_id LIKE 'team-%'"), 3000);
  assert.equal(await count("SELECT count(*) FROM nathan_rbac_changes WHERE kind='member.added'"), 3000, "one feed row per membership");
});

test("removing 1,000 members answers 503 until every removal is applied, then the retry succeeds", async () => {
  const [group] = groups;
  const empty = { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", path: "members", value: [] }] };
  const first = await scim("PATCH", "/Groups/" + group.id, empty);
  assert.equal(first.status, 503, "removals reduce access: success is reported only after they are applied");
  assert.equal(first.headers.get("Retry-After"), "10");
  await drained();
  await ok(await scim("PATCH", "/Groups/" + group.id, empty));
  assert.equal(await count("SELECT count(*) FROM nathan_group_members WHERE group_id='team-0'"), 0);
  assert.equal(await count("SELECT count(*) FROM nathan_rbac_changes WHERE kind='member.removed'"), 1000);
});

test("a change that can never apply is reviewed at the head of the outbox and skipped by an administrator", async () => {
  // D1 refuses this one user (as a permanently failing statement would).
  await db.prepare("CREATE TRIGGER poison BEFORE INSERT ON nathan_scim_users WHEN NEW.user_name='poison@big.example' BEGIN SELECT RAISE(ABORT,'poisoned row'); END").run();
  const user = email => ({ schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: email, externalId: email, emails: [{ value: email }], active: true });
  assert.equal((await scim("POST", "/Users", user("poison@big.example"))).status, 503);
  assert.equal((await scim("POST", "/Users", user("next@big.example"))).status, 503, "the poisoned entry blocks the connection");
  const view = await outbox();
  const head = view.head[0];
  assert.equal(head.kind, "User");
  assert.equal(head.resource.userName, "poison@big.example");
  assert.ok(head.attempts >= 1);
  assert.match(head.lastError, /poisoned row/);
  const skip = { op: "skip", connection: "big", kind: "User", id: head.resourceId, seq: head.seq, confirm: "CONFIRM SKIP USER " + head.resourceId };
  assert.equal((await studio("/studio/api/scim/outbox", { ...skip, confirm: "CONFIRM SKIP" })).status, 409, "exact confirmation");
  assert.equal((await studio("/studio/api/scim/outbox", { ...skip, seq: head.seq + 1 })).status, 409, "only the entry the administrator reviewed");
  const skipped = await ok(await studio("/studio/api/scim/outbox", skip));
  assert.match(skipped.warning, /NOT blocked/);
  assert.ok(await db.prepare("SELECT 1 FROM nathan_security_audit WHERE action='scim_outbox_skip' AND outcome='succeeded'").first());
  assert.ok(await db.prepare("SELECT 1 FROM nathan_scim_errors WHERE message LIKE 'Skipped by administrator%'").first());
  await ok(await scim("POST", "/Users", user("next2@big.example")), 201);
  await db.prepare("DROP TRIGGER poison").run();
});
