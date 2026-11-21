/**
 * NATH-11 review fixes: reconciliation (src/auth/scim/lifecycle.ts) exercised directly against the
 * real migrations on node:sqlite. These tests call applyUser/applyGroup the way the connection's
 * Durable Object does, including the cases the Worker cannot easily produce on demand: duplicate
 * outbox rows for an applied revision, a stale revision arriving late, two appliers racing, the last
 * administrator, and a membership change larger than one invocation's statement budget.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { d1, migratedDatabase } from "./fixtures/d1-sqlite.mjs";
import { applyUser, applyGroup, adminProtection, Budget, RECONCILE_LIMITS, REVIEW_LIMITS, scimBanReason } from "../src/auth/scim/lifecycle.ts";
import { scimUserOperation } from "../src/auth/scim/reviews.ts";
import { scimConnectionView } from "../src/auth/scim/lifecycle-admin.ts";

const policy = { id: "acme", domain: "acme.example", organizationId: null, enabled: true, linking: true, jit: false, domainVerified: true };
const ADMIN_EMAILS = "root@acme.example";

function setup() {
  const db = migratedDatabase();
  db.exec("INSERT INTO nathan_scim_connections(id,domain,created_by,linking_enabled) VALUES ('acme','acme.example','t',1)");
  const env = { DB: d1(db), NATHAN_ADMIN_EMAILS: ADMIN_EMAILS, NATHAN_BOOTSTRAP_REQUIRED: "true" };
  const run = (sql, ...params) => db.prepare(sql).run(...params);
  const get = (sql, ...params) => { const r = db.prepare(sql).get(...params); return r ? { ...r } : null; };
  const count = (sql, ...params) => Number(Object.values(db.prepare(sql).get(...params))[0]);
  const user = (id, email, { role = "user", verified = 1 } = {}) =>
    run('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,?,0,0,?)', id, id, email, verified, role);
  const session = userId => run('INSERT INTO "session"("id","expiresAt","token","createdAt","updatedAt","userId") VALUES (?,?,?,0,0,?)',
    "s-" + crypto.randomUUID(), "2999-01-01", "t-" + crypto.randomUUID(), userId);
  return { db, env, run, get, count, user, session };
}
let n = 0;
const snap = (over = {}) => ({ id: over.id ?? crypto.randomUUID(), externalId: "ext-" + (++n), userName: "x@acme.example", displayName: "X",
  emails: [{ value: over.userName ?? "x@acme.example" }], active: true, deleted: false, revision: 1, groups: [], ...over });
const feedOf = (t, userId, kind) => t.count("SELECT count(*) FROM nathan_rbac_changes WHERE principal_id=? AND kind=?", userId, kind);
const banned = (t, userId) => Boolean(t.get('SELECT "banned" AS b FROM "user" WHERE "id"=?', userId).b);
const linkRow = (t, scimId, connection = "acme") => t.get("SELECT * FROM nathan_scim_users WHERE connection_id=? AND scim_id=?", connection, scimId);

test("a duplicate outbox entry for an applied revision, or a stale revision, changes nothing", async () => {
  const t = setup();
  t.user("u-a", "a@acme.example"); t.session("u-a");
  const s = snap({ userName: "a@acme.example" });
  assert.equal((await applyUser(t.env, policy, s)).changed, true);
  assert.equal(linkRow(t, s.id).user_id, "u-a");
  const off = { ...s, active: false, revision: 2 };
  assert.deepEqual(await applyUser(t.env, policy, off), { changed: true, deprovisioned: true });
  const before = { feed: t.count("SELECT count(*) FROM nathan_rbac_changes"), audit: t.count("SELECT count(*) FROM nathan_security_audit"), batches: t.env.DB.statements };
  // The Durable Object lost its outbox delete after D1 committed: the same row is applied again.
  assert.deepEqual(await applyUser(t.env, policy, off), { changed: false, deprovisioned: false });
  // An older snapshot arriving late (revision 1, still active) never undoes the deprovisioning.
  assert.deepEqual(await applyUser(t.env, policy, s), { changed: false, deprovisioned: false });
  assert.equal(banned(t, "u-a"), true);
  assert.equal(t.count("SELECT count(*) FROM nathan_rbac_changes"), before.feed);
  assert.equal(t.count("SELECT count(*) FROM nathan_security_audit"), before.audit);
  assert.equal(t.env.DB.statements, before.batches, "no D1 write at all for a replay");
});

test("two appliers racing on one revision commit exactly one transition", async () => {
  const t = setup();
  t.user("u-r", "r@acme.example");
  const s = snap({ userName: "r@acme.example" });
  await applyUser(t.env, policy, s);
  const off = { ...s, active: false, revision: 2 };
  // All three read revision 1 before any commits (the shim yields on every call).
  const results = await Promise.all([applyUser(t.env, policy, off), applyUser(t.env, policy, off), applyUser(t.env, policy, off)]);
  assert.equal(results.filter(r => r.deprovisioned).length, 1, JSON.stringify(results));
  assert.equal(feedOf(t, "u-r", "user.deprovisioned"), 1);
  assert.equal(t.count("SELECT count(*) FROM nathan_security_audit WHERE action='scim_user_deprovision'"), 1);
  assert.equal(linkRow(t, s.id).applied_revision, 2);
  // Racing first applications (no row yet) also link once.
  t.user("u-q", "q@acme.example");
  const q = snap({ userName: "q@acme.example" });
  const first = await Promise.all([applyUser(t.env, policy, q), applyUser(t.env, policy, q)]);
  assert.equal(first.filter(r => r.changed).length, 1, JSON.stringify(first));
  assert.equal(feedOf(t, "u-q", "user.linked"), 1);
});

test("administrator principals are never linked automatically: a review item is opened once", async () => {
  const t = setup();
  t.user("u-root", "root@acme.example");                                      // NATHAN_ADMIN_EMAILS allowlist
  t.user("u-role", "role@acme.example", { role: "admin" });                   // global admin role
  t.user("u-grant", "grant@acme.example");
  t.run("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES ('u-grant','grant@acme.example','t')");
  t.user("u-owner", "owner@acme.example", { role: "admin" });
  t.run("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf','owner@acme.example','u-owner','complete')");
  t.user("u-plain", "plain@acme.example");
  assert.match(await adminProtection(t.env, "u-root"), /NATHAN_ADMIN_EMAILS/);
  assert.match(await adminProtection(t.env, "u-role"), /role/);
  assert.match(await adminProtection(t.env, "u-grant"), /grant/);
  assert.match(await adminProtection(t.env, "u-owner"), /bootstrap owner/);
  assert.equal(await adminProtection(t.env, "u-plain"), null);
  for (const id of ["u-root", "u-role", "u-grant", "u-owner"]) {
    const email = t.get('SELECT "email" AS e FROM "user" WHERE "id"=?', id).e;
    const s = snap({ userName: email });
    await applyUser(t.env, policy, s);
    const row = linkRow(t, s.id);
    assert.equal(row.user_id, null, id + " is not linked");
    assert.match(row.link_note, /administrator review/);
    assert.deepEqual(t.get("SELECT action, state, user_id FROM nathan_scim_reviews WHERE scim_id=?", s.id), { action: "link", state: "pending", user_id: id });
    // Forced replays (resync) do not pile up review items.
    await applyUser(t.env, policy, s, { force: true });
    assert.equal(t.count("SELECT count(*) FROM nathan_scim_reviews WHERE scim_id=?", s.id), 1);
  }
  assert.equal(t.count("SELECT count(*) FROM nathan_security_audit WHERE action='scim_admin_review_open'"), 4, "each review item is audited once");
  // Just-in-time creation never takes an allowlisted administrator email.
  const jit = { ...policy, jit: true };
  const s = snap({ userName: "root2@acme.example" });
  await applyUser({ ...t.env, NATHAN_ADMIN_EMAILS: "root2@acme.example" }, jit, s);
  assert.equal(t.get('SELECT 1 AS x FROM "user" WHERE "email"=\'root2@acme.example\''), null);
});

test("deprovisioning a linked administrator waits for an approved review; the last administrator is never deprovisioned", async () => {
  const t = setup();
  t.user("u-owner", "owner@acme.example", { role: "admin" });
  t.run("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf','owner@acme.example','u-owner','complete')");
  t.user("u-adm", "adm@acme.example", { role: "admin" });
  t.run("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES ('u-adm','adm@acme.example','u-owner')");
  // Linked through an administrator's approval (or before the grant existed).
  const link = (scimId, userId) => t.run("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,link_method,applied_revision,linked_at) VALUES ('acme',?,?,?,1,?,'linked','approved',1,1)",
    scimId, "ext-" + scimId, scimId + "@acme.example", userId);
  link("adm", "u-adm"); link("owner", "u-owner");
  t.session("u-adm"); t.session("u-owner");
  const adm = snap({ id: "adm", externalId: "ext-adm", userName: "adm@acme.example", active: false, revision: 2 });
  assert.deepEqual(await applyUser(t.env, policy, adm), { changed: true, deprovisioned: false });
  assert.equal(banned(t, "u-adm"), false, "no ban");
  assert.equal(t.count('SELECT count(*) FROM "session" WHERE "userId"=\'u-adm\''), 1, "no session deleted");
  assert.equal(t.get("SELECT state FROM nathan_scim_reviews WHERE scim_id='adm' AND action='deprovision'").state, "pending");
  assert.match(linkRow(t, "adm").link_note, /administrator review/);
  // An administrator approves (src/auth/scim/reviews.ts records that); the next application applies it once.
  t.run("UPDATE nathan_scim_reviews SET state='approved', decided_by='u-owner', decided_at=unixepoch() WHERE scim_id='adm'");
  assert.deepEqual(await applyUser(t.env, policy, adm, { force: true }), { changed: true, deprovisioned: true });
  assert.equal(banned(t, "u-adm"), true);
  assert.equal(t.count('SELECT count(*) FROM "session" WHERE "userId"=\'u-adm\''), 0);
  assert.equal(t.get("SELECT state FROM nathan_scim_reviews WHERE scim_id='adm'").state, "applied");
  // The owner is now the only active administrator: even an approved review never removes them.
  const owner = snap({ id: "owner", externalId: "ext-owner", userName: "owner@acme.example", deleted: true, active: false, revision: 2 });
  await applyUser(t.env, policy, owner);
  t.run("UPDATE nathan_scim_reviews SET state='approved', decided_by='someone' WHERE scim_id='owner'");
  assert.deepEqual(await applyUser(t.env, policy, owner, { force: true }), { changed: true, deprovisioned: false });
  assert.equal(banned(t, "u-owner"), false);
  assert.equal(t.count('SELECT count(*) FROM "session" WHERE "userId"=\'u-owner\''), 1);
  assert.match(linkRow(t, "owner").link_note, /last administrator/);
  // Reactivation in the directory supersedes an open review.
  t.user("u-adm2", "adm2@acme.example", { role: "admin" });
  link("adm2", "u-adm2");
  const adm2 = snap({ id: "adm2", externalId: "ext-adm2", userName: "adm2@acme.example", active: false, revision: 2 });
  await applyUser(t.env, policy, adm2);
  assert.equal(t.get("SELECT state FROM nathan_scim_reviews WHERE scim_id='adm2'").state, "pending");
  await applyUser(t.env, policy, { ...adm2, active: true, revision: 3 });
  assert.equal(t.get("SELECT state FROM nathan_scim_reviews WHERE scim_id='adm2'").state, "superseded");
});

test("an administrator's unban survives a forced resync; only a new deprovision change bans again", async () => {
  const t = setup();
  t.user("u-o", "o@acme.example");
  const s = snap({ userName: "o@acme.example" });
  await applyUser(t.env, policy, s);
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 });
  assert.equal(banned(t, "u-o"), true);
  // Unbanned outside SCIM (Better Auth's admin API or by hand): recorded as an administrator override.
  t.run('UPDATE "user" SET "banned"=0, "banReason"=NULL WHERE "id"=\'u-o\'');
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 }, { force: true });
  assert.equal(banned(t, "u-o"), false, "resync does not re-ban");
  const row = linkRow(t, s.id);
  assert.equal(row.override_cause, "deactivated");
  assert.ok(row.override_at);
  assert.ok(row.override_by);
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 }, { force: true });
  assert.equal(banned(t, "u-o"), false);
  // The directory reactivates and later deactivates again: a new deprovision change.
  await applyUser(t.env, policy, { ...s, active: true, revision: 3 });
  assert.equal(linkRow(t, s.id).override_at, null, "reactivation clears the override");
  await applyUser(t.env, policy, { ...s, active: false, revision: 4 });
  assert.equal(banned(t, "u-o"), true);
  assert.equal(t.get('SELECT "banReason" AS r FROM "user" WHERE "id"=\'u-o\'').r, scimBanReason("acme"));
  // A DELETE after a deactivation override is a new change too.
  t.run('UPDATE "user" SET "banned"=0, "banReason"=NULL WHERE "id"=\'u-o\'');
  await applyUser(t.env, policy, { ...s, active: false, revision: 4 }, { force: true });
  assert.equal(banned(t, "u-o"), false);
  await applyUser(t.env, policy, { ...s, active: false, deleted: true, revision: 5 });
  assert.equal(banned(t, "u-o"), true);
});

test("a deleted Nathan user's link is not re-made automatically, here or in another connection", async () => {
  const t = setup();
  t.run("INSERT INTO nathan_scim_connections(id,domain,created_by,linking_enabled) VALUES ('acme2','acme.example','t',1)");
  t.user("u-i", "ivy@acme.example");
  const s = snap({ userName: "ivy@acme.example" });
  await applyUser(t.env, policy, s);
  assert.equal(linkRow(t, s.id).user_id, "u-i");
  t.run('DELETE FROM "user" WHERE "id"=\'u-i\'');
  t.user("u-i2", "ivy@acme.example");
  // Another connection for the same verified domain cannot take the new account.
  const other = snap({ userName: "ivy@acme.example" });
  await applyUser(t.env, { ...policy, id: "acme2" }, other);
  assert.equal(linkRow(t, other.id, "acme2").user_id, null);
  // Nor does the original connection silently re-link (a resync replays it).
  await applyUser(t.env, policy, s, { force: true });
  assert.equal(linkRow(t, s.id).user_id, null);
  assert.equal(t.count("SELECT count(*) FROM nathan_scim_reviews WHERE user_id='u-i2' AND action='link' AND state='pending'"), 2,
    "each connection's claim waits for an administrator");
});

test("a rehire with the same externalId in the same connection takes over the deleted identity's link", async () => {
  const t = setup();
  t.user("u-h", "h@acme.example");
  const s = snap({ userName: "h@acme.example" });
  await applyUser(t.env, policy, s);
  await applyUser(t.env, policy, { ...s, active: false, deleted: true, revision: 2 });
  assert.equal(banned(t, "u-h"), true);
  const rehire = snap({ userName: "h@acme.example", externalId: s.externalId });
  await applyUser(t.env, policy, rehire);
  assert.equal(linkRow(t, rehire.id).user_id, "u-h");
  assert.equal(linkRow(t, s.id).user_id, null);
  assert.equal(banned(t, "u-h"), false, "the new active identity lifts Nathan's SCIM ban");
});

test("a mapped group larger than one invocation's budget is applied in bounded batches, removals first", async () => {
  const t = setup();
  t.run("INSERT INTO nathan_groups(id,name,source,created_by) VALUES ('eng','Engineering','scim','t')");
  t.run("INSERT INTO nathan_scim_group_mappings(id,connection_id,ref_type,ref_value,group_id,created_by) VALUES ('m','acme','externalId','g-eng','eng','t')");
  const members = [];
  for (let i = 0; i < 450; i++) {
    const id = crypto.randomUUID();
    t.user("u" + i, "m" + i + "@acme.example");
    t.run("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,applied_revision) VALUES ('acme',?,?,?,1,?,'linked',1)", id, "e" + i, "m" + i, "u" + i);
    members.push(id);
  }
  const group = { id: crypto.randomUUID(), externalId: "g-eng", displayName: "Eng", deleted: false, revision: 1, members };
  const sizes = [];
  const batch = t.env.DB.batch.bind(t.env.DB);
  t.env.DB.batch = statements => { sizes.push(statements.length); return batch(statements); };
  let runs = 0, result;
  do {
    const budget = new Budget(RECONCILE_LIMITS.statementsPerInvocation);
    result = await applyGroup(budget.wrap(t.env), policy, group, { budget });
    runs++;
    assert.ok(budget.used <= RECONCILE_LIMITS.statementsPerInvocation, "an invocation stays within its budget: " + budget.used);
  } while (result.partial && runs < 20);
  assert.ok(runs > 1, "needed several invocations, got " + runs);
  assert.ok(Math.max(...sizes) <= RECONCILE_LIMITS.statementsPerBatch, "largest D1 batch " + Math.max(...sizes));
  assert.equal(t.count("SELECT count(*) FROM nathan_group_members WHERE group_id='eng'"), 450);
  assert.equal(t.count("SELECT count(*) FROM nathan_rbac_changes WHERE kind='member.added'"), 450, "one feed row per real change");
  assert.equal(t.get("SELECT applied_revision AS r FROM nathan_scim_groups WHERE scim_id=?", group.id).r, 1, "marked applied only when complete");
  // Shrinking: removals are applied before additions, and a partial result says whether removals remain.
  const next = { ...group, members: members.slice(0, 300), revision: 2 };
  const small = new Budget(120);
  const partial = await applyGroup(small.wrap(t.env), policy, next, { budget: small });
  assert.equal(partial.partial, true);
  assert.equal(partial.removalsPending, true);
  let guard = 0, r;
  do { const b = new Budget(RECONCILE_LIMITS.statementsPerInvocation); r = await applyGroup(b.wrap(t.env), policy, next, { budget: b }); } while (r.partial && ++guard < 20);
  assert.equal(t.count("SELECT count(*) FROM nathan_group_members WHERE group_id='eng'"), 300);
  assert.equal(t.get("SELECT applied_revision AS r FROM nathan_scim_groups WHERE scim_id=?", group.id).r, 2);
});

// ---- re-review fixes ---------------------------------------------------------------------------

const banOf = (t, userId) => t.get('SELECT "banned" AS banned, "banReason" AS reason, "banExpires" AS expires FROM "user" WHERE "id"=?', userId);
const overrideAudits = t => t.count("SELECT count(*) FROM nathan_security_audit WHERE action='scim_override_detected'");
/** Better Auth's session hook (admin plugin): an expired ban is lifted at the next sign-in. */
const signInLiftsExpiredBan = (t, userId) =>
  t.run('UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL WHERE "id"=? AND "banned"=1 AND "banExpires" IS NOT NULL', userId);
/** Better Auth's banUser: overwrites reason and expiry. */
const adminBan = (t, userId, reason, expires) =>
  t.run('UPDATE "user" SET "banned"=1, "banReason"=?, "banExpires"=? WHERE "id"=?', reason, expires, userId);

test("deprovisioning takes over a temporary ban: its expiry never lifts the SCIM block or counts as an override", async () => {
  const t = setup();
  t.user("u-t", "t@acme.example"); t.session("u-t");
  const s = snap({ userName: "t@acme.example" });
  await applyUser(t.env, policy, s);
  // An administrator suspended the user for 7 days; then the directory deactivates them.
  adminBan(t, "u-t", "Suspended for 7 days", new Date(Date.now() + 7 * 86400_000).toISOString());
  assert.deepEqual(await applyUser(t.env, policy, { ...s, active: false, revision: 2 }), { changed: true, deprovisioned: true });
  assert.deepEqual(banOf(t, "u-t"), { banned: 1, reason: scimBanReason("acme"), expires: null }, "Nathan's SCIM ban replaces the temporary one");
  assert.equal(linkRow(t, s.id).scim_banned, 1);
  assert.equal(t.count('SELECT count(*) FROM "session" WHERE "userId"=\'u-t\''), 0);
  // Seven days later the user signs in: nothing lapses, and a resync keeps them blocked.
  signInLiftsExpiredBan(t, "u-t");
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 }, { force: true });
  assert.equal(banned(t, "u-t"), true);
  assert.equal(linkRow(t, s.id).override_cause, null, "no override recorded");
  assert.equal(overrideAudits(t), 0);
});

test("a temporary ban that lapsed before Nathan took over is re-banned by a resync, never recorded as an override", async () => {
  // Rows written before the takeover (or a ban Nathan did not write) look exactly like this.
  const t = setup();
  t.user("u-l", "l@acme.example");
  const s = snap({ userName: "l@acme.example" });
  await applyUser(t.env, policy, s);
  adminBan(t, "u-l", "Suspended for 7 days", new Date(Date.now() + 7 * 86400_000).toISOString());
  t.run("UPDATE nathan_scim_users SET link_state='deprovisioned', active=0, scim_banned=0, applied_revision=2 WHERE scim_id=?", s.id);
  signInLiftsExpiredBan(t, "u-l");
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 }, { force: true });
  assert.deepEqual(banOf(t, "u-l"), { banned: 1, reason: scimBanReason("acme"), expires: null });
  assert.equal(linkRow(t, s.id).override_cause, null);
  assert.equal(overrideAudits(t), 0);
});

test("an administrator's expiring re-ban over the SCIM ban lapses, and the next resync bans again", async () => {
  const t = setup();
  t.user("u-x", "x2@acme.example");
  const s = snap({ userName: "x2@acme.example" });
  await applyUser(t.env, policy, s);
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 });
  assert.equal(banOf(t, "u-x").reason, scimBanReason("acme"));
  adminBan(t, "u-x", "Cooling off", new Date(Date.now() + 86400_000).toISOString());
  signInLiftsExpiredBan(t, "u-x");
  assert.equal(banned(t, "u-x"), false);
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 }, { force: true });
  assert.deepEqual(banOf(t, "u-x"), { banned: 1, reason: scimBanReason("acme"), expires: null });
  assert.equal(linkRow(t, s.id).override_cause, null);
  assert.equal(overrideAudits(t), 0);
});

test("lifting Nathan's own SCIM ban is the only out-of-band override, and it is audited once", async () => {
  const t = setup();
  t.user("u-k", "k@acme.example");
  const s = snap({ userName: "k@acme.example" });
  await applyUser(t.env, policy, s);
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 });
  // Better Auth's unbanUser (or by hand) on the ban Nathan wrote.
  t.run('UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL WHERE "id"=\'u-k\'');
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 }, { force: true });
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 }, { force: true });
  assert.equal(banned(t, "u-k"), false);
  assert.equal(linkRow(t, s.id).override_cause, "deactivated");
  assert.equal(overrideAudits(t), 1);
});

test("a permanent ban an administrator wrote is kept (not taken over), so reactivation never lifts it", async () => {
  const t = setup();
  t.user("u-p", "p@acme.example");
  const s = snap({ userName: "p@acme.example" });
  await applyUser(t.env, policy, s);
  adminBan(t, "u-p", "Fraud investigation", null);
  await applyUser(t.env, policy, { ...s, active: false, revision: 2 });
  assert.deepEqual(banOf(t, "u-p"), { banned: 1, reason: "Fraud investigation", expires: null });
  await applyUser(t.env, policy, { ...s, active: true, revision: 3 });
  assert.deepEqual(banOf(t, "u-p"), { banned: 1, reason: "Fraud investigation", expires: null });
});

test("two appliers on a large group: a stale applier commits nothing (no stale removal, no duplicate feed rows)", async () => {
  const t = setup();
  t.run("INSERT INTO nathan_groups(id,name,source,created_by) VALUES ('ops','Ops','scim','t')");
  t.run("INSERT INTO nathan_scim_group_mappings(id,connection_id,ref_type,ref_value,group_id,created_by) VALUES ('m2','acme','externalId','g-ops','ops','t')");
  const members = [];
  for (let i = 0; i < 300; i++) {
    const id = crypto.randomUUID();
    t.user("o" + i, "o" + i + "@acme.example");
    t.run("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,applied_revision) VALUES ('acme',?,?,?,1,?,'linked',1)", id, "oe" + i, "o" + i, "o" + i);
    members.push(id);
  }
  const group = { id: crypto.randomUUID(), externalId: "g-ops", displayName: "Ops", deleted: false, revision: 1, members };
  // The same revision applied twice at once (an alarm racing a directory retry).
  const settle = async (g, first) => {
    let r = first, guard = 0;
    while ((r === "error" || r.partial) && guard++ < 20) r = await applyGroup(t.env, policy, g).catch(() => "error");
    return r;
  };
  const both = await Promise.all([applyGroup(t.env, policy, group).catch(() => "error"), applyGroup(t.env, policy, group).catch(() => "error")]);
  await Promise.all(both.map(r => settle(group, r)));
  assert.equal(t.count("SELECT count(*) FROM nathan_group_members WHERE group_id='ops'"), 300);
  assert.equal(t.count("SELECT count(*) FROM nathan_rbac_changes WHERE kind='member.added' AND json_extract(detail,'$.group')='ops'"), 300, "one feed row per member");
  // A stale shrink (revision 2) racing the directory's newer full list (revision 3).
  const stale = { ...group, members: members.slice(0, 100), revision: 2 };
  const fresh = { ...group, revision: 3 };
  const race = await Promise.all([applyGroup(t.env, policy, stale).catch(() => "error"), applyGroup(t.env, policy, fresh).catch(() => "error")]);
  await settle(fresh, race[1]);
  await settle(stale, race[0]);
  assert.equal(t.get("SELECT applied_revision AS r FROM nathan_scim_groups WHERE scim_id=?", group.id).r, 3);
  assert.equal(t.count("SELECT count(*) FROM nathan_group_members WHERE group_id='ops'"), 300, "no stale removal survives the newer revision");
  const removed = t.count("SELECT count(*) FROM nathan_rbac_changes WHERE kind='member.removed' AND json_extract(detail,'$.group')='ops'");
  const added = t.count("SELECT count(*) FROM nathan_rbac_changes WHERE kind='member.added' AND json_extract(detail,'$.group')='ops'");
  assert.equal(added - 300, removed, "every removal the feed reports is matched by a re-add, never duplicated");
});

test("two administrators in different connections approved for deprovisioning together: at least one stays", async () => {
  const t = setup();
  t.run("INSERT INTO nathan_scim_connections(id,domain,created_by,linking_enabled) VALUES ('acme2','acme.example','t',1)");
  const other = { ...policy, id: "acme2" };
  for (const [id, connection] of [["a1", "acme"], ["a2", "acme2"]]) {
    t.user("u-" + id, id + "@acme.example", { role: "admin" });
    t.run("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES (?,?,'t')", "u-" + id, id + "@acme.example");
    t.run("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,link_method,applied_revision,linked_at) VALUES (?,?,?,?,1,?,'linked','approved',1,1)",
      connection, id, "ext-" + id, id + "@acme.example", "u-" + id);
  }
  const a1 = snap({ id: "a1", externalId: "ext-a1", userName: "a1@acme.example", active: false, revision: 2 });
  const a2 = snap({ id: "a2", externalId: "ext-a2", userName: "a2@acme.example", active: false, revision: 2 });
  await applyUser(t.env, policy, a1); await applyUser(t.env, other, a2);
  // Each administrator approves the other's deprovisioning.
  t.run("UPDATE nathan_scim_reviews SET state='approved', decided_by='someone' WHERE action='deprovision'");
  assert.equal(t.count("SELECT count(*) FROM nathan_scim_reviews WHERE state='approved'"), 2);
  // The two connections' Durable Objects apply concurrently (no shared serialization).
  const results = await Promise.all([applyUser(t.env, policy, a1, { force: true }).catch(e => e), applyUser(t.env, other, a2, { force: true }).catch(e => e)]);
  const active = ["u-a1", "u-a2"].filter(id => !banned(t, id));
  assert.equal(active.length, 1, "exactly one administrator remains: " + JSON.stringify(results));
  assert.equal(results.filter(r => r.deprovisioned).length, 1);
  const kept = active[0] === "u-a1" ? "a1" : "a2";
  assert.match(linkRow(t, kept, kept === "a1" ? "acme" : "acme2").link_note, /last administrator/);
  assert.equal(t.get("SELECT state FROM nathan_scim_reviews WHERE scim_id=?", kept).state, "pending", "the refused approval goes back to pending");
  assert.equal(t.count('SELECT count(*) FROM "session" WHERE "userId"=?', "u-" + kept), 0, "(no sessions were created in this test)");
});

test("approve and dismiss audit what the conditional update did: a decision racing another is refused, not 'succeeded'", async () => {
  const t = setup();
  t.env.NATHAN_ISSUER = "https://id.acme.example";
  t.user("u-boss", "boss@acme.example", { role: "admin" });
  t.run("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf','boss@acme.example','u-boss','complete')");
  t.user("u-ad", "ad@acme.example", { role: "admin" });
  const s = snap({ userName: "ad@acme.example" });
  await applyUser(t.env, policy, s);
  const review = t.get("SELECT id FROM nathan_scim_reviews WHERE scim_id=?", s.id).id;
  const dismiss = actor => scimUserOperation(t.env, { op: "dismiss", connection: "acme", review, confirm: "CONFIRM DISMISS LINK ad@acme.example" }, actor)
    .then(() => "ok", e => e.message);
  const approve = actor => scimUserOperation(t.env, { op: "approve", connection: "acme", review, confirm: "CONFIRM APPROVE LINK ad@acme.example" }, actor)
    .then(() => "ok", e => e.message);
  // Both administrators load the pending item; only one decision changes it.
  const outcomes = await Promise.all([dismiss("admin-1"), approve("admin-2")]);
  assert.equal(outcomes.filter(o => o === "ok").length, 1, JSON.stringify(outcomes));
  assert.match(outcomes.find(o => o !== "ok"), /no longer pending/);
  const audits = t.db.prepare("SELECT action, outcome FROM nathan_security_audit WHERE action IN ('scim_review_dismiss','scim_review_approve')").all().map(r => r.outcome).sort();
  assert.deepEqual(audits, ["rejected", "succeeded"]);
  const state = t.get("SELECT state FROM nathan_scim_reviews WHERE id=?", review).state;
  const row = linkRow(t, s.id);
  if (state === "dismissed") assert.ok(row.link_hold, "the dismissal's hold is recorded");
  else assert.equal(row.link_hold, null, "a refused dismissal records no hold");
});

test("review creation is rate-limited per connection, so a directory cannot flood Studio", async () => {
  const t = setup();
  const limit = REVIEW_LIMITS.perConnectionPerHour;
  const snaps = [];
  for (let i = 0; i < limit + 5; i++) {
    t.user("u-f" + i, "f" + i + "@acme.example", { role: "admin" });
    snaps.push(snap({ userName: "f" + i + "@acme.example" }));
  }
  for (const s of snaps) await applyUser(t.env, policy, s);
  assert.equal(t.count("SELECT count(*) FROM nathan_scim_reviews WHERE connection_id='acme'"), limit);
  assert.equal(t.count("SELECT count(*) FROM nathan_security_audit WHERE action='scim_admin_review_open'"), limit);
  const last = linkRow(t, snaps.at(-1).id);
  assert.equal(last.user_id, null, "still not linked");
  assert.match(last.link_note, /rate-limited/);
  // An hour later the next resync opens the review.
  t.run("UPDATE nathan_scim_reviews SET created_at=created_at-3601");
  await applyUser(t.env, policy, snaps.at(-1), { force: true });
  assert.equal(t.get("SELECT state FROM nathan_scim_reviews WHERE scim_id=?", snaps.at(-1).id).state, "pending");
});

test("Studio lists reviews pending first and oldest first, with counts, a state filter and paging", async () => {
  const t = setup();
  t.env.NATHAN_ISSUER = "https://id.acme.example";
  t.user("u-v", "v@acme.example");
  const add = (id, state, created) => t.run("INSERT INTO nathan_scim_reviews(id,connection_id,scim_id,user_id,action,reason,revision,state,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
    id, "acme", "s-" + id, "u-v", "link", "r", 1, state, created);
  for (let i = 0; i < 130; i++) add("d" + i, "dismissed", 2000 + i);   // newer, decided
  for (let i = 0; i < 120; i++) add("p" + i, "pending", 1000 + i);     // older, still pending
  const view = await scimConnectionView(t.env, "acme");
  assert.deepEqual(view.reviewCounts, { dismissed: 130, pending: 120 });
  assert.equal(view.reviews.length, 100);
  assert.ok(view.reviews.every(r => r.state === "pending"));
  assert.equal(view.reviews[0].id, "p0", "oldest pending first");
  assert.deepEqual(view.reviewPage, { state: null, offset: 0, limit: 100, total: 250 });
  const page2 = await scimConnectionView(t.env, "acme", { reviewOffset: "100" });
  assert.equal(page2.reviews[0].id, "p100");
  assert.equal(page2.reviews.filter(r => r.state === "pending").length, 20);
  const dismissed = await scimConnectionView(t.env, "acme", { reviewState: "dismissed" });
  assert.equal(dismissed.reviewPage.total, 130);
  assert.ok(dismissed.reviews.every(r => r.state === "dismissed"));
  await assert.rejects(scimConnectionView(t.env, "acme", { reviewState: "bogus" }), /Invalid review filter/);
  await assert.rejects(scimConnectionView(t.env, "acme", { reviewOffset: "-1" }), /Invalid review filter/);
});
