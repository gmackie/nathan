/**
 * NATH-18 (c): the change-feed triggers for bans (migration 0011) and Nathan's SCIM ban-change trigger
 * (0016) exist in D1, and the ban/unban feed rows are written for the SQL Better Auth itself runs:
 * - Better Auth's admin banUser/unbanUser API. The identity Worker blocks the raw /api/auth/admin/*
 *   routes (management boundary), so the same Better Auth 1.7.14 admin plugin runs here, server-side
 *   in Node, against the identity Worker's own D1 database;
 * - an expired ban lifted by Better Auth at the next sign-in, through the real identity Worker.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins";
import { hashPassword } from "better-auth/crypto";
import { authWorker, randomKey, insertSession, cookiesOf } from "./helpers.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST;
const SECRET = randomKey() + randomKey();
const PASSWORD = "correct horse battery staple 77";

let mf, db, nodeAuth, adminCookie;
before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, ENABLE_PASSWORD: "true" });
  db = await mf.getD1Database("DB");
  const now = new Date().toISOString();
  const sql = (statement, ...params) => db.prepare(statement).bind(...params).run();
  await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (\'u-op\',\'op\',\'op@example.test\',1,?,?,\'admin\')', now, now);
  await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (\'u-ban\',\'ban\',\'ban@example.test\',1,?,?,\'user\')', now, now);
  await sql('INSERT INTO "account"("id","accountId","providerId","userId","password","createdAt","updatedAt") VALUES (\'acc-ban\',\'u-ban\',\'credential\',\'u-ban\',?,?,?)',
    await hashPassword(PASSWORD), now, now);
  adminCookie = (await insertSession(db, SECRET, "u-op")).cookie;
  // Better Auth's own admin plugin, configured like the identity Worker (src/auth/instance.ts), on the same D1.
  const d1 = { prepare: q => db.prepare(q), batch: s => db.batch(s), exec: q => db.exec(q), dump: () => db.dump() };
  nodeAuth = betterAuth({
    database: d1, baseURL: ORIGIN, basePath: "/api/auth", secret: SECRET,
    emailAndPassword: { enabled: true, requireEmailVerification: true },
    advanced: { cookiePrefix: "nathan", useSecureCookies: true, database: { joins: false } },
    plugins: [admin()]
  });
});
after(() => mf?.dispose());

const feed = async userId => (await db.prepare("SELECT kind, actor FROM nathan_rbac_changes WHERE principal_id=? ORDER BY seq").bind(userId).all()).results;
const banOf = userId => db.prepare('SELECT "banned" AS banned, "banReason" AS reason, "banExpires" AS expires FROM "user" WHERE "id"=?').bind(userId).first();
let client = 0;
const signIn = () => mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/email", {
  method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": "192.0.2." + (++client) },
  body: JSON.stringify({ email: "ban@example.test", password: PASSWORD })
});
const asAdmin = () => new Headers({ Cookie: adminCookie });

test("D1 has the admission, email, app provisioning, change-feed and SCIM triggers", async () => {
  const triggers = (await db.prepare("SELECT name, tbl_name AS tbl FROM sqlite_master WHERE type='trigger' ORDER BY name").all()).results;
  assert.deepEqual(triggers.filter(t => t.name.startsWith("nathan_")).map(t => t.name + " ON " + t.tbl),
    ["nathan_app_membership_changes ON nathan_app_provisions", "nathan_capture_ending_session ON session", "nathan_claim_email_invitation ON user",
     "nathan_claim_owner ON nathan_operator_owner_claim",
      "nathan_email_delivery_before_insert ON nathan_email_sign_ins", "nathan_erase_app_credentials ON user",
      "nathan_invalidate_changed_totp ON twoFactor", "nathan_keep_required_admin_passkey ON passkey",
      "nathan_rbac_feed_user_ban ON user", "nathan_rbac_feed_user_delete ON user",
      "nathan_reconcile_app_grants ON nathan_app_provisions", "nathan_retire_app_provision ON nathan_app_provisions",
      "nathan_scim_ban_changed ON user"]);
});

test("Better Auth's admin banUser and unbanUser write user.banned and user.unbanned to the change feed", async () => {
  assert.equal((await signIn()).status, 200, "the user can sign in before the ban");
  await nodeAuth.api.banUser({ body: { userId: "u-ban", banReason: "Policy violation" }, headers: asAdmin() });
  assert.equal((await banOf("u-ban")).banned, 1);
  assert.deepEqual((await feed("u-ban")).map(r => r.kind), ["user.banned"]);
  assert.equal((await feed("u-ban"))[0].actor, "system:user-state");
  const refused = await signIn();
  assert.equal(refused.status, 403, "a banned user cannot sign in");
  assert.equal(cookiesOf(refused)["__Secure-nathan.session_token"], undefined);
  assert.deepEqual((await feed("u-ban")).map(r => r.kind), ["user.banned"], "a refused sign-in changes nothing");
  await nodeAuth.api.unbanUser({ body: { userId: "u-ban" }, headers: asAdmin() });
  assert.deepEqual((await feed("u-ban")).map(r => r.kind), ["user.banned", "user.unbanned"]);
  // Re-banning a banned user (only the reason changes) is not a new feed event.
  await nodeAuth.api.banUser({ body: { userId: "u-ban", banReason: "first" }, headers: asAdmin() });
  await nodeAuth.api.banUser({ body: { userId: "u-ban", banReason: "second" }, headers: asAdmin() });
  assert.deepEqual((await feed("u-ban")).map(r => r.kind), ["user.banned", "user.unbanned", "user.banned"]);
  await nodeAuth.api.unbanUser({ body: { userId: "u-ban" }, headers: asAdmin() });
});

test("an expired ban lifted by Better Auth at sign-in writes user.unbanned", async () => {
  const before = (await feed("u-ban")).length;
  await nodeAuth.api.banUser({ body: { userId: "u-ban", banReason: "Cooling off", banExpiresIn: 1 }, headers: asAdmin() });
  assert.ok((await banOf("u-ban")).expires, "the ban has an expiry");
  assert.deepEqual((await feed("u-ban")).slice(before).map(r => r.kind), ["user.banned"]);
  assert.equal((await signIn()).status, 403, "still banned before the expiry");
  await new Promise(resolve => setTimeout(resolve, 1500));
  const signedIn = await signIn();
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  assert.ok(cookiesOf(signedIn)["__Secure-nathan.session_token"], "the lapsed ban no longer blocks sign-in");
  assert.deepEqual({ ...(await banOf("u-ban")) }, { banned: 0, reason: null, expires: null });
  assert.deepEqual((await feed("u-ban")).slice(before).map(r => r.kind), ["user.banned", "user.unbanned"]);
});
