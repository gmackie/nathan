/**
 * NATH-19 in workerd: a directory-deprovisioned user must not sign in again when an administrator's
 * expiring ban, which replaced Nathan's SCIM ban, lapses. Better Auth lifts an expired ban at the next
 * sign-in; Nathan's session.create.before hook then refuses the session for a deprovisioned SCIM link
 * without an administrator override, puts Nathan's SCIM ban back and audits it. An explicit
 * administrator override (keep active / out-of-band unban of Nathan's ban) still lets the user in.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { admin as adminPlugin } from "better-auth/plugins";
import { hashPassword } from "better-auth/crypto";
import { authWorker, randomKey, enrollAdmin, studioPost, cookiesOf } from "./helpers.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST;
const SECRET = randomKey() + randomKey();
const PASSWORD = "correct horse battery staple 19";
const okta = JSON.parse(readFileSync("tests/fixtures/scim/okta.json", "utf8"));
const SCIM_BAN = "SCIM deprovisioned (connection acme)";

let mf, db, admin, nodeAuth, token;
const worker = { fetch: (url, init) => mf.dispatchFetch(url, init) };
before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, ENABLE_PASSWORD: "true" });
  db = await mf.getD1Database("DB");
  admin = await enrollAdmin(db, SECRET);
  await db.prepare('INSERT INTO "ssoProvider"("id","issuer","userId","providerId","domain","domainVerified") VALUES (\'sso-1\',\'https://idp.acme.example\',\'admin-1\',\'acme-sso\',\'acme.example\',1)').run();
  const created = await studio("/studio/api/scim/connections", { id: "acme", domain: "acme.example" });
  assert.equal(created.status, 200, await created.clone().text());
  token = (await created.json()).bearerToken;
  assert.equal((await studio("/studio/api/scim/status", { id: "acme", enabled: true, confirm: "CONFIRM ENABLE acme" })).status, 200);
  assert.equal((await studio("/studio/api/scim/settings", { id: "acme", linking: true, jit: false, confirm: "CONFIRM SCIM SETTINGS acme" })).status, 200);
  const d1 = { prepare: q => db.prepare(q), batch: s => db.batch(s), exec: q => db.exec(q), dump: () => db.dump() };
  // Better Auth's own admin plugin on the same D1 (the Worker blocks the raw admin routes).
  nodeAuth = betterAuth({ database: d1, baseURL: ORIGIN, basePath: "/api/auth", secret: SECRET,
    emailAndPassword: { enabled: true }, advanced: { cookiePrefix: "nathan", useSecureCookies: true, database: { joins: false } },
    plugins: [adminPlugin()] });
});
after(() => mf?.dispose());

const studio = (path, body) => studioPost(worker, ORIGIN, path, body, admin.cookie);
const scim = (method, path, body) => mf.dispatchFetch(ORIGIN + "/scim/v2/acme" + path, {
  method, body: body === undefined ? undefined : JSON.stringify(body),
  headers: { Authorization: "Bearer " + token, ...(body === undefined ? {} : { "Content-Type": "application/scim+json" }) }
});
const one = (sql, ...params) => db.prepare(sql).bind(...params).first();
const banOf = id => one('SELECT "banned" AS banned, "banReason" AS reason, "banExpires" AS expires FROM "user" WHERE "id"=?', id);
const linkOf = id => one("SELECT link_state AS state, scim_banned AS scimBanned, override_cause AS override FROM nathan_scim_users WHERE user_id=?", id);
const asAdmin = () => new Headers({ Cookie: admin.cookie });
let client = 0;
const signIn = email => mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/email", {
  method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": "198.18.0." + (++client) },
  body: JSON.stringify({ email, password: PASSWORD })
});

/** A Nathan user with a password, linked to a directory user, then deactivated by the directory. */
async function deprovisioned(id) {
  const email = id + "@acme.example", now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,1,?,?,\'user\')').bind(id, id, email, now, now).run();
  await db.prepare('INSERT INTO "account"("id","accountId","providerId","userId","password","createdAt","updatedAt") VALUES (?,?,\'credential\',?,?,?,?)')
    .bind("acc-" + id, id, id, await hashPassword(PASSWORD), now, now).run();
  assert.equal((await signIn(email)).status, 200, "signs in while active");
  const user = await scim("POST", "/Users", { ...okta.createUser, userName: email, externalId: "ext-" + id, emails: [{ value: email, primary: true, type: "work" }] });
  assert.equal(user.status, 201, await user.clone().text());
  const scimId = (await user.json()).id;
  assert.equal((await scim("PATCH", "/Users/" + scimId, okta.deactivateUser)).status, 200);
  assert.deepEqual({ ...(await banOf(id)) }, { banned: 1, reason: SCIM_BAN, expires: null });
  assert.equal((await linkOf(id)).state, "deprovisioned");
  return email;
}
async function lapse(id, banReason) {
  // An administrator replaces Nathan's SCIM ban with an expiring ban (Better Auth admin banUser).
  await nodeAuth.api.banUser({ body: { userId: id, banReason, banExpiresIn: 1 }, headers: asAdmin() });
  const link = await linkOf(id);
  assert.equal(link.scimBanned, 0, "the 0016 trigger: the ban is no longer Nathan's");
  assert.equal(link.override, null, "replacing the ban is not an override");
  await new Promise(resolve => setTimeout(resolve, 1500));
}

test("the exact scenario: an administrator's expiring ban over a SCIM deprovisioning lapses; sign-in is still refused", async () => {
  const email = await deprovisioned("u-cool");
  await lapse("u-cool", "Cooling off");
  const refused = await signIn(email);
  assert.equal(refused.status, 403, await refused.clone().text());
  assert.equal(cookiesOf(refused)["__Secure-nathan.session_token"], undefined, "no session");
  const body = await refused.json();
  assert.equal(body.code, "ACCOUNT_DEPROVISIONED");
  assert.match(body.message, /directory/i);
  assert.equal(await one('SELECT 1 AS n FROM "session" WHERE "userId"=\'u-cool\''), null);
  // Nathan's SCIM ban is back, permanent, and the link records it again.
  assert.deepEqual({ ...(await banOf("u-cool")) }, { banned: 1, reason: SCIM_BAN, expires: null });
  assert.deepEqual({ ...(await linkOf("u-cool")) }, { state: "deprovisioned", scimBanned: 1, override: null });
  const audit = await one("SELECT actor, target, outcome FROM nathan_security_audit WHERE action='scim_ban_lapse_reapplied'");
  assert.deepEqual({ ...audit }, { actor: "scim:acme", target: "acme:u-cool", outcome: "succeeded" });
  const feed = (await db.prepare("SELECT kind FROM nathan_rbac_changes WHERE principal_id='u-cool' ORDER BY seq").all()).results.map(r => r.kind);
  assert.equal(feed.at(-1), "user.banned", "Gatekeeper sees the user blocked again");
  // Every later attempt is refused by the restored ban itself.
  const again = await signIn(email);
  assert.equal(again.status, 403);
  assert.equal(cookiesOf(again)["__Secure-nathan.session_token"], undefined);
});

test("an administrator's permanent ban over the SCIM ban, lifted by hand, is not an override either", async () => {
  const email = await deprovisioned("u-hand");
  await nodeAuth.api.banUser({ body: { userId: "u-hand", banReason: "Investigation" }, headers: asAdmin() });
  await nodeAuth.api.unbanUser({ body: { userId: "u-hand" }, headers: asAdmin() });
  assert.equal((await linkOf("u-hand")).override, null);
  const refused = await signIn(email);
  assert.equal(refused.status, 403);
  assert.equal((await refused.json()).code, "ACCOUNT_DEPROVISIONED");
  assert.equal((await banOf("u-hand")).reason, SCIM_BAN);
});

test("an administrator's explicit override of the SCIM deprovisioning still lets the user sign in", async () => {
  const email = await deprovisioned("u-kept");
  // Lifting Nathan's own SCIM ban is the recorded override (keep active / out-of-band unban).
  await nodeAuth.api.unbanUser({ body: { userId: "u-kept" }, headers: asAdmin() });
  assert.equal((await linkOf("u-kept")).override, "deactivated");
  const signedIn = await signIn(email);
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  assert.ok(cookiesOf(signedIn)["__Secure-nathan.session_token"]);
  assert.equal((await banOf("u-kept")).banned, 0);
});

test("users without a deprovisioned SCIM link are unaffected by the check", async () => {
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u-free\',\'f\',\'free@acme.example\',1,?,?)').bind(now, now).run();
  await db.prepare('INSERT INTO "account"("id","accountId","providerId","userId","password","createdAt","updatedAt") VALUES (\'acc-free\',\'u-free\',\'credential\',\'u-free\',?,?,?)')
    .bind(await hashPassword(PASSWORD), now, now).run();
  await nodeAuth.api.banUser({ body: { userId: "u-free", banReason: "Short", banExpiresIn: 1 }, headers: asAdmin() });
  await new Promise(resolve => setTimeout(resolve, 1500));
  assert.equal((await signIn("free@acme.example")).status, 200, "an ordinary lapsed ban ends at sign-in, as Better Auth intends");
});
