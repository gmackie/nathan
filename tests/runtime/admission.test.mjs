/**
 * NATH-16 in workerd: account admission (invitation-only by default, self-service optional) through
 * the built identity Worker, for every way Better Auth creates an account: password sign-up (the
 * invitation is claimed only when the address is verified), GitHub and Discord sign-in (mocked
 * providers), enterprise OIDC SSO (mocked IdP), and the first-administrator bootstrap; the real
 * invitee's way in after someone squatted their invitation; and a SCIM just-in-time claim racing a
 * Better Auth claim. SAML and the remaining SCIM just-in-time cases are in saml.test.mjs and
 * scim-lifecycle.test.mjs.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, randomKey, insertSession, studioPost, cookiesOf } from "./helpers.mjs";
import { sealProviderCredentials } from "../../src/auth/config-crypto.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST;
const KEY = randomKey(), SECRET = randomKey() + randomKey();
const CREDS = {
  github: { clientId: "Ov23liAdmissionTest01", clientSecret: "0123456789abcdef0123456789abcdef01234567" },
  discord: { clientId: "123456789012345678", clientSecret: "AbCdEfGhIjKlMnOpQrStUvWxYz012345" }
};

/** Mocked GitHub, Discord and the email API, keyed by the authorization code the test sends back. */
const codes = new Map(), oidcCodes = new Map();
const mails = [];
async function outbound(request) {
  const url = new URL(request.url);
  const body = request.method === "POST" ? await request.text() : "";
  if (url.href === "https://api.resend.com/emails") { mails.push(JSON.parse(body)); return Response.json({ id: "mail-" + mails.length }); }
  if (url.href === "https://github.com/login/oauth/access_token" || url.href === "https://discord.com/api/oauth2/token") {
    const code = new URLSearchParams(body).get("code");
    if (!codes.has(code)) return Response.json({ error: "invalid_grant" }, { status: 400 });
    return Response.json({ access_token: "at-" + code, token_type: "bearer", scope: "read:user,user:email", expires_in: 3600 });
  }
  // Enterprise OIDC IdP (acme.example): token and userinfo endpoints, no ID token.
  if (url.href === "https://idp.acme.example/token") {
    const code = new URLSearchParams(body).get("code");
    if (!oidcCodes.has(code)) return Response.json({ error: "invalid_grant" }, { status: 400 });
    return Response.json({ access_token: "oidc-" + code, token_type: "Bearer", expires_in: 300 });
  }
  if (url.href === "https://idp.acme.example/userinfo") {
    const claims = oidcCodes.get((request.headers.get("authorization") || "").replace(/^Bearer oidc-/, ""));
    return claims ? Response.json(claims) : Response.json({ error: "invalid_token" }, { status: 401 });
  }
  const grant = codes.get((request.headers.get("authorization") || "").replace(/^Bearer at-/, ""));
  if (!grant) return new Response("unexpected outbound " + url.href, { status: 599 });
  if (url.href === "https://api.github.com/user") return Response.json({ id: grant.id, login: "gh" + grant.id, name: "GitHub user" });
  if (url.href === "https://api.github.com/user/emails") return Response.json([{ email: grant.email, primary: true, verified: grant.verified }]);
  if (url.origin + decodeURIComponent(url.pathname) === "https://discord.com/api/users/@me")
    return Response.json({ id: grant.id, username: "user" + grant.id, global_name: null, avatar: null, discriminator: "0", email: grant.email, verified: grant.verified });
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

let mf, db, admin;
before(async () => {
  mf = await authWorker(HOST, {
    BETTER_AUTH_SECRET: SECRET, NATHAN_CONFIG_KEY: KEY, ENABLE_PASSWORD: "true", ENTERPRISE_SSO: "true",
    RESEND_API_KEY: "re_test_key", EMAIL_FROM: "Nathan <login@example.test>",
    NATHAN_ADMIN_EMAILS: "founder@example.test"
  }, { outboundService: outbound });
  db = await mf.getD1Database("DB");
  for (const [id, values] of Object.entries(CREDS)) {
    const sealed = await sealProviderCredentials(id, values, KEY);
    await db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,config,secret_fields,updated_by) VALUES (?,?,?,?,'test')")
      .bind(id, sealed.clientId, sealed.config, sealed.secretFields).run();
  }
  // The hosted installer recorded the Cloudflare-verified founder; no Nathan account exists yet.
  await db.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary','cf-1','founder@example.test','pending')").run();
});
after(() => mf?.dispose());

const one = (sql, ...params) => db.prepare(sql).bind(...params).first();
const all = async (sql, ...params) => (await db.prepare(sql).bind(...params).all()).results;
const userRowRaw = (id, email) => db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,0,0,0)').bind(id, id, email).run();
const userByEmail = email => one('SELECT "id" AS id, "emailVerified" AS verified FROM "user" WHERE lower("email")=?', email);
const worker = { fetch: (url, init) => mf.dispatchFetch(url, init) };
const studio = (path, body) => studioPost(worker, ORIGIN, path, body, admin.cookie);
let clients = 0;
const ip = () => "198.51.100." + (++clients % 250);

/** A complete social sign-in: start like the sign-in page, then the provider redirects back. */
async function social(provider, code, grant) {
  return (await socialStarted(provider, code, grant))();
}
/** Starts a social sign-in; the returned function is the provider's redirect back (the callback). */
async function socialStarted(provider, code, grant) {
  const started = await mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/social", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": ip() },
    body: JSON.stringify({ provider, callbackURL: "/", errorCallbackURL: "/sign-in" })
  });
  assert.equal(started.status, 200, await started.clone().text());
  const jar = cookiesOf(started);
  const state = new URL((await started.json()).url).searchParams.get("state");
  codes.set(code, grant);
  const cookie = Object.entries(jar).map(([k, v]) => k + "=" + v.value).join("; ");
  return async () => {
    const back = await mf.dispatchFetch(ORIGIN + "/api/auth/callback/" + provider + "?code=" + code + "&state=" + encodeURIComponent(state),
      { redirect: "manual", headers: { Cookie: cookie } });
    return { status: back.status, location: back.headers.get("Location") || "", session: cookiesOf(back)["__Secure-nathan.session_token"]?.value };
  };
}
const PASSWORD = "correct horse battery staple 42";
const signUp = (email, password = PASSWORD) => mf.dispatchFetch(ORIGIN + "/api/auth/sign-up/email", {
  method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": ip() },
  body: JSON.stringify({ email, password, name: "New person" })
});
const signIn = (email, password = PASSWORD) => mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/email", {
  method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": ip() },
  body: JSON.stringify({ email, password })
});
/** Opens the newest verification link mailed to an address (as the mailbox owner would). */
async function verifyEmail(email) {
  const mail = mails.filter(m => m.to[0] === email).at(-1);
  assert.ok(mail, "a verification email was sent to " + email);
  const link = /https:\/\/\S+/.exec(mail.text)[0];
  return mf.dispatchFetch(link, { redirect: "manual" });
}
/** A complete enterprise OIDC sign-in through the mocked acme.example IdP. */
async function enterprise(providerId, code, claims, between = async () => {}) {
  const started = await mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/sso", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": ip() },
    body: JSON.stringify({ providerId, callbackURL: "/", errorCallbackURL: "/sign-in" })
  });
  assert.equal(started.status, 200, await started.clone().text());
  const jar = cookiesOf(started);
  const state = new URL((await started.json()).url).searchParams.get("state");
  oidcCodes.set(code, claims);
  await between();
  const cookie = Object.entries(jar).map(([k, v]) => k + "=" + v.value).join("; ");
  const back = await mf.dispatchFetch(ORIGIN + "/api/auth/sso/callback/" + providerId + "?code=" + code + "&state=" + encodeURIComponent(state),
    { redirect: "manual", headers: { Cookie: cookie } });
  return { status: back.status, location: back.headers.get("Location") || "", session: cookiesOf(back)["__Secure-nathan.session_token"]?.value };
}
function assertRefused(result, label) {
  assert.equal(result.status, 302, label);
  assert.equal(result.session, undefined, label + ": no session");
  const location = new URL(result.location, ORIGIN);
  assert.equal(location.pathname, "/sign-in", label + ": back on the sign-in page, got " + result.location);
  assert.equal(location.searchParams.get("error"), "ACCOUNT_NOT_ADMITTED", label);
  assert.match(location.searchParams.get("error_description") || "", /invitation/i, label + ": the reason is explained");
}

test("the installation starts invitation-only, and the first administrator can still bootstrap", async () => {
  assert.equal(await one("SELECT mode FROM nathan_admission_settings"), null, "no row: the default applies");
  // A stranger is refused before any account exists.
  assertRefused(await social("github", "gh-stranger", { id: 501, email: "stranger@example.test", verified: true }), "uninvited GitHub user");
  assert.equal(await userByEmail("stranger@example.test"), null, "no user row for a refused sign-in");
  // The founder's address without proof of control (a password sign-up is unverified) is not the founder.
  assert.equal((await signUp("founder@example.test")).status, 422);
  assert.equal(await userByEmail("founder@example.test"), null, "nobody can squat the founder's address");
  // The installer-approved founder (verified email) is admitted without an invitation.
  const founder = await social("github", "gh-founder", { id: 500, email: "founder@example.test", verified: true });
  assert.equal(founder.status, 302, founder.location);
  assert.equal(founder.location, "/");
  assert.ok(founder.session, "the founder is signed in");
  const row = await userByEmail("founder@example.test");
  assert.equal(row.verified, 1);
  // The installer's bootstrap stage then promotes the account; model that, plus enrollment and step-up.
  const sql = (s, ...p) => db.prepare(s).bind(...p).run();
  await sql('UPDATE "user" SET "role"=\'admin\' WHERE "id"=?', row.id);
  await sql("UPDATE nathan_bootstrap_status SET admin_user_id=?, state='complete' WHERE id='primary'", row.id);
  await sql('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (\'pk-f\',\'x\',?,\'cred-f\',0,\'singleDevice\',0)', row.id);
  await sql('INSERT INTO "twoFactor"("id","secret","backupCodes","userId","verified") VALUES (\'tf-f\',\'x\',\'x\',?,1)', row.id);
  admin = await insertSession(db, SECRET, row.id);
  await sql("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES (?,?,'passkey')", admin.id, row.id);
  const audit = await all("SELECT action,outcome FROM nathan_security_audit WHERE action LIKE 'account_admission%'");
  assert.ok(audit.some(a => a.action === "account_admission" && a.outcome === "refused"), JSON.stringify(audit));
  assert.ok(audit.some(a => a.action === "account_admission" && a.outcome === "admitted_bootstrap"), JSON.stringify(audit));
});

test("Studio: admission mode and invitations need a stepped-up administrator, exact confirmation, and are audited", async () => {
  const member = await insertSession(db, SECRET, (await userByEmail("founder@example.test")).id);
  // The same administrator without a fresh passkey step-up is refused.
  assert.equal((await studioPost(worker, ORIGIN, "/studio/api/admission", { op: "invite", email: "x@example.test" }, member.cookie)).status, 403);
  assert.equal((await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { headers: { Cookie: member.cookie } })).status, 403);
  const cross = await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { method: "POST", body: JSON.stringify({ op: "invite", email: "x@example.test" }),
    headers: { Cookie: admin.cookie, Origin: "https://evil.example", "Content-Type": "application/json" } });
  assert.equal(cross.status, 403);
  const view = await (await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { headers: { Cookie: admin.cookie } })).json();
  assert.equal(view.mode, "invitation-only");
  assert.deepEqual(view.invitations, []);
  const vague = await studio("/studio/api/admission", { op: "mode", mode: "self-service", confirm: "yes" });
  assert.equal(vague.status, 409);
  assert.match((await vague.json()).error, /confirmation/i);
  assert.equal((await studio("/studio/api/admission", { op: "invite", email: "not-an-email" })).status, 409);
  assert.equal((await studio("/studio/api/admission", { op: "invite", email: "founder@example.test" })).status, 409, "an existing account needs no invitation");
  const audit = await all("SELECT action,outcome FROM nathan_security_audit WHERE action IN ('admission_mode_change','invitation_create')");
  assert.ok(audit.some(a => a.action === "admission_mode_change" && a.outcome === "rejected"));
  assert.ok(audit.some(a => a.action === "invitation_create" && a.outcome === "rejected"));
});

test("GitHub: an uninvited user is refused with no user row; an invited one succeeds once", async () => {
  assertRefused(await social("github", "gh-ann-1", { id: 601, email: "ann@example.test", verified: true }), "uninvited");
  assert.equal(await userByEmail("ann@example.test"), null);
  const invited = await studio("/studio/api/admission", { op: "invite", email: "Ann@Example.test", days: 3 });
  assert.equal(invited.status, 200, await invited.clone().text());
  const invitation = await invited.json();
  assert.equal(invitation.email, "ann@example.test", "bound to the normalized email");
  assert.ok(invitation.expiresAt * 1000 > Date.now() + 2.9 * 86400_000 && invitation.expiresAt * 1000 < Date.now() + 3.1 * 86400_000);
  const ok = await social("github", "gh-ann-2", { id: 601, email: "ann@example.test", verified: true });
  assert.equal(ok.location, "/", ok.location);
  assert.ok(ok.session);
  const ann = await userByEmail("ann@example.test");
  const used = await one("SELECT uses, used_by_user, used_method FROM nathan_invitations WHERE id=?", invitation.id);
  assert.deepEqual({ ...used }, { uses: 1, used_by_user: ann.id, used_method: "social:github" });
  // Signing in again is a sign-in, not a new account.
  assert.equal((await social("github", "gh-ann-3", { id: 601, email: "ann@example.test", verified: true })).location, "/");
  // Single use: once the account is gone, the same invitation does not admit it again.
  await db.prepare('DELETE FROM "user" WHERE "id"=?').bind(ann.id).run();
  assertRefused(await social("github", "gh-ann-4", { id: 601, email: "ann@example.test", verified: true }), "invitation already used");
  assert.equal(await userByEmail("ann@example.test"), null);
  const listed = (await (await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { headers: { Cookie: admin.cookie } })).json()).invitations;
  assert.equal(listed.find(i => i.id === invitation.id).state, "used");
});

test("Discord without a verified email: the placeholder address never redeems an invitation", async () => {
  await studio("/studio/api/admission", { op: "invite", email: "dee@example.test" });
  assertRefused(await social("discord", "dc-dee-1", { id: "200000000000000001", email: "dee@example.test", verified: false }), "unverified Discord email");
  assert.equal(await one('SELECT 1 FROM "user" WHERE "email" LIKE \'200000000000000001@discord%\''), null, "no placeholder account");
  assert.equal((await one("SELECT uses FROM nathan_invitations WHERE email='dee@example.test' AND revoked_at IS NULL")).uses, 0, "still unused");
  // The same person with a verified Discord email is admitted by the invitation.
  const ok = await social("discord", "dc-dee-2", { id: "200000000000000001", email: "dee@example.test", verified: true });
  assert.equal(ok.location, "/");
  assert.equal((await userByEmail("dee@example.test")).verified, 1);
});

test("password sign-up: refused unless invited; the invitation is claimed only when the address is verified", async () => {
  const refused = await signUp("pat@example.test");
  assert.equal(refused.status, 422, await refused.clone().text());
  const body = await refused.json();
  assert.equal(body.code, "ACCOUNT_NOT_ADMITTED");
  assert.match(body.message, /invitation/i);
  assert.equal(await userByEmail("pat@example.test"), null);
  assert.equal(mails.length, 0, "no verification email for a refused sign-up");
  const invitation = await (await studio("/studio/api/admission", { op: "invite", email: "pat@example.test" })).json();
  const created = await signUp("pat@example.test");
  assert.equal(created.status, 200, await created.clone().text());
  const pat = await userByEmail("pat@example.test");
  assert.equal(pat.verified, 0, "the address is proven by the verification email, as before");
  assert.equal(mails.length, 1);
  // Nothing is claimed yet: an unproven address holds no invitation, and the account cannot sign in.
  assert.equal((await one("SELECT uses FROM nathan_invitations WHERE id=?", invitation.id)).uses, 0, "still open before verification");
  assert.equal((await signIn("pat@example.test")).status, 403, "no sign-in before verification");
  const verified = await verifyEmail("pat@example.test");
  assert.equal(verified.status, 302, await verified.clone().text());
  assert.equal(verified.headers.get("Location"), "/");
  assert.equal((await userByEmail("pat@example.test")).verified, 1);
  const used = await one("SELECT uses, used_method, used_by_user FROM nathan_invitations WHERE id=?", invitation.id);
  assert.deepEqual({ ...used }, { uses: 1, used_method: "password", used_by_user: pat.id });
  assert.equal((await signIn("pat@example.test")).status, 200, "usable once verified and admitted");
  await db.prepare('DELETE FROM "user" WHERE "id"=?').bind(pat.id).run();
  assert.equal((await signUp("pat@example.test")).status, 422, "single use");
});

test("password sign-up: an invitation revoked before verification leaves the account unverified and unusable", async () => {
  const invitation = await (await studio("/studio/api/admission", { op: "invite", email: "rob@example.test" })).json();
  assert.equal((await signUp("rob@example.test")).status, 200);
  assert.equal((await studio("/studio/api/admission", { op: "revoke", id: invitation.id, confirm: "CONFIRM REVOKE INVITATION " + invitation.id })).status, 200);
  const refused = await verifyEmail("rob@example.test");
  assert.notEqual(refused.headers.get("Location"), "/", "verification does not complete");
  assert.match(await refused.text(), /ACCOUNT_NOT_ADMITTED/);
  assert.equal((await userByEmail("rob@example.test")).verified, 0);
  assert.equal((await signIn("rob@example.test")).status, 403);
  const audit = await all("SELECT outcome FROM nathan_security_audit WHERE action='account_admission' AND target='password' AND outcome='refused_at_verification'");
  assert.equal(audit.length, 1);
});

test("a squatted invitation: the real invitee's verified sign-in supersedes the unverified password account", async () => {
  const invitation = await (await studio("/studio/api/admission", { op: "invite", email: "sid@example.test" })).json();
  // Someone who knows the invited address signs up with a password first; they cannot verify it.
  assert.equal((await signUp("sid@example.test", "squatter password 1234567")).status, 200);
  const squat = await userByEmail("sid@example.test");
  assert.equal(squat.verified, 0);
  assert.equal((await one("SELECT uses FROM nathan_invitations WHERE id=?", invitation.id)).uses, 0, "the squat claims nothing");
  // An administrator cannot simply invite again while that account exists; the real person needs no help:
  const real = await social("github", "gh-sid", { id: 801, email: "sid@example.test", verified: true });
  assert.equal(real.location, "/", "the real invitee signs in: " + real.location);
  assert.ok(real.session);
  const account = await userByEmail("sid@example.test");
  assert.notEqual(account.id, squat.id, "a new account, not the squatter's");
  assert.equal(account.verified, 1);
  assert.equal(await one('SELECT 1 FROM "user" WHERE "id"=?', squat.id), null, "the squatter's account is gone");
  const used = await one("SELECT uses, used_method, used_by_user FROM nathan_invitations WHERE id=?", invitation.id);
  assert.deepEqual({ ...used }, { uses: 1, used_method: "social:github", used_by_user: account.id });
  assert.equal((await signIn("sid@example.test", "squatter password 1234567")).status, 401, "the squatter's password is gone with it");
  const audit = await all("SELECT actor, target, outcome FROM nathan_security_audit WHERE action='account_superseded'");
  assert.deepEqual(audit.map(a => ({ ...a })), [{ actor: "system:admission", target: squat.id + " email=sid@example.test provider=github", outcome: "succeeded" }]);
});

test("Studio: reissue an invitation by removing an unverified account (stepped-up administrator, confirmed, audited)", async () => {
  await studio("/studio/api/admission", { op: "invite", email: "ola@example.test" });
  assert.equal((await signUp("ola@example.test", "squatter password 7654321")).status, 200);
  const squat = await userByEmail("ola@example.test");
  const again = await studio("/studio/api/admission", { op: "invite", email: "ola@example.test" });
  assert.equal(again.status, 409);
  assert.match((await again.json()).error, /unverified.*reissue/i, "Studio explains the way out");
  assert.equal((await studio("/studio/api/admission", { op: "reissue", email: "ola@example.test", confirm: "yes" })).status, 409);
  const verifiedAccount = await studio("/studio/api/admission", { op: "reissue", email: "founder@example.test", confirm: "CONFIRM REISSUE INVITATION founder@example.test" });
  assert.equal(verifiedAccount.status, 409, "a verified account is never removed");
  const member = await insertSession(db, SECRET, (await userByEmail("founder@example.test")).id);
  assert.equal((await studioPost(worker, ORIGIN, "/studio/api/admission", { op: "reissue", email: "ola@example.test", confirm: "CONFIRM REISSUE INVITATION ola@example.test" }, member.cookie)).status, 403,
    "needs a fresh step-up");
  // An unverified account that has really been used (an enterprise SSO link from before NATH-16,
  // whose session ended at sign-out) is never removed, even though it has no current session.
  await userRowRaw("u-sso-used", "used@example.test");
  await db.prepare('INSERT INTO "account"("id","accountId","providerId","userId","createdAt","updatedAt") VALUES (\'a-sso\',\'ext-1\',\'acme-oidc\',\'u-sso-used\',0,0)').run();
  const used = await studio("/studio/api/admission", { op: "reissue", email: "used@example.test", confirm: "CONFIRM REISSUE INVITATION used@example.test" });
  assert.equal(used.status, 409, "an account with a non-password login is never removed: " + await used.clone().text());
  assert.ok(await one('SELECT 1 FROM "user" WHERE "id"=?', "u-sso-used"));
  const reissued = await studio("/studio/api/admission", { op: "reissue", email: "ola@example.test", confirm: "CONFIRM REISSUE INVITATION ola@example.test" });
  assert.equal(reissued.status, 200, await reissued.clone().text());
  const result = await reissued.json();
  assert.equal(result.removedUser, squat.id);
  assert.equal(result.state, "pending");
  assert.equal(await one('SELECT 1 FROM "user" WHERE "id"=?', squat.id), null);
  const audit = await all("SELECT action, target, outcome FROM nathan_security_audit WHERE action IN ('unverified_account_remove','invitation_create') AND outcome='succeeded' ORDER BY rowid DESC LIMIT 2");
  assert.deepEqual(audit.map(a => a.action).sort(), ["invitation_create", "unverified_account_remove"]);
  assert.equal(audit.find(a => a.action === "unverified_account_remove").target, squat.id);
  // The real person signs in with the new invitation.
  assert.equal((await social("discord", "dc-ola", { id: "400000000000000001", email: "ola@example.test", verified: true })).location, "/");
});

test("revoked and expired invitations admit nobody", async () => {
  const revokeMe = await (await studio("/studio/api/admission", { op: "invite", email: "rev@example.test" })).json();
  assert.equal((await studio("/studio/api/admission", { op: "revoke", id: revokeMe.id, confirm: "nope" })).status, 409);
  assert.equal((await studio("/studio/api/admission", { op: "revoke", id: revokeMe.id, confirm: "CONFIRM REVOKE INVITATION " + revokeMe.id })).status, 200);
  assert.equal((await signUp("rev@example.test")).status, 422);
  await studio("/studio/api/admission", { op: "invite", email: "old@example.test" });
  await db.prepare("UPDATE nathan_invitations SET expires_at=unixepoch()-1 WHERE email='old@example.test'").run();
  assert.equal((await signUp("old@example.test")).status, 422);
  assert.equal(await userByEmail("rev@example.test"), null);
  assert.equal(await userByEmail("old@example.test"), null);
  const listed = (await (await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { headers: { Cookie: admin.cookie } })).json()).invitations;
  assert.equal(listed.find(i => i.email === "rev@example.test").state, "revoked");
  assert.equal(listed.find(i => i.email === "old@example.test").state, "expired");
  // A new invitation for the same address supersedes the old one.
  await studio("/studio/api/admission", { op: "invite", email: "old@example.test" });
  assert.equal((await signUp("old@example.test")).status, 200);
});

test("self-service admits verified sign-ins without an invitation; switching back closes it again", async () => {
  const saved = await studio("/studio/api/admission", { op: "mode", mode: "self-service", confirm: "CONFIRM ADMISSION self-service" });
  assert.equal(saved.status, 200, await saved.clone().text());
  assert.equal((await saved.json()).mode, "self-service");
  assert.equal((await social("github", "gh-sam", { id: 701, email: "sam@example.test", verified: true })).location, "/");
  assert.equal((await social("discord", "dc-sue", { id: "300000000000000001", email: "sue@example.test", verified: true })).location, "/");
  assert.equal((await signUp("sal@example.test")).status, 200);
  for (const email of ["sam@example.test", "sue@example.test", "sal@example.test"]) assert.ok(await userByEmail(email), email);
  await studio("/studio/api/admission", { op: "mode", mode: "invitation-only", confirm: "CONFIRM ADMISSION invitation-only" });
  assertRefused(await social("github", "gh-tim", { id: 702, email: "tim@example.test", verified: true }), "back to invitation-only");
  const audit = await all("SELECT outcome FROM nathan_security_audit WHERE action='admission_mode_change' AND outcome='succeeded'");
  assert.equal(audit.length, 2);
});

test("the sign-in page explains a refused sign-in", async () => {
  const html = await (await mf.dispatchFetch(ORIGIN + "/sign-in?error=ACCOUNT_NOT_ADMITTED")).text();
  // NATH-38: explained on the server (no script needed), with the reason code.
  assert.match(html, /invitation only[^<]*\(ACCOUNT_NOT_ADMITTED\)/);
  // The sign-in behaviour is the SRI-pinned sign-in island; its social sign-in returns here on errors.
  const island = /<script type="module" src="(\/__nathan\/ui\/sign-in-[A-Za-z0-9]+\.js)"/.exec(html)?.[1];
  assert.ok(island, "the sign-in island is loaded");
  assert.match(await (await mf.dispatchFetch(ORIGIN + island)).text(), /errorCallbackURL:"\/sign-in"/, "social sign-in returns to the sign-in page on errors");
});

test("enterprise OIDC SSO: an invitation is claimed only for an address inside the connection's verified domain", async () => {
  const founder = await userByEmail("founder@example.test");
  const config = {
    issuer: "https://idp.acme.example", clientId: "nathan-acme", clientSecret: "acme-oidc-secret-0123", pkce: true,
    authorizationEndpoint: "https://idp.acme.example/authorize", tokenEndpoint: "https://idp.acme.example/token",
    userInfoEndpoint: "https://idp.acme.example/userinfo", jwksEndpoint: "https://idp.acme.example/jwks"
  };
  await db.prepare('INSERT INTO "ssoProvider"("id","issuer","oidcConfig","userId","providerId","domain","domainVerified") VALUES (\'sso-acme\',?,?,?,\'acme-oidc\',\'acme.example\',1)')
    .bind(config.issuer, JSON.stringify(config), founder.id).run();
  for (const email of ["out@outside.example", "ivy@acme.example", "zed@acme.example"]) await studio("/studio/api/admission", { op: "invite", email });
  // The IdP asserts an invited address outside the domain it proved (even claiming it is verified).
  const outside = await enterprise("acme-oidc", "oidc-out", { sub: "acme-1", email: "out@outside.example", email_verified: true });
  assert.equal(outside.session, undefined, "no session: " + outside.location);
  assert.equal(await userByEmail("out@outside.example"), null, "no user for an address the connection cannot prove");
  assert.equal((await one("SELECT uses FROM nathan_invitations WHERE email='out@outside.example' AND revoked_at IS NULL")).uses, 0, "invitation unclaimed");
  // A connection whose domain is no longer verified proves nothing.
  const unverified = await enterprise("acme-oidc", "oidc-zed", { sub: "acme-2", email: "zed@acme.example", email_verified: true },
    () => db.prepare('UPDATE "ssoProvider" SET "domainVerified"=0 WHERE "providerId"=\'acme-oidc\'').run());
  await db.prepare('UPDATE "ssoProvider" SET "domainVerified"=1 WHERE "providerId"=\'acme-oidc\'').run();
  assert.equal(unverified.session, undefined);
  assert.equal(await userByEmail("zed@acme.example"), null);
  assert.equal((await one("SELECT uses FROM nathan_invitations WHERE email='zed@acme.example' AND revoked_at IS NULL")).uses, 0);
  // Inside the verified domain the connection proves the address, as SAML does.
  const inside = await enterprise("acme-oidc", "oidc-ivy", { sub: "acme-3", email: "ivy@acme.example" });
  assert.equal(inside.location, "/", inside.location);
  assert.ok(inside.session);
  const ivy = await userByEmail("ivy@acme.example");
  assert.equal(ivy.verified, 1);
  const used = await one("SELECT uses, used_method, used_by_user FROM nathan_invitations WHERE email='ivy@acme.example'");
  assert.deepEqual({ ...used }, { uses: 1, used_method: "enterprise-sso:acme-oidc", used_by_user: ivy.id });
});

test("a SCIM just-in-time claim racing a Better Auth claim for the same invitation: exactly one account, one claim", async () => {
  const founder = await userByEmail("founder@example.test");
  await db.prepare('INSERT INTO "ssoProvider"("id","issuer","userId","providerId","domain","domainVerified") VALUES (\'sso-race\',\'https://idp.race.example\',?,\'race-sso\',\'race.example\',1)')
    .bind(founder.id).run();
  const created = await studio("/studio/api/scim/connections", { id: "race", domain: "race.example" });
  assert.equal(created.status, 200, await created.clone().text());
  const token = (await created.json()).bearerToken;
  assert.equal((await studio("/studio/api/scim/status", { id: "race", enabled: true, confirm: "CONFIRM ENABLE race" })).status, 200);
  assert.equal((await studio("/studio/api/scim/settings", { id: "race", linking: true, jit: true, confirm: "CONFIRM SCIM SETTINGS race" })).status, 200);
  const scimCreate = email => mf.dispatchFetch(ORIGIN + "/scim/v2/race/Users", {
    method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/scim+json" },
    body: JSON.stringify({ schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: email, externalId: "ext-" + email,
      emails: [{ value: email, primary: true, type: "work" }], displayName: "Racer", active: true })
  });
  const winners = new Set();
  for (let round = 0; round < 8; round++) {
    const email = "racer" + round + "@race.example";
    const invitation = await (await studio("/studio/api/admission", { op: "invite", email })).json();
    // The sign-in is started first; its callback (where Better Auth claims) races the SCIM create,
    // with a head start for one side that varies by round, against the same open invitation.
    const callback = await socialStarted("github", "gh-race-" + round, { id: 900 + round, email, verified: true });
    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
    const head = [0, 5, 15, 30][round % 4];
    const [scimResult, socialResult] = round % 2
      ? await Promise.all([delay(head).then(() => scimCreate(email)), callback()])
      : await Promise.all([scimCreate(email), delay(head).then(callback)]);
    const accounts = await all('SELECT "id" AS id FROM "user" WHERE lower("email")=?', email);
    assert.equal(accounts.length, 1, "round " + round + ": exactly one account");
    const used = await one("SELECT uses, used_method, used_by_user FROM nathan_invitations WHERE id=?", invitation.id);
    assert.equal(used.uses, 1, "round " + round + ": claimed once");
    assert.equal(used.used_by_user, accounts[0].id, "round " + round + ": by the account that exists");
    winners.add(used.used_method);
    if (used.used_method === "social:github") {
      assert.ok(socialResult.session, "round " + round + ": the Better Auth sign-in won");
      const link = await one("SELECT link_method FROM nathan_scim_users WHERE connection_id='race' AND external_id=?", "ext-" + email);
      assert.notEqual(link?.link_method, "jit", "round " + round + ": SCIM created no second account");
    } else {
      assert.equal(used.used_method, "scim:race");
      assert.equal(socialResult.session, undefined, "round " + round + ": the losing Better Auth sign-in gets no account or session");
      assert.ok(scimResult.status < 300, "round " + round + ": SCIM accepted the user");
    }
  }
  assert.ok(winners.size >= 1);
});

test("Studio: installations that had accounts before 0017 get a one-time notice linking to the admission setting", async () => {
  const view = async () => (await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { headers: { Cookie: admin.cookie } })).json();
  // This installation was migrated before it had accounts: the default was recorded, no notice.
  const recorded = await all("SELECT target FROM nathan_security_audit WHERE action='admission_default_invitation_only'");
  assert.deepEqual(recorded.map(r => r.target), ["no-existing-users"]);
  assert.equal((await view()).upgradeNotice, undefined);
  // An upgraded installation (accounts existed when 0017 ran):
  await db.prepare("UPDATE nathan_security_audit SET target='existing-users' WHERE action='admission_default_invitation_only'").run();
  await db.prepare("DELETE FROM nathan_security_audit WHERE action='admission_mode_change'").run();
  assert.match((await view()).upgradeNotice, /invitation.*SCIM just-in-time/s);
  const page = await (await mf.dispatchFetch(ORIGIN + "/studio", { headers: { Cookie: admin.cookie } })).text();
  assert.match(page, /href="#adm-mode"/, "the notice links to the setting");
  assert.match(page, /enterprise SSO \(SAML and OIDC\)/);
  assert.equal((await studio("/studio/api/admission", { op: "dismiss-upgrade-notice" })).status, 200);
  assert.equal((await view()).upgradeNotice, undefined, "shown once");
  assert.equal((await one("SELECT outcome FROM nathan_security_audit WHERE action='admission_upgrade_notice_dismiss'")).outcome, "succeeded");
});
