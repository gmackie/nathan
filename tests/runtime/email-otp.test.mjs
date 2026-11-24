/**
 * NATH-49 in workerd: passwordless email sign-in codes through the built identity Worker, with a
 * mocked Resend. Off by default; fails closed without Resend; generic answers; codes mailed only to
 * addresses that could sign in (invitation-only); per-IP and per-address limits; 10-minute,
 * 3-attempt codes; admission (invitation claim, self-service, refusal); an unverified squatted
 * account; no assurance evidence; audit; and an app's OIDC authorization resuming after sign-in.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { authWorker, randomKey, cookiesOf } from "./helpers.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST;
const SECRET = randomKey() + randomKey();
const RESEND = { RESEND_API_KEY: "re_test_key", EMAIL_FROM: "Nathan <login@example.test>" };

const mails = [];
let resendStatus = 200;
async function outbound(request) {
  if (request.url === "https://api.resend.com/emails") {
    const mail = JSON.parse(await request.text());
    if (resendStatus !== 200) return new Response("unavailable", { status: resendStatus });
    mails.push(mail);
    return Response.json({ id: "mail-" + mails.length });
  }
  return new Response("unexpected outbound " + request.url, { status: 599 });
}
const logs = [];
const capture = { log: line => logs.push(String(line)) };

let mf, db, off, noMail;
before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, ENABLE_EMAIL_OTP: "true", NATHAN_INSTANCE_NAME: "Example", ...RESEND },
    { outboundService: outbound, handleStructuredLogs: ({ message }) => capture.log(message) });
  db = await mf.getD1Database("DB");
  await db.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary','cf','founder@example.test','pending')").run();
});
after(async () => { await mf?.dispose(); await off?.dispose(); await noMail?.dispose(); });

let clients = 0;
const ip = () => "203.0.113." + (++clients % 250);
const one = (sql, ...params) => db.prepare(sql).bind(...params).first();
const resetLimits = () => db.prepare('DELETE FROM "rateLimit"').run();
const post = (worker, path, body, { from = ip(), headers = {} } = {}) => worker.dispatchFetch(ORIGIN + "/api/auth" + path, {
  method: "POST", redirect: "manual",
  headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": from, ...headers },
  body: JSON.stringify(body)
});
/** Mails seen per address before its latest send, so codeFor waits for the new one. */
const sentBefore = new Map();
const send = (email, options) => {
  sentBefore.set(email, mails.filter(m => m.to[0] === email).length);
  return post(mf, "/email-otp/send-verification-otp", { email, type: "sign-in" }, options);
};
const verify = (email, otp, extra = {}, options) => post(mf, "/sign-in/email-otp", { email, otp, ...extra }, options);
/** Lets background work (the mail is sent with waitUntil) finish. */
const settle = () => new Promise(resolve => setTimeout(resolve, 150));
async function codeFor(email, before = sentBefore.get(email) ?? 0) {
  // The mail is sent after the response (waitUntil); wait for it on a loaded machine.
  for (let i = 0; i < 50 && mailCount(email) <= before; i++) await settle();
  const mail = mails.filter(m => m.to[0] === email).at(-1);
  assert.ok(mail, "a code was mailed to " + email);
  return /\b(\d{6})\b/.exec(mail.text)[1];
}
const mailCount = email => mails.filter(m => m.to[0] === email).length;
const userByEmail = email => one('SELECT "id" AS id, "emailVerified" AS verified, "name" AS name FROM "user" WHERE lower("email")=?', email);
const invite = (email, id = crypto.randomUUID()) =>
  db.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,'admin',unixepoch()+3600)").bind(id, email).run().then(() => id);
const existingUser = async (email, verified = 1, id = "u-" + crypto.randomUUID()) => {
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)').bind(id, "Someone", email, verified, now, now).run();
  return id;
};

test("off by default: no routes, and the sign-in page does not offer it", async () => {
  off = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, ...RESEND });
  const sent = await post(off, "/email-otp/send-verification-otp", { email: "a@example.test", type: "sign-in" });
  assert.equal(sent.status, 404);
  assert.equal((await post(off, "/sign-in/email-otp", { email: "a@example.test", otp: "123456" })).status, 404);
  const page = await (await off.dispatchFetch(ORIGIN + "/sign-in")).text();
  assert.ok(!page.includes("Email me a code"));
});

test("enabled without Resend: sending fails closed and the page does not offer it", async () => {
  noMail = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, ENABLE_EMAIL_OTP: "true" });
  const sent = await post(noMail, "/email-otp/send-verification-otp", { email: "a@example.test", type: "sign-in" });
  assert.equal(sent.status, 503);
  assert.equal((await sent.json()).code, "EMAIL_SIGN_IN_UNAVAILABLE");
  assert.ok(!(await (await noMail.dispatchFetch(ORIGIN + "/sign-in")).text()).includes("Email me a code"));
});

test("the hosted sign-in page offers 'Email me a code' when enabled", async () => {
  const page = await (await mf.dispatchFetch(ORIGIN + "/sign-in")).text();
  assert.match(page, /Email me a code/);
  assert.match(page, /autocomplete="one-time-code"/);
  assert.match(page, /\/sign-in\/email-otp/);
});

test("only sign-in codes: other OTP types and the other emailOTP routes are refused", async () => {
  for (const type of ["email-verification", "forget-password", "change-email"]) {
    const response = await post(mf, "/email-otp/send-verification-otp", { email: "member@example.test", type });
    assert.equal(response.status, 400, type);
  }
  for (const path of ["/email-otp/check-verification-otp", "/email-otp/verify-email", "/email-otp/request-password-reset",
    "/email-otp/reset-password", "/forget-password/email-otp", "/email-otp/request-email-change", "/email-otp/change-email"]) {
    const response = await post(mf, path, { email: "member@example.test", otp: "123456", type: "sign-in", password: "x".repeat(20) });
    assert.equal(response.status, 404, path);
  }
  const extra = await verify("member@example.test", "123456", { name: "Administrator" });
  assert.equal(extra.status, 400);
});

test("sending answers the same for every address; invitation-only mails only addresses that could sign in", async () => {
  await existingUser("member@example.test");
  const known = await send("member@example.test");
  const unknown = await send("stranger@example.test");
  assert.equal(known.status, 200);
  assert.equal(unknown.status, 200);
  assert.deepEqual(await known.json(), await unknown.json());
  await settle();
  assert.equal(mailCount("member@example.test"), 1);
  assert.equal(mailCount("stranger@example.test"), 0, "no mail to an address that could not sign in");
  // A guess for the stranger fails exactly like a wrong code for the member.
  const wrongKnown = await verify("member@example.test", "000000");
  const wrongUnknown = await verify("stranger@example.test", "000000");
  assert.equal(wrongKnown.status, wrongUnknown.status);
  assert.deepEqual((await wrongKnown.json()).code, (await wrongUnknown.json()).code);
  assert.equal(await userByEmail("stranger@example.test"), null);
});

test("the email has the code and the requesting host; the code is stored hashed and never logged", async () => {
  await resetLimits();
  await send("member@example.test");
  const code = await codeFor("member@example.test");
  const mail = mails.at(-1);
  assert.equal(mail.from, RESEND.EMAIL_FROM);
  assert.equal(mail.subject, "Your Example sign-in code");
  assert.match(mail.text, new RegExp(HOST.replaceAll(".", "\\.")));
  const stored = await one('SELECT "value" AS value FROM "verification" WHERE "identifier"=?', "sign-in-otp-member@example.test");
  assert.ok(stored && !stored.value.includes(code), "stored hashed");
  assert.ok(!logs.join("\n").includes(code), "the code is not logged");
});

test("a code signs an existing account in, once, with no assurance evidence; the sign-in is audited", async () => {
  await resetLimits();
  await send("member@example.test");
  const code = await codeFor("member@example.test");
  const signedIn = await verify("member@example.test", code);
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  const session = cookiesOf(signedIn)["__Secure-nathan.session_token"];
  assert.ok(session?.value, "a session cookie");
  const user = await userByEmail("member@example.test");
  const row = await one('SELECT "id" AS id FROM "session" WHERE "userId"=? ORDER BY "createdAt" DESC LIMIT 1', user.id);
  assert.equal(await one("SELECT 1 AS x FROM nathan_admin_assurance WHERE session_id=?", row.id), null, "no assurance evidence");
  assert.ok(await one("SELECT 1 AS x FROM nathan_security_audit WHERE action='email_otp_sign_in' AND actor=? AND target=? AND outcome='succeeded'", user.id, row.id));
  // Single use.
  assert.equal((await verify("member@example.test", code)).status, 400);
});

test("three wrong guesses invalidate a code, even for the right one after", async () => {
  await resetLimits();
  await send("member@example.test");
  const code = await codeFor("member@example.test");
  const wrong = code === "111111" ? "222222" : "111111";
  for (let i = 0; i < 3; i++) assert.equal((await verify("member@example.test", wrong)).status, 400);
  const blocked = await verify("member@example.test", code);
  assert.equal(blocked.status, 403);
  assert.equal((await blocked.json()).code, "TOO_MANY_ATTEMPTS");
  assert.equal((await verify("member@example.test", code)).status, 400, "the code is gone");
  assert.ok(await one("SELECT 1 AS x FROM nathan_security_audit WHERE action='email_otp_sign_in' AND outcome='rejected'"));
});

test("a code expires after 10 minutes", async () => {
  await resetLimits();
  await send("member@example.test");
  const code = await codeFor("member@example.test");
  const row = await one('SELECT "expiresAt" AS expiresAt FROM "verification" WHERE "identifier"=?', "sign-in-otp-member@example.test");
  const expires = new Date(typeof row.expiresAt === "number" ? row.expiresAt : Date.parse(row.expiresAt)).getTime();
  assert.ok(Math.abs(expires - (Date.now() + 600_000)) < 30_000, "about 10 minutes from now");
  await db.prepare('UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?').bind(new Date(Date.now() - 1000).toISOString(), "sign-in-otp-member@example.test").run();
  const late = await verify("member@example.test", code);
  assert.equal(late.status, 400);
  assert.equal((await late.json()).code, "OTP_EXPIRED");
});

test("a new code replaces the previous one", async () => {
  await resetLimits();
  await send("member@example.test");
  const first = await codeFor("member@example.test");
  await send("member@example.test");
  const second = await codeFor("member@example.test");
  if (first !== second) assert.equal((await verify("member@example.test", first)).status, 400);
  assert.equal((await verify("member@example.test", second)).status, 200);
});

test("per-address limits on sending and verifying, across IPs", async () => {
  await resetLimits();
  for (let i = 0; i < 3; i++) assert.equal((await send("limited@example.test")).status, 200);
  const sent = await send("limited@example.test");
  assert.equal(sent.status, 429);
  assert.ok(Number(sent.headers.get("X-Retry-After")) > 0);
  // Wrong codes: 400, then 403 once the code has used its attempts; the sixth try is over the address limit.
  for (let i = 0; i < 5; i++) assert.ok([400, 403].includes((await verify("limited@example.test", "000000")).status));
  assert.equal((await verify("limited@example.test", "000000")).status, 429);
  assert.ok(await one("SELECT 1 AS x FROM nathan_security_audit WHERE action='email_otp_rate_limited' AND outcome='refused'"));
  const keys = (await db.prepare('SELECT "key" FROM "rateLimit"').all()).results.map(r => r.key);
  assert.ok(keys.every(k => !k.includes("limited@example.test")), "no address in the rate-limit table");
});

test("per-IP limits on sending and verifying, across addresses", async () => {
  await resetLimits();
  const from = "198.51.100.77";
  for (let i = 0; i < 10; i++) assert.equal((await send("ip" + i + "@example.test", { from })).status, 200, "send " + i);
  assert.equal((await send("ip-last@example.test", { from })).status, 429);
  for (let i = 0; i < 20; i++) assert.equal((await verify("v" + i + "@example.test", "000000", {}, { from })).status, 400, "verify " + i);
  assert.equal((await verify("v-last@example.test", "000000", {}, { from })).status, 429);
});

test("a failed delivery still answers generically and logs no code or address", async () => {
  await resetLimits();
  resendStatus = 500;
  try {
    const sent = await send("member@example.test");
    assert.equal(sent.status, 200);
    await settle();
  } finally { resendStatus = 200; }
  // The Worker's own output is captured (the delivery failure is reported, by status only).
  for (let i = 0; i < 50 && !logs.join("").includes("not delivered"); i++) await settle();
  assert.match(logs.join(""), /Email sign-in code not delivered \(Resend 500\)/);
  assert.ok(!logs.join("\n").includes("member@example.test"), "no address in the logs");
});

test("invitation-only: an unknown address creates no account, even with a valid code", async () => {
  await resetLimits();
  // The send step stores a code but mails nothing; plant a known code to prove admission still refuses.
  await send("uninvited@example.test");
  await settle();
  const hash = createHash("sha256").update("424242").digest("base64url");
  await db.prepare('UPDATE "verification" SET "value"=? WHERE "identifier"=?').bind(hash + ":0", "sign-in-otp-uninvited@example.test").run();
  const refused = await verify("uninvited@example.test", "424242");
  assert.equal(refused.status, 422, await refused.clone().text());
  assert.equal((await refused.json()).code, "ACCOUNT_NOT_ADMITTED");
  assert.equal(await userByEmail("uninvited@example.test"), null);
  assert.ok(await one("SELECT 1 AS x FROM nathan_security_audit WHERE action='account_admission' AND target='email-otp' AND outcome='refused'"));
});

test("invitation-only: a code claims an open invitation and creates a verified account with no profile from the request", async () => {
  await resetLimits();
  const id = await invite("invitee@example.test");
  await send("invitee@example.test");
  const signedIn = await verify("invitee@example.test", await codeFor("invitee@example.test"));
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  const user = await userByEmail("invitee@example.test");
  assert.equal(user.verified, 1);
  assert.equal(user.name, "");
  const invitation = await one("SELECT uses, used_method AS method, used_by_user AS userId FROM nathan_invitations WHERE id=?", id);
  assert.deepEqual({ ...invitation }, { uses: 1, method: "email-otp", userId: user.id });
});

test("the installer's first administrator may sign up by code, but gains no admin assurance", async () => {
  await resetLimits();
  await send("founder@example.test");
  const signedIn = await verify("founder@example.test", await codeFor("founder@example.test"));
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  const user = await userByEmail("founder@example.test");
  assert.equal(await one("SELECT 1 AS x FROM nathan_admin_assurance WHERE user_id=?", user.id), null);
  const cookie = "__Secure-nathan.session_token=" + cookiesOf(signedIn)["__Secure-nathan.session_token"].value;
  const studio = await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { headers: { Cookie: cookie } });
  assert.notEqual(studio.status, 200, "an email-code session is not an administrator session");
});

test("a squatted, unverified password account for an invited address: the code admits the real owner and drops the squatter's profile", async () => {
  await resetLimits();
  const squatter = await existingUser("squatted@example.test", 0);
  await db.prepare("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES ('squatted@example.test',?,'password')").bind(squatter).run();
  await db.prepare('INSERT INTO "account"("id","accountId","providerId","userId","password","createdAt","updatedAt") VALUES (?,?,\'credential\',?,\'hash\',?,?)')
    .bind("acc-" + squatter, squatter, squatter, new Date().toISOString(), new Date().toISOString()).run();
  const id = await invite("squatted@example.test");
  await send("squatted@example.test");
  const signedIn = await verify("squatted@example.test", await codeFor("squatted@example.test"));
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  const user = await userByEmail("squatted@example.test");
  assert.equal(user.verified, 1);
  assert.equal(user.name, "", "the squatter's profile is dropped");
  assert.equal(await one('SELECT 1 AS x FROM "account" WHERE "userId"=?', squatter), null, "the squatter's password is gone");
  assert.equal((await one("SELECT used_method AS m FROM nathan_invitations WHERE id=?", id)).m, "email-otp");
});

test("a squatted, unverified account whose invitation is gone stays unverified", async () => {
  await resetLimits();
  const squatter = await existingUser("orphan@example.test", 0);
  await db.prepare("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES ('orphan@example.test',?,'password')").bind(squatter).run();
  // An account exists, so a code is mailed; there is no open invitation to claim.
  await send("orphan@example.test");
  const refused = await verify("orphan@example.test", await codeFor("orphan@example.test"));
  assert.equal(refused.status, 422, await refused.clone().text());
  assert.equal((await userByEmail("orphan@example.test")).verified, 0);
  assert.equal(await one('SELECT 1 AS x FROM "session" WHERE "userId"=?', squatter), null);
});

test("self-service: a code creates the account", async () => {
  await resetLimits();
  await db.prepare("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','admin') ON CONFLICT(id) DO UPDATE SET mode='self-service'").run();
  try {
    await send("newcomer@example.test");
    const signedIn = await verify("newcomer@example.test", await codeFor("newcomer@example.test"));
    assert.equal(signedIn.status, 200, await signedIn.clone().text());
    assert.equal((await userByEmail("newcomer@example.test")).verified, 1);
    assert.ok(await one("SELECT 1 AS x FROM nathan_security_audit WHERE action='account_admission' AND target='email-otp' AND outcome='admitted_self_service'"));
  } finally {
    await db.prepare("UPDATE nathan_admission_settings SET mode='invitation-only' WHERE id='primary'").run();
  }
});

test("an app's OIDC authorization resumes after an email-code sign-in", async () => {
  await resetLimits();
  const CLIENT = "app-" + randomKey().slice(0, 8), REDIRECT = "https://app.example.test/api/auth/callback/nathan";
  await db.prepare('INSERT INTO "oauthClient"("id","clientId","redirectUris","disabled","skipConsent","tokenEndpointAuthMethod","requirePKCE","subjectType","createdAt","updatedAt") VALUES (?,?,?,0,1,\'none\',1,\'public\',?,?)')
    .bind("oc-" + CLIENT, CLIENT, JSON.stringify([REDIRECT]), Date.now(), Date.now()).run();
  const state = randomKey();
  const query = new URLSearchParams({ response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT, scope: "openid profile email",
    state, code_challenge: createHash("sha256").update(randomKey()).digest("base64url"), code_challenge_method: "S256" });
  const authorize = await mf.dispatchFetch(ORIGIN + "/api/auth/oauth2/authorize?" + query, { redirect: "manual",
    headers: { Accept: "text/html", "Sec-Fetch-Mode": "navigate" } });
  const login = new URL(authorize.headers.get("Location") ?? (await authorize.json()).url, ORIGIN);
  assert.equal(login.pathname, "/sign-in");
  const { signedOAuthQuery } = await import("../../src/auth/oauth-query.mjs");
  const oauthQuery = signedOAuthQuery(login.search);
  assert.ok(oauthQuery);
  await send("member@example.test");
  const signedIn = await verify("member@example.test", await codeFor("member@example.test"), { oauth_query: oauthQuery });
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  const body = await signedIn.json();
  const resumed = new URL(body.url, ORIGIN);
  assert.equal(resumed.origin + resumed.pathname, REDIRECT, "back to the app: " + resumed.href);
  assert.ok(resumed.searchParams.get("code"));
  assert.equal(resumed.searchParams.get("state"), state);
});

test("an administrator account gets no code, and a code attempt fails like a wrong code", async () => {
  await resetLimits();
  const adminId = await existingUser("boss@example.test");
  await db.prepare('UPDATE "user" SET "role"=\'admin\' WHERE "id"=?').bind(adminId).run();
  const sent = await send("boss@example.test");
  assert.equal(sent.status, 200);
  assert.deepEqual(await sent.json(), { success: true });
  await settle(); await settle();
  assert.equal(mailCount("boss@example.test"), 0);
  // Plant a valid code: the administrator is still refused, with the same answer as a wrong code.
  const hash = createHash("sha256").update("515151").digest("base64url");
  await db.prepare('UPDATE "verification" SET "value"=? WHERE "identifier"=?').bind(hash + ":0", "sign-in-otp-boss@example.test").run();
  const refused = await verify("boss@example.test", "515151");
  const wrong = await verify("member@example.test", "000001");
  assert.equal(refused.status, wrong.status);
  assert.deepEqual(await refused.json(), await wrong.json());
  assert.equal(await one('SELECT 1 AS x FROM "session" WHERE "userId"=?', adminId), null);
});
