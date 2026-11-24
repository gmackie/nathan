/** NATH-49: passwordless email sign-in policy (limits, recipients, the email, request shape), on node:sqlite. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { d1, migratedDatabase } from "./fixtures/d1-sqlite.mjs";
import {
  EMAIL_OTP, SEND_PATH, VERIFY_PATH, DISABLED_EMAIL_OTP_PATHS, IP_LIMITS, ADDRESS_LIMITS, emailOtpEnabled, emailDeliveryConfigured,
  emailOtpOffered, requestProblem, addressLimitKey, consumeAddressLimit, mayReceiveSignInCode, signInCodeMail, isAdministratorAccount
} from "../src/auth/email-otp-policy.mjs";
import { creationMethod, admitOnVerification } from "../src/auth/admission-policy.mjs";
import { evidenceClaims } from "../src/shared/token-claims.mjs";

const RESEND = { RESEND_API_KEY: "re_x", EMAIL_FROM: "Nathan <login@example.test>" };
const database = () => { const raw = migratedDatabase(); return Object.assign(d1(raw), { raw }); };

test("the method is off unless the instance enables it, and offered only with mail configured", () => {
  assert.equal(emailOtpEnabled({}), false);
  assert.equal(emailOtpEnabled({ ENABLE_EMAIL_OTP: "false" }), false);
  assert.equal(emailOtpEnabled({ ENABLE_EMAIL_OTP: "1" }), false);
  assert.equal(emailOtpEnabled({ ENABLE_EMAIL_OTP: "true" }), true);
  assert.equal(emailDeliveryConfigured({ RESEND_API_KEY: "re_x" }), false);
  assert.equal(emailDeliveryConfigured({ EMAIL_FROM: "a@b.test" }), false);
  assert.equal(emailDeliveryConfigured(RESEND), true);
  assert.equal(emailOtpOffered({ ENABLE_EMAIL_OTP: "true" }), false);
  assert.equal(emailOtpOffered({ ...RESEND }), false);
  assert.equal(emailOtpOffered({ ENABLE_EMAIL_OTP: "true", ...RESEND }), true);
});

test("deployed configurations keep the flag off except staging", () => {
  const vars = file => JSON.parse(readFileSync(file, "utf8").replace(/^\s*\/\/.*$/gm, "")).vars;
  assert.equal(vars("wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "false");
  assert.equal(vars("deploy/production/wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "false");
  assert.equal(vars("deploy/staging/wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "true");
});

test("codes are short-lived, few-attempt, 6 digits; limits stay inside Better Auth's pruning window", () => {
  assert.equal(EMAIL_OTP.expiresIn, 600);
  assert.equal(EMAIL_OTP.allowedAttempts, 3);
  assert.equal(EMAIL_OTP.otpLength, 6);
  assert.deepEqual(Object.keys(IP_LIMITS).sort(), [SEND_PATH, VERIFY_PATH].sort());
  // Better Auth prunes rate-limit rows older than its longest configured window (the IP rules here).
  assert.ok(Math.max(...Object.values(ADDRESS_LIMITS).map(r => r.window)) <= Math.max(...Object.values(IP_LIMITS).map(r => r.window)));
  assert.ok(ADDRESS_LIMITS.send.max <= 3 && ADDRESS_LIMITS.verify.max <= 5);
});

test("only sign-in routes stay reachable", () => {
  for (const path of ["/email-otp/check-verification-otp", "/email-otp/verify-email", "/email-otp/request-password-reset",
    "/email-otp/reset-password", "/forget-password/email-otp", "/email-otp/request-email-change", "/email-otp/change-email"])
    assert.ok(DISABLED_EMAIL_OTP_PATHS.includes(path), path);
  assert.ok(!DISABLED_EMAIL_OTP_PATHS.includes(SEND_PATH) && !DISABLED_EMAIL_OTP_PATHS.includes(VERIFY_PATH));
});

test("requests carry exactly the hosted page's fields", () => {
  assert.equal(requestProblem(SEND_PATH, { email: "a@example.test", type: "sign-in" }), null);
  assert.equal(requestProblem(SEND_PATH, { email: "a@example.test", type: "email-verification" }), "Only sign-in codes are available");
  assert.equal(requestProblem(SEND_PATH, { email: "a@example.test", type: "forget-password" }), "Only sign-in codes are available");
  assert.equal(requestProblem(SEND_PATH, { email: "not-an-address", type: "sign-in" }), "Enter a valid email address");
  assert.equal(requestProblem(SEND_PATH, { email: "a@example.test", type: "sign-in", callbackURL: "/" }), "Unsupported field");
  assert.equal(requestProblem(SEND_PATH, null), "Invalid request");
  assert.equal(requestProblem(SEND_PATH, ["a"]), "Invalid request");
  assert.equal(requestProblem(VERIFY_PATH, { email: "a@example.test", otp: "123456" }), null);
  assert.equal(requestProblem(VERIFY_PATH, { email: "a@example.test", otp: "123456", oauth_query: "a=b&sig=c" }), null);
  assert.equal(requestProblem(VERIFY_PATH, { email: "a@example.test", otp: "123456", oauth_query: 7 }), "Invalid request");
  // A first sign-in creates the account: no profile or other user fields from the request.
  assert.equal(requestProblem(VERIFY_PATH, { email: "a@example.test", otp: "123456", name: "Admin" }), "Unsupported field");
  assert.equal(requestProblem(VERIFY_PATH, { email: "a@example.test", otp: "123456", image: "https://x.test/a.png" }), "Unsupported field");
  assert.equal(requestProblem(VERIFY_PATH, { email: "a@example.test", otp: "123456", role: "admin" }), "Unsupported field");
  for (const otp of ["12345", "1234567", "12 456", "abcdef", 123456, ""])
    assert.equal(requestProblem(VERIFY_PATH, { email: "a@example.test", otp }), "Enter the 6-digit code from the email", String(otp));
  assert.equal(requestProblem("/sign-in/email", { anything: true }), null, "other routes are not this guard's business");
});

test("per-address limits: atomic, hashed keys, Better Auth's rolling window", async () => {
  const db = database();
  const rule = { window: 600, max: 3 }, t0 = 1_700_000_000_000;
  for (let i = 0; i < 3; i++) assert.equal((await consumeAddressLimit(db, "send", "a@example.test", rule, t0 + i)).allowed, true);
  const refused = await consumeAddressLimit(db, "send", "a@example.test", rule, t0 + 10_000);
  assert.equal(refused.allowed, false);
  assert.ok(refused.retryAfter > 0 && refused.retryAfter <= 600);
  // A refused request does not extend the window: it restarts 600 s after the last allowed one.
  assert.equal((await consumeAddressLimit(db, "send", "a@example.test", rule, t0 + 2 + 599_000)).allowed, false);
  assert.equal((await consumeAddressLimit(db, "send", "a@example.test", rule, t0 + 2 + 600_000)).allowed, true);
  // Other addresses and the other kind count separately.
  assert.equal((await consumeAddressLimit(db, "send", "b@example.test", rule, t0)).allowed, true);
  assert.equal((await consumeAddressLimit(db, "verify", "a@example.test", rule, t0 + 10_000)).allowed, true);
  // Concurrent requests cannot overshoot.
  const burst = await Promise.all(Array.from({ length: 10 }, () => consumeAddressLimit(db, "verify", "c@example.test", rule, t0)));
  assert.equal(burst.filter(r => r.allowed).length, 3);
  // The table never holds an address.
  const keys = db.raw.prepare('SELECT "key" FROM "rateLimit"').all().map(r => r.key);
  assert.ok(keys.length >= 4);
  assert.ok(keys.every(k => !k.includes("@") && /^nathan-email-otp:(send|verify):[0-9a-f]{64}$/.test(k)), keys.join());
  assert.equal(await addressLimitKey("send", "a@example.test"), await addressLimitKey("send", "a@example.test"));
  assert.notEqual(await addressLimitKey("send", "a@example.test"), await addressLimitKey("verify", "a@example.test"));
});

test("invitation-only mode mails codes only to addresses that could sign in", async () => {
  const db = database();
  const env = { NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_EMAILS: "" };
  assert.equal(await mayReceiveSignInCode(db, env, "stranger@example.test"), false);
  assert.equal(await mayReceiveSignInCode(db, env, "nope"), false);
  db.raw.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u1\',\'\',\'Member@Example.test\',1,0,0)').run();
  assert.equal(await mayReceiveSignInCode(db, env, "member@example.test"), true, "an existing account");
  db.raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('i1','invitee@example.test','admin',unixepoch()+3600)").run();
  assert.equal(await mayReceiveSignInCode(db, env, "invitee@example.test"), true, "an open invitation");
  db.raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at,revoked_at) VALUES ('i2','revoked@example.test','admin',unixepoch()+3600,unixepoch())").run();
  db.raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('i3','expired@example.test','admin',unixepoch()-1)").run();
  assert.equal(await mayReceiveSignInCode(db, env, "revoked@example.test"), false);
  assert.equal(await mayReceiveSignInCode(db, env, "expired@example.test"), false);
  db.raw.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary','cf','founder@example.test','pending')").run();
  assert.equal(await mayReceiveSignInCode(db, env, "founder@example.test"), true, "the installer's first administrator");
  db.raw.prepare("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','admin')").run();
  assert.equal(await mayReceiveSignInCode(db, env, "stranger@example.test"), true, "self-service mode");
});

test("an email code creates accounts as method email-otp and claims invitations under that name", async () => {
  assert.equal(creationMethod({ path: "/sign-in/email-otp" }), "email-otp");
  const db = database();
  db.raw.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u1\',\'\',\'squat@example.test\',0,0,0)').run();
  db.raw.prepare("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES ('squat@example.test','u1','password')").run();
  db.raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('i1','squat@example.test','admin',unixepoch()+3600)").run();
  const decision = await admitOnVerification(db, {}, { userId: "u1", email: "squat@example.test", method: "email-otp" });
  assert.deepEqual(decision, { pending: true, admitted: true, via: "invitation", invitationId: "i1" });
  assert.equal(db.raw.prepare("SELECT used_method FROM nathan_invitations WHERE id='i1'").get().used_method, "email-otp");
});

test("the email is short and carries the code and the requesting host, not a link", () => {
  const mail = signInCodeMail({ code: "042917", host: "id.gmac.io", appName: "gmacko" });
  assert.equal(mail.subject, "Your gmacko sign-in code");
  assert.ok(!mail.subject.includes("042917"), "the code stays out of the subject");
  assert.match(mail.text, /\b042917\b/);
  assert.match(mail.text, /id\.gmac\.io/);
  assert.match(mail.text, /10 minutes/);
  assert.ok(!/https?:\/\//.test(mail.text), "no link to click");
  assert.ok(mail.text.length < 400);
  assert.equal(signInCodeMail({ code: "123456", host: "login.example.test" }).subject, "Your Nathan sign-in code");
  assert.throws(() => signInCodeMail({ code: "<b>", host: "x.test" }));
  assert.throws(() => signInCodeMail({ code: "123456", host: "evil.test/<x>" }));
});

test("an email-code session carries no assurance evidence", () => {
  // Only a verified passkey writes nathan_admin_assurance; even a row naming another method yields nothing.
  assert.deepEqual(evidenceClaims({ session_id: "s1", user_id: "u1", method: "email-otp", verified_at: 1700000000 }, { userId: "u1", sessionId: "s1" }), {});
  assert.deepEqual(evidenceClaims(null, { userId: "u1", sessionId: "s1" }), {});
});

test("administrator accounts never receive or use email codes", async () => {
  const db = database();
  const env = { NATHAN_BOOTSTRAP_REQUIRED: "true" };
  const user = (id, email, role = null) => db.raw.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,\'\',?,1,0,0,?)').run(id, email, role);
  user("u-role", "role@example.test", "admin");
  user("u-grant", "grant@example.test");
  user("u-root", "root@example.test");
  user("u-plain", "plain@example.test", "user");
  db.raw.prepare("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES ('u-grant','grant@example.test','root')").run();
  db.raw.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf','root@example.test','u-root','complete')").run();
  for (const email of ["role@example.test", "GRANT@example.test", "root@example.test"]) {
    assert.equal(await isAdministratorAccount(db, email), true, email);
    assert.equal(await mayReceiveSignInCode(db, env, email), false, email);
  }
  assert.equal(await isAdministratorAccount(db, "plain@example.test"), false);
  assert.equal(await mayReceiveSignInCode(db, env, "plain@example.test"), true);
  assert.equal(await isAdministratorAccount(db, "nobody@example.test"), false);
});
