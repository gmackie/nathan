/** NATH-16: the account admission policy and migration 0017's invitation constraints (node:sqlite). */
import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import * as policy from "../src/auth/admission-policy.mjs";
const {
  admissionMode, decideAdmission, normalizeEmail, creationMethod, claimInvitationStatement, NOT_ADMITTED
} = policy;

const migrations = readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort();
/** A D1-shaped wrapper over node:sqlite (prepare/bind/first/run/all and batch). */
function d1(raw) {
  const statement = (sql, params = []) => ({
    bind: (...p) => statement(sql, p),
    first: async () => raw.prepare(sql).get(...params) ?? null,
    run: async () => ({ meta: { changes: raw.prepare(sql).run(...params).changes } }),
    all: async () => ({ results: raw.prepare(sql).all(...params) }),
    sql, params
  });
  return { prepare: sql => statement(sql), raw };
}
function database() {
  const raw = new DatabaseSync(":memory:");
  raw.exec("PRAGMA foreign_keys=ON");
  for (const file of migrations) raw.exec(readFileSync("migrations/" + file, "utf8"));
  return d1(raw);
}
const invite = (db, email, { id = crypto.randomUUID(), expires = 3600 } = {}) =>
  db.raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,'admin',unixepoch()+?)").run(id, email, expires) && id;
const ENV = { NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_EMAILS: "ops@example.test" };

test("0017 is the only 0017 migration and is packaged with the release", () => {
  assert.deepEqual(migrations.filter(f => f.startsWith("0017")), ["0017_admission_provider_health.sql"]);
  for (const script of ["scripts/pack-release.mjs", "scripts/verify-release.mjs"])
    assert.match(readFileSync(script, "utf8"), /0017_admission_provider_health\.sql/, script);
});

test("a missing or unknown admission setting is invitation-only", async () => {
  const db = database();
  assert.equal(await admissionMode(db), "invitation-only");
  assert.throws(() => db.raw.exec("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','open','x')"), /CHECK/);
  assert.throws(() => db.raw.exec("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('second','self-service','x')"), /CHECK/);
  db.raw.exec("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','x')");
  assert.equal(await admissionMode(db), "self-service");
});

test("invitations: one open invitation per address, lower-case, single use enforced by the schema", async () => {
  const db = database();
  invite(db, "ann@example.test", { id: "i1" });
  assert.throws(() => invite(db, "ann@example.test"), /UNIQUE/, "a second open invitation for the same address");
  assert.throws(() => invite(db, "Bob@Example.test"), /CHECK/, "addresses are stored normalized");
  db.raw.exec("UPDATE nathan_invitations SET uses=1 WHERE id='i1'");
  assert.throws(() => db.raw.exec("UPDATE nathan_invitations SET uses=2 WHERE id='i1'"), /CHECK/);
  invite(db, "ann@example.test", { id: "i2" });
  // The batch claim fails the CHECK for a used, revoked or expired invitation.
  const used = claimInvitationStatement("i1", "scim:acme", "u1");
  assert.throws(() => db.raw.prepare(used.sql).run(...used.params), /CHECK/);
  db.raw.exec("UPDATE nathan_invitations SET revoked_at=unixepoch() WHERE id='i2'");
  const revoked = claimInvitationStatement("i2", "scim:acme", "u1");
  assert.throws(() => db.raw.prepare(revoked.sql).run(...revoked.params), /CHECK/);
  invite(db, "cy@example.test", { id: "i3", expires: -1 });
  const expired = claimInvitationStatement("i3", "scim:acme", "u1");
  assert.throws(() => db.raw.prepare(expired.sql).run(...expired.params), /CHECK/);
  invite(db, "di@example.test", { id: "i4" });
  const open = claimInvitationStatement("i4", "scim:acme", "u4");
  db.raw.prepare(open.sql).run(...open.params);
  assert.deepEqual({ ...db.raw.prepare("SELECT uses, used_method, used_by_user FROM nathan_invitations WHERE id='i4'").get() },
    { uses: 1, used_method: "scim:acme", used_by_user: "u4" });
});

test("invitation-only: only an open invitation admits, and it admits once", async () => {
  const db = database();
  const refused = await decideAdmission(db, ENV, { email: "ann@example.test", emailVerified: true, method: "social:github" });
  assert.equal(refused.admitted, false);
  invite(db, "ann@example.test", { id: "i1" });
  const first = await decideAdmission(db, ENV, { email: " Ann@Example.TEST ", emailVerified: true, method: "social:github" });
  assert.deepEqual(first, { admitted: true, via: "invitation", invitationId: "i1" });
  assert.equal((await decideAdmission(db, ENV, { email: "ann@example.test", emailVerified: true, method: "social:google" })).admitted, false);
  invite(db, "old@example.test", { expires: -1 });
  assert.equal((await decideAdmission(db, ENV, { email: "old@example.test", emailVerified: true, method: "password" })).admitted, false);
  assert.equal((await decideAdmission(db, ENV, { email: "not an email", emailVerified: true, method: "password" })).admitted, false);
});

test("the installer-approved founder is admitted only with a proven address and only before the account exists", async () => {
  const db = database();
  db.raw.exec("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary','cf','founder@example.test','pending')");
  assert.equal((await decideAdmission(db, ENV, { email: "founder@example.test", emailVerified: false, method: "password" })).admitted, false);
  assert.deepEqual(await decideAdmission(db, ENV, { email: "FOUNDER@example.test", emailVerified: true, method: "social:github" }),
    { admitted: true, via: "bootstrap" });
  db.raw.exec('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'f\',\'f\',\'founder@example.test\',1,0,0)');
  db.raw.exec("UPDATE nathan_bootstrap_status SET admin_user_id='f' WHERE id='primary'");
  assert.equal((await decideAdmission(db, ENV, { email: "founder@example.test", emailVerified: true, method: "social:google" })).admitted, false,
    "a second account for the founder's address is an ordinary account");
  // NATHAN_ADMIN_EMAILS admits only on legacy manual installations (no installer record).
  assert.equal((await decideAdmission(db, ENV, { email: "ops@example.test", emailVerified: true, method: "password" })).admitted, false);
  const legacy = database();
  assert.equal((await decideAdmission(legacy, { NATHAN_ADMIN_EMAILS: "ops@example.test" }, { email: "ops@example.test", emailVerified: true, method: "x" })).via, "bootstrap");
  assert.equal((await decideAdmission(legacy, { NATHAN_ADMIN_EMAILS: "ops@example.test" }, { email: "ops@example.test", emailVerified: false, method: "x" })).admitted, false);
});

test("self-service admits any well-formed address without consuming invitations", async () => {
  const db = database();
  db.raw.exec("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','x')");
  invite(db, "ann@example.test", { id: "i1" });
  assert.deepEqual(await decideAdmission(db, ENV, { email: "ann@example.test", emailVerified: false, method: "password" }),
    { admitted: true, via: "self-service" });
  assert.equal(db.raw.prepare("SELECT uses FROM nathan_invitations WHERE id='i1'").get().uses, 0);
});

test("a database error refuses (fail closed)", async () => {
  const broken = { prepare: () => { throw Error("D1 unavailable"); } };
  await assert.rejects(decideAdmission(broken, ENV, { email: "ann@example.test", emailVerified: true, method: "password" }));
});

test("creation methods and normalized addresses", () => {
  assert.equal(creationMethod({ path: "/sign-up/email" }), "password");
  assert.equal(creationMethod({ path: "/callback/:id", params: { id: "github" } }), "social:github");
  assert.equal(creationMethod({ path: "/callback/:id", params: { id: "../../x" } }), "social:unknown");
  assert.equal(creationMethod({ path: "/sso/saml2/sp/acs/:providerId", params: { providerId: "acme-saml" } }), "saml:acme-saml");
  assert.equal(creationMethod(null), "other");
  assert.equal(normalizeEmail("  A.B@Example.COM "), "a.b@example.com");
  for (const bad of ["", "a@b", "a b@example.com", "x".repeat(250) + "@example.com", "<a>@example.com", 7]) assert.equal(normalizeEmail(bad), null, String(bad));
  assert.match(NOT_ADMITTED.message, /invitation/);
});

const users = db => db.raw.prepare('SELECT "id" AS id FROM "user"').all().map(r => r.id);
const userRow = (db, id, email, verified = 0) =>
  db.raw.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,0,0)').run(id, id, email, verified);
const uses = (db, id) => db.raw.prepare("SELECT uses FROM nathan_invitations WHERE id=?").get(id).uses;

test("an invitation is claimed only by a method that proved the address (every method except password)", async () => {
  const db = database();
  invite(db, "ivy@example.test", { id: "i1" });
  for (const method of ["social:github", "enterprise-sso:acme-oidc", "saml:acme", "other"]) {
    const refused = await decideAdmission(db, ENV, { email: "ivy@example.test", emailVerified: false, method });
    assert.equal(refused.admitted, false, method + ": an unproven address claims nothing");
  }
  assert.equal(uses(db, "i1"), 0, "the invitation stays open");
  const ok = await decideAdmission(db, ENV, { email: "ivy@example.test", emailVerified: true, method: "enterprise-sso:acme-oidc" });
  assert.deepEqual(ok, { admitted: true, via: "invitation", invitationId: "i1" });
});

test("password sign-up: admitted provisionally, the invitation stays open until the address is verified", async () => {
  const db = database();
  invite(db, "pat@example.test", { id: "i1" });
  const decision = await decideAdmission(db, ENV, { email: "pat@example.test", emailVerified: false, method: "password" });
  assert.deepEqual(decision, { admitted: true, via: "invitation_pending" });
  assert.equal(uses(db, "i1"), 0, "nothing is claimed at sign-up");
  await policy.recordPendingAdmission(db, "pat@example.test", "password");
  userRow(db, "u-pat", "pat@example.test");
  await policy.bindPendingAdmission(db, "pat@example.test", "u-pat");
  // Verification claims it, bound to the account.
  assert.deepEqual(await policy.admitOnVerification(db, ENV, { userId: "u-pat", email: "pat@example.test" }),
    { pending: true, admitted: true, via: "invitation", invitationId: "i1" });
  assert.deepEqual({ ...db.raw.prepare("SELECT uses, used_method, used_by_user FROM nathan_invitations WHERE id='i1'").get() },
    { uses: 1, used_method: "password", used_by_user: "u-pat" });
  assert.equal(db.raw.prepare("SELECT 1 FROM nathan_admission_pending").get(), undefined, "no longer pending");
  // An account that was never provisional is not affected by verification.
  userRow(db, "u-old", "old@example.test");
  assert.deepEqual(await policy.admitOnVerification(db, ENV, { userId: "u-old", email: "old@example.test" }), { pending: false });
  // Without an invitation (no sign-up admission at all) nothing is recorded.
  assert.equal((await decideAdmission(db, ENV, { email: "nobody@example.test", emailVerified: false, method: "password" })).admitted, false);
});

test("password sign-up: a provisional account whose invitation was revoked is refused at verification", async () => {
  const db = database();
  invite(db, "rex@example.test", { id: "i1" });
  await policy.recordPendingAdmission(db, "rex@example.test", "password");
  userRow(db, "u-rex", "rex@example.test");
  await policy.bindPendingAdmission(db, "rex@example.test", "u-rex");
  db.raw.exec("UPDATE nathan_invitations SET revoked_at=unixepoch() WHERE id='i1'");
  assert.deepEqual(await policy.admitOnVerification(db, ENV, { userId: "u-rex", email: "rex@example.test" }), { pending: true, admitted: false });
  // Self-service at verification time admits it.
  db.raw.exec("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','x')");
  assert.deepEqual(await policy.admitOnVerification(db, ENV, { userId: "u-rex", email: "rex@example.test" }),
    { pending: true, admitted: true, via: "self-service" });
});

test("a provisional (password, unverified, never signed in) account is superseded when the invitee proves the address", async () => {
  const db = database();
  invite(db, "sid@example.test", { id: "i1" });
  await policy.recordPendingAdmission(db, "sid@example.test", "password");
  userRow(db, "u-squat", "sid@example.test");
  await policy.bindPendingAdmission(db, "sid@example.test", "u-squat");
  assert.equal(await policy.supersedeUnprovenAccount(db, "SID@example.test"), "u-squat");
  assert.deepEqual(users(db), []);
  assert.equal(uses(db, "i1"), 0, "the invitation is still open for the real person");
  const audit = db.raw.prepare("SELECT actor, action, target, outcome FROM nathan_security_audit WHERE action='account_superseded'").all();
  assert.deepEqual(audit.map(a => ({ ...a })), [{ actor: "system:admission", action: "account_superseded", target: "u-squat", outcome: "succeeded" }]);
  // Never: a verified account, an account that is not provisional, one with a session, or without an open invitation.
  userRow(db, "u-ver", "ver@example.test", 1); invite(db, "ver@example.test");
  await policy.recordPendingAdmission(db, "ver@example.test", "password"); await policy.bindPendingAdmission(db, "ver@example.test", "u-ver");
  userRow(db, "u-plain", "plain@example.test"); invite(db, "plain@example.test");
  userRow(db, "u-sess", "sess@example.test"); invite(db, "sess@example.test");
  await policy.recordPendingAdmission(db, "sess@example.test", "password"); await policy.bindPendingAdmission(db, "sess@example.test", "u-sess");
  db.raw.exec('INSERT INTO "session"("id","expiresAt","token","createdAt","updatedAt","userId") VALUES (\'s1\',0,\'t1\',0,0,\'u-sess\')');
  userRow(db, "u-noinv", "noinv@example.test");
  await policy.recordPendingAdmission(db, "noinv@example.test", "password"); await policy.bindPendingAdmission(db, "noinv@example.test", "u-noinv");
  for (const email of ["ver@example.test", "plain@example.test", "sess@example.test", "noinv@example.test", "missing@example.test"])
    assert.equal(await policy.supersedeUnprovenAccount(db, email), null, email);
  assert.deepEqual(users(db).sort(), ["u-noinv", "u-plain", "u-sess", "u-ver"]);
});

test("0017 records that admission defaulted to invitation-only, and flags upgrades that already had users", () => {
  const fresh = new DatabaseSync(":memory:");
  for (const file of migrations) fresh.exec(readFileSync("migrations/" + file, "utf8"));
  const row = db => db.prepare("SELECT actor, action, target, outcome FROM nathan_security_audit WHERE action='admission_default_invitation_only'").all().map(r => ({ ...r }));
  assert.deepEqual(row(fresh), [{ actor: "system:migration-0017", action: "admission_default_invitation_only", target: "no-existing-users", outcome: "applied" }]);
  const upgraded = new DatabaseSync(":memory:");
  for (const file of migrations.filter(f => f < "0017")) upgraded.exec(readFileSync("migrations/" + file, "utf8"));
  upgraded.exec('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u1\',\'u\',\'u@example.test\',1,0,0)');
  for (const file of migrations.filter(f => f >= "0017")) upgraded.exec(readFileSync("migrations/" + file, "utf8"));
  assert.deepEqual(row(upgraded), [{ actor: "system:migration-0017", action: "admission_default_invitation_only", target: "existing-users", outcome: "applied" }]);
  // Re-running the migration records nothing new.
  upgraded.exec(readFileSync("migrations/0017_admission_provider_health.sql", "utf8"));
  assert.equal(row(upgraded).length, 1);
});

test("enterprise OIDC creates accounts only for addresses inside the connection's verified domain", async () => {
  const { enterpriseOidcUserCreateGuard } = await import("../src/auth/enterprise-oidc-policy.mjs");
  const db = database();
  userRow(db, "owner", "owner@example.test", 1);
  const provider = (id, domain, verified, saml = null) => db.raw.prepare('INSERT INTO "ssoProvider"("id","issuer","oidcConfig","samlConfig","userId","providerId","domain","domainVerified") VALUES (?,?,?,?,\'owner\',?,?,?)')
    .run("p-" + id, "https://idp." + domain, saml ? null : "{}", saml, id, domain, verified);
  provider("acme-oidc", "acme.example", 1);
  provider("beta-oidc", "beta.example", 0);
  provider("acme-saml", "acme.example", 1, "{}");
  const ctx = id => ({ path: "/sso/callback/:providerId", params: { providerId: id } });
  assert.deepEqual(await enterpriseOidcUserCreateGuard(db, { email: "ivy@acme.example" }, ctx("acme-oidc")), { data: { emailVerified: true } });
  assert.deepEqual(await enterpriseOidcUserCreateGuard(db, { email: "ivy@eu.acme.example" }, ctx("acme-oidc")), { data: { emailVerified: true } });
  for (const [email, id] of [["out@outside.example", "acme-oidc"], ["x@notacme.example", "acme-oidc"], ["bo@beta.example", "beta-oidc"],
    ["ivy@acme.example", "acme-saml"], ["ivy@acme.example", "missing"], ["ivy@acme.example", "../x"]])
    assert.equal(await enterpriseOidcUserCreateGuard(db, { email }, ctx(id)), false, email + " via " + id);
  assert.equal(await enterpriseOidcUserCreateGuard(db, { email: "ivy@acme.example" }, { path: "/sso/callback", params: {} }), false, "unknown SSO route");
  assert.equal(await enterpriseOidcUserCreateGuard(db, { email: "ivy@acme.example" }, { path: "/sso/saml2/sp/acs/:providerId" }), undefined, "SAML has its own guard");
  assert.equal(await enterpriseOidcUserCreateGuard(db, { email: "ivy@acme.example" }, { path: "/callback/:id" }), undefined, "not enterprise SSO");
});
