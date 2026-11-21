/** NATH-16: the account admission policy and migration 0017's invitation constraints (node:sqlite). */
import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import {
  admissionMode, decideAdmission, normalizeEmail, creationMethod, claimInvitationStatement, NOT_ADMITTED
} from "../src/auth/admission-policy.mjs";

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
  assert.equal((await decideAdmission(db, ENV, { email: "ann@example.test", emailVerified: true, method: "password" })).admitted, false);
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
