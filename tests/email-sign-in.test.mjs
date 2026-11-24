import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { consumeAddressLimit, reserveProofAttempt, releaseProofAttempt, auditRefusedProof, pruneEmailOtpLimits, FAILURE_BUDGET } from "../src/auth/email-otp-policy.mjs";
import { d1, migratedDatabase } from "./fixtures/d1-sqlite.mjs";
import { emailTarget, liveAdminSession, reserveEmailDelivery, publishEmailDelivery } from "../src/auth/email-sign-in-policy.ts";
import { allowRequests } from "../src/auth/request-limit.ts";
import { evidenceClaims } from "../src/shared/token-claims.mjs";

test("self-service signup and the bootstrap allowlist do not admit an unknown address to email sign-in", async () => {
  const raw = migratedDatabase(), db = d1(raw), email = "owner@example.test";
  raw.exec("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','admin')");
  assert.equal(await emailTarget(db, email), null);
  raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('i',?,'admin',unixepoch()+100)").run(email);
  assert.deepEqual(await emailTarget(db, email), { invitation_id: "i", subject_id: null });
  raw.prepare('INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES (\'u\',\'user\',?,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)').run(email);
  assert.equal(await emailTarget(db, email), null, "unproven signup");
  raw.prepare("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES (?,'u','password')").run(email);
  assert.deepEqual(await emailTarget(db, email), { invitation_id: "i", subject_id: "u" });
  raw.exec("UPDATE nathan_invitations SET revoked_at=unixepoch()");
  assert.equal(await emailTarget(db, email), null);
  raw.exec('UPDATE "user" SET emailVerified=1');
  assert.deepEqual(await emailTarget(db, email), { invitation_id: null, subject_id: "u" });
  raw.exec('UPDATE "user" SET banned=1');
  assert.equal(await emailTarget(db, email), null);
  raw.close();
});

test("address and IP budgets are atomic and independent", async () => {
  const raw = migratedDatabase(), env = { DB: d1(raw) };
  const flood = await Promise.all(Array.from({ length: 7 }, () => allowRequests(env, "email-send-address", "a@example.test", 3, 600)));
  assert.equal(flood.filter(Boolean).length, 3);
  assert.equal(await allowRequests(env, "email-send-address", "b@example.test", 3, 600), true);
  assert.equal(await allowRequests(env, "email-send-ip", "192.0.2.1", 1, 600), true);
  assert.equal(await allowRequests(env, "email-send-ip", "192.0.2.1", 1, 600), false);
  assert.ok(raw.prepare("SELECT id FROM nathan_mcp_limits").all().every(row => !row.id.includes("@") && !row.id.includes("192.0.2.1")));
  raw.close();
});

test("a verified enterprise SSO domain takes precedence over invitations and directory provisioning", async () => {
  const raw = migratedDatabase(), db = d1(raw);
  raw.prepare('INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES (\'owner\',\'Owner\',\'owner@example.test\',1,0,0)').run();
  raw.prepare('INSERT INTO "ssoProvider"(id,issuer,userId,providerId,domain,domainVerified) VALUES (\'s\',\'https://idp.example.test\',\'owner\',\'school\',\'school.test\',1)').run();
  for (const email of ["a@school.test", "b@district.school.test", "c@notschool.test"]) {
    raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?, 'owner',unixepoch()+300)").run(email, email);
  }
  assert.equal(await emailTarget(db, "a@school.test"), null);
  assert.equal(await emailTarget(db, "b@district.school.test"), null);
  assert.ok(await emailTarget(db, "c@notschool.test"));
  raw.close();
});

test("email evidence is bound to a session and cannot assert admin assurance", () => {
  const row = { email_session_id: "session-1", userId: "member" };
  assert.deepEqual(evidenceClaims(row, { userId: "member", sessionId: "session-1" }), { nathan_amr: ["email"] });
  assert.deepEqual(evidenceClaims(row, { userId: "another", sessionId: "session-1" }), {});
  assert.deepEqual(evidenceClaims(row, { userId: "member", sessionId: "old-session" }), {});
  for (const script of ["pack-release", "verify-release"])
    assert.match(readFileSync("scripts/" + script + ".mjs", "utf8"), /0019_email_otp\.sql","0020_hosted_email_sign_in\.sql","0021_email_delivery_order\.sql/);
});

test("the invitation and new user roll back together and an active directory subject can be admitted", async () => {
  const raw = migratedDatabase(), db = d1(raw), email = "directory@example.test";
  raw.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('i',?,'admin',unixepoch()+600)").run(email);
  raw.prepare("INSERT INTO nathan_email_sign_ins(id,generation,email,invitation_id,expires_at) VALUES ('flow','first',?,'i',unixepoch()+300)").run(email);
  raw.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON nathan_security_audit BEGIN SELECT RAISE(ABORT,'test write failure'); END");
  const create = () => raw.prepare('INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES (\'n-email-first\',\'\',?,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)').run(email);
  assert.throws(create, /test write failure/);
  assert.equal(raw.prepare("SELECT uses FROM nathan_invitations WHERE id='i'").get().uses, 0);
  assert.equal(raw.prepare('SELECT id FROM "user" WHERE email=?').get(email), undefined);
  raw.exec("DROP TRIGGER fail_audit");
  create();
  assert.equal(raw.prepare("SELECT used_by_user FROM nathan_invitations WHERE id='i'").get().used_by_user, "n-email-first");
  raw.exec('UPDATE "user" SET emailVerified=0');
  raw.exec("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES ('district','example.test','admin')");
  raw.prepare("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,link_method) " +
    "VALUES ('district','scim','staff',?,1,'n-email-first','linked','jit')").run(email);
  assert.deepEqual(await emailTarget(db, email), { invitation_id: null, subject_id: "n-email-first" });
  raw.exec("UPDATE nathan_scim_users SET active=0,link_state='deprovisioned'");
  assert.equal(await emailTarget(db, email), null);
  raw.close();
});

test("deployed configurations keep the flag off except staging", () => {
  const vars = file => JSON.parse(readFileSync(file, "utf8").replace(/^\s*\/\/.*$/gm, "")).vars;
  assert.equal(vars("wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "false");
  assert.equal(vars("deploy/production/wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "false");
  assert.equal(vars("deploy/staging/wrangler.auth.jsonc").ENABLE_EMAIL_OTP, "true");
});


test("address limits survive resends and roll over at each fixed window", async () => {
  const raw = migratedDatabase(), db = d1(raw);
  const now = 1_700_000_000_000, window = 600_000;
  for (const [kind, short, daily] of [["send", 3, 10], ["verify", 5, 15]]) {
    const address = kind + "@example.test";
    const burst = await Promise.all(Array.from({ length: short + 1 }, () => consumeAddressLimit(db, kind, address, now)));
    assert.equal(burst.filter(r => r.allowed).length, short);
    let attempts = burst.length;
    for (let i = 1; attempts <= daily; i++) {
      for (let j = 0; j < short && attempts <= daily; j++) {
        attempts++;
        assert.equal((await consumeAddressLimit(db, kind, address, now + window * i)).allowed, attempts <= daily);
      }
    }
    assert.equal((await consumeAddressLimit(db, kind, address, now + 86_400_000)).allowed, true);
  }
  assert.ok(raw.prepare("SELECT key FROM nathan_email_otp_limits").all().every(r => /^address:(send|verify)(-day)?:[a-f0-9]{64}$/.test(r.key)));
  raw.exec("UPDATE nathan_email_otp_limits SET window_start=0");
  await pruneEmailOtpLimits(db);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM nathan_email_otp_limits").get().n, 0);
  raw.close();
});

test("failed proofs share the hourly budget and write a bounded anonymous audit", async () => {
  const raw = migratedDatabase(), db = d1(raw), now = 1_700_000_000_000;
  for (let i = 1; i < FAILURE_BUDGET.max; i++) assert.ok(await reserveProofAttempt(db, now));
  const last = await Promise.all(Array.from({length: 4}, () => reserveProofAttempt(db, now)));
  assert.equal(last.filter(Boolean).length, 1);
  const nextWindow = await reserveProofAttempt(db, now + 3_600_000);
  await releaseProofAttempt(db, last.find(Boolean));
  assert.equal(raw.prepare("SELECT count FROM nathan_email_otp_limits WHERE key='instance:failures'").get().count, 1);
  await releaseProofAttempt(db, nextWindow);
  assert.equal(raw.prepare("SELECT count FROM nathan_email_otp_limits WHERE key='instance:failures'").get().count, 0);
  await Promise.all([auditRefusedProof(db), auditRefusedProof(db)]);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action='email_otp_sign_in' AND outcome='rejected'").get().n, 1);
  raw.close();
});

for (const prior of ["code-only", "hosted draft"]) test("email session evidence upgrades from " + prior, () => {
  const raw = new DatabaseSync(":memory:");
  const migration = name => readFileSync("migrations/" + name, "utf8");
  for (const name of readdirSync("migrations").filter(f => /^00(0[1-9]|1[0-8])_/.test(f)).sort()) raw.exec(migration(name));
  raw.exec(`INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('member','','member@example.test',1,0,0);
    INSERT INTO session(id,token,userId,expiresAt,createdAt,updatedAt) VALUES ('sess','stub','member',99,0,0);`);
  if (prior === "hosted draft") {
    raw.exec(`CREATE TABLE nathan_email_sign_ins (id TEXT PRIMARY KEY,email TEXT UNIQUE,generation TEXT UNIQUE,
      subject_id TEXT,invitation_id TEXT,oauth_query TEXT,expires_at INTEGER,attempts INTEGER DEFAULT 0,second_factor TEXT);
      CREATE INDEX nathan_email_sign_ins_expiry ON nathan_email_sign_ins(expires_at);
      CREATE TABLE nathan_email_sessions(session_id TEXT PRIMARY KEY REFERENCES session(id) ON DELETE CASCADE);
      INSERT INTO nathan_email_sessions VALUES ('sess');`);
  }
  raw.exec(migration("0019_email_otp.sql"));
  if (prior === "code-only") raw.exec("INSERT INTO nathan_email_otp_sessions(session_id,user_id) VALUES ('sess','member')");
  raw.exec(migration("0020_hosted_email_sign_in.sql"));
  raw.exec("INSERT INTO verification(id,identifier,value,expiresAt,createdAt,updatedAt) VALUES ('proof','hosted-email-generation','old-hash',unixepoch()+100,0,0)");
  raw.exec(migration("0021_email_delivery_order.sql"));
  assert.equal(raw.prepare("SELECT value FROM verification WHERE identifier='hosted-email-generation'").get()?.value, "old-hash");
  assert.deepEqual({ ...raw.prepare("SELECT user_id,hosted FROM nathan_email_otp_sessions WHERE session_id='sess'").get() },
    { user_id: "member", hosted: Number(prior === "hosted draft") });
  raw.close();
});

test("legacy authenticator enrollment and noncanonical imported addresses fail closed", async () => {
  const raw = migratedDatabase(), db = d1(raw);
  raw.exec(`INSERT INTO "user"(id,name,email,emailVerified,twoFactorEnabled,createdAt,updatedAt) VALUES ('member','','member@example.test',1,1,0,0);
    INSERT INTO twoFactor(id,userId,secret,backupCodes,verified) VALUES ('factor','member','fixture','fixture',NULL);`);
  assert.equal((await emailTarget(db, "member@example.test"))?.subject_id, "member");
  raw.exec('UPDATE "user" SET twoFactorEnabled=0');
  assert.equal(await emailTarget(db, "member@example.test"), null);
  raw.exec(`UPDATE "user" SET email='Member@Example.test';
    INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('i','member@example.test','owner',unixepoch()+300);`);
  assert.equal(await emailTarget(db, "member@example.test"), null);
  raw.close();
});

test("an administrator needs the original live non-email session on every profile", async () => {
  const raw = migratedDatabase(), db = d1(raw);
  raw.exec(`INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('admin','','admin@example.test',1,0,0);
    INSERT INTO session(id,token,userId,expiresAt,createdAt,updatedAt) VALUES ('s','fixture','admin',unixepoch()+300,0,0);`);
  assert.equal(await liveAdminSession(db, "admin", "s"), true);
  assert.equal(await liveAdminSession(db, "another", "s"), false);
  raw.exec("INSERT INTO nathan_email_otp_sessions(session_id,user_id) VALUES ('s','admin')");
  assert.equal(await liveAdminSession(db, "admin", "s"), false);
  raw.exec("DELETE FROM session WHERE id='s'");
  assert.equal(await liveAdminSession(db, "admin", "s"), false);
  assert.equal(await liveAdminSession(db, "admin"), false);
  raw.close();
});

test("an older accepted delivery cannot resurrect its challenge after a newer delivery or redemption", async () => {
  const raw = migratedDatabase(), db = d1(raw), email = "order@example.test";
  const flow = generation => ({id: generation, generation, email, subject_id:"member", invitation_id:null, oauth_query:null, second_factor:null});
  const older = await reserveEmailDelivery(db, flow("stale")), newer = await reserveEmailDelivery(db, flow("latest"));
  await publishEmailDelivery(db, flow("latest"), newer);
  await publishEmailDelivery(db, flow("stale"), older);
  // A Worker already waiting on the mail provider at deploy time still uses this upsert.
  const publishFromPreviousWorker = raw.prepare("INSERT INTO nathan_email_sign_ins(id,generation,email,expires_at) " +
    "VALUES ('prior','prior',?,?) ON CONFLICT(email) DO UPDATE SET generation=excluded.generation");
  publishFromPreviousWorker.run(email, older.expires_at);
  assert.equal(raw.prepare("SELECT generation FROM nathan_email_sign_ins WHERE email=?").get(email).generation, "latest");
  raw.exec("DELETE FROM nathan_email_sign_ins");
  await publishEmailDelivery(db, flow("stale"), older);
  publishFromPreviousWorker.run(email, older.expires_at);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM nathan_email_sign_ins").get().n, 0);
  raw.prepare("UPDATE nathan_email_delivery_order SET expires_at=unixepoch() WHERE email=?").run(email);
  publishFromPreviousWorker.run(email, newer.expires_at + 1);
  assert.equal(raw.prepare("SELECT generation FROM nathan_email_sign_ins WHERE email=?").get(email).generation, "prior");
  raw.close();
});
