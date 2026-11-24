import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { d1, migratedDatabase } from "./fixtures/d1-sqlite.mjs";
import { emailTarget } from "../src/auth/email-sign-in-policy.ts";
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

test("email evidence is bound to a session and cannot assert admin assurance", () => {
  const row = { email_session_id: "session-1", userId: "member" };
  assert.deepEqual(evidenceClaims(row, { userId: "member", sessionId: "session-1" }), { nathan_amr: ["email"] });
  assert.deepEqual(evidenceClaims(row, { userId: "another", sessionId: "session-1" }), {});
  assert.deepEqual(evidenceClaims(row, { userId: "member", sessionId: "old-session" }), {});
  for (const script of ["pack-release", "verify-release"])
    assert.match(readFileSync("scripts/" + script + ".mjs", "utf8"), /0019_email_sign_in\.sql/);
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
