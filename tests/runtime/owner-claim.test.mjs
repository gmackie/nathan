import assert from "node:assert/strict";
import test from "node:test";
import { promoteBootstrapOwner } from "../../scripts/lib/admin-wizard.mjs";
import { migrate, start } from "./helpers.mjs";

test("D1 serializes concurrent ForgeGraph owner claims and rolls back failed grants", async () => {
  const mf = await start({ script: "export default {}", d1Databases: { DB: "owner-claim" } });
  try {
    const db = await mf.getD1Database("DB");
    await db.prepare('CREATE TABLE "user" (id TEXT PRIMARY KEY, email TEXT, emailVerified INTEGER, role TEXT, banned INTEGER)').run();
    for (const migration of ["0003_security_audit", "0006_control_plane", "0030_operator_owner_claim"])
      await migrate(db, "migrations/" + migration + ".sql");
    const seed = "forgegraph:nathan:staging", email = "owner@example.test";
    await db.prepare('INSERT INTO "user" VALUES (?, ?, 1, ?, 0)').bind("owner", email, "user").run();
    await db.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary',?,?,'pending')")
      .bind(seed, email).run();
    const api = { queryDatabase: (_id, sql, params) => db.prepare(sql).bind(...params).run() };
    const claim = () => promoteBootstrapOwner(api, "db", "account", email, "owner", seed);
    const state = () => db.prepare("SELECT state FROM nathan_bootstrap_status").first("state");
    const auditCount = () => db.prepare("SELECT COUNT(*) AS n FROM nathan_security_audit").first("n");

    await db.prepare("CREATE TRIGGER fail_grant BEFORE UPDATE OF role ON user BEGIN SELECT RAISE(ABORT,'forced rollback'); END").run();
    await assert.rejects(claim, /forced rollback/);
    assert.equal(await state(), "pending");
    assert.equal(await auditCount(), 0);
    await db.prepare("DROP TRIGGER fail_grant").run();

    await Promise.all([claim(), claim()]);
    assert.equal(await state(), "identity_verified");
    assert.equal(await db.prepare('SELECT role FROM "user" WHERE id=?').bind("owner").first("role"), "admin");
    assert.equal(await auditCount(), 1);
  } finally {
    await mf.dispose();
  }
});
