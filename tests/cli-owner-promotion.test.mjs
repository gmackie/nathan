import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { initializeBootstrapOwner, promoteBootstrapOwner } from "../scripts/lib/admin-wizard.mjs";
import { CloudflareClient } from "../scripts/lib/cloudflare.mjs";

test("CLI owner promotion resumes an interrupted setup and preserves completed enrollment", async () => {
  const db = new DatabaseSync(":memory:");
  const email = "owner@example.test";
  const userId = "owner-1";
  db.exec(readFileSync(new URL("../migrations/0003_security_audit.sql", import.meta.url), "utf8"));
  db.exec('CREATE TABLE user (id TEXT PRIMARY KEY, email TEXT, emailVerified INTEGER, role TEXT, banned INTEGER)');
  db.exec(readFileSync(new URL("../migrations/0006_control_plane.sql", import.meta.url), "utf8"));
  db.exec(readFileSync(new URL("../migrations/0020_cli_owner_bootstrap.sql", import.meta.url), "utf8"));
  db.prepare("INSERT INTO user VALUES (?, ?, 1, 'admin', NULL)").run(userId, email);
  const api = new CloudflareClient("test", "test");
  let interrupt = false;
  api.request = async (path, {body}) => {
    assert.match(path, /\/query$/);
    assert.equal(typeof body.sql, "string");
    const results = db.prepare(body.sql).all(...body.params);
    if (interrupt && body.sql.includes("INSERT INTO nathan_cli_owner_claim")) {
      interrupt = false;
      throw Error("connection interrupted");
    }
    return [{ success: true, results }];
  };
  const id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  try {
    await initializeBootstrapOwner(api, id, "test", email);
    await initializeBootstrapOwner(api, id, "test", email);
    await assert.rejects(initializeBootstrapOwner(api, id, "test", "stranger@example.test"));
    await assert.rejects(initializeBootstrapOwner(api, id, "other", email));
    assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action='admin_bootstrap_init' AND outcome='succeeded'").get().n, 1);
    db.exec("UPDATE user SET role='user'");
    interrupt = true;
    await assert.rejects(promoteBootstrapOwner(api, id, "test", email, userId), /interrupted/);
    assert.equal(db.prepare("SELECT role FROM user").get().role, "admin");
    assert.equal(db.prepare("SELECT outcome FROM nathan_security_audit WHERE action='admin_bootstrap'").get().outcome, "succeeded");
    await promoteBootstrapOwner(api, id, "test", email, userId);
    assert.deepEqual({...db.prepare("SELECT admin_user_id,state FROM nathan_bootstrap_status").get()}, {admin_user_id:userId,state:"identity_verified"});
    db.exec("UPDATE nathan_bootstrap_status SET state='complete', updated_at=123");
    await promoteBootstrapOwner(api, id, "test", email, userId);
    assert.equal(db.prepare("SELECT updated_at FROM nathan_bootstrap_status WHERE state='complete'").get().updated_at,123);
    assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action='admin_bootstrap'").get().n,1);
    db.exec("UPDATE user SET role='user'");
    await assert.rejects(promoteBootstrapOwner(api, id, "another-account", email, userId));
    assert.equal(db.prepare("SELECT role FROM user").get().role,"user");
    await promoteBootstrapOwner(api, id, "test", email, userId);
    assert.equal(db.prepare("SELECT role FROM user").get().role,"admin");
    assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action='admin_bootstrap' AND outcome='succeeded'").get().n,2);
    db.exec("UPDATE user SET role='user', banned=1");
    await assert.rejects(promoteBootstrapOwner(api, id, "test", email, userId));
    db.exec("UPDATE user SET banned=0, emailVerified=0");
    await assert.rejects(promoteBootstrapOwner(api, id, "test", email, userId));
    db.exec("UPDATE user SET emailVerified=1");
    db.prepare("INSERT INTO user VALUES ('duplicate',?,1,'user',0)").run(email.toUpperCase());
    await assert.rejects(promoteBootstrapOwner(api, id, "test", email, userId));
    assert.equal(db.prepare("SELECT count(*) AS n FROM user WHERE role='admin'").get().n,0);
    assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action='admin_bootstrap'").get().n,2);
  } finally { db.close(); }
});
