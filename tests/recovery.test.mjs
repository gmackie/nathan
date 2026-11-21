import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { missingIdpSecrets, hostnameConflicts } from "../scripts/lib/cloudflare.mjs";
import { redirectWithCookies } from "../src/shared/security.mjs";

test("CLI installs only the identity Worker secrets that are missing", () => {
  assert.deepEqual(missingIdpSecrets([]), ["BETTER_AUTH_SECRET", "NATHAN_CONFIG_KEY"]);
  assert.deepEqual(missingIdpSecrets(["BETTER_AUTH_SECRET"]), ["NATHAN_CONFIG_KEY"]);
  assert.deepEqual(missingIdpSecrets(["NATHAN_CONFIG_KEY", "BETTER_AUTH_SECRET", "OTHER"]), []);
});

test("the installation's own custom-domain DNS record is not a conflict on re-run", () => {
  const records = [{ id: "r1", type: "AAAA", name: "auth.example.com" }];
  assert.deepEqual(hostnameConflicts(records, [{ hostname: "auth.example.com", service: "acme-auth" }], "auth.example.com", "acme-auth"), []);
  assert.deepEqual(hostnameConflicts(records, [{ hostname: "auth.example.com", service: "someone-else" }], "auth.example.com", "acme-auth"), records);
  assert.deepEqual(hostnameConflicts(records, [], "auth.example.com", "acme-auth"), records);
});

test("cookie redirects keep mutable headers and every Set-Cookie", () => {
  const response = redirectWithCookies("https://idp.example.com/authorize?x=1", 302, ["__Host-a=1; Path=/", "__Host-b=2; Path=/"]);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "https://idp.example.com/authorize?x=1");
  assert.deepEqual(response.headers.getSetCookie(), ["__Host-a=1; Path=/", "__Host-b=2; Path=/"]);
  response.headers.set("Cache-Control", "no-store");
  assert.throws(() => redirectWithCookies("/relative"), "relative locations are rejected");
});

test("installer job lease migration applies on top of existing job rows", () => {
  const db = new DatabaseSync(":memory:");
  for (const file of ["0002_jobs.sql", "0003_realm.sql", "0004_scim_settings.sql"])
    db.exec(readFileSync("migrations/installer/" + file, "utf8"));
  db.prepare("INSERT INTO nathan_install_jobs(id,owner_user_id,owner_email,account_id,zone_id,hostname,worker_name,admin_email,profile,release_id) VALUES ('j','u','e@x.io','a','z','h','w','e@x.io','business','r')").run();
  db.exec(readFileSync("migrations/installer/0005_job_lease.sql", "utf8"));
  assert.deepEqual({ ...db.prepare("SELECT lease_token, database_create_started FROM nathan_install_jobs").get() },
    { lease_token: null, database_create_started: 0 });
  assert.throws(() => db.prepare("UPDATE nathan_install_jobs SET database_create_started=2").run(), /CHECK/);
});
