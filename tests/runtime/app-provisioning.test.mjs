import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { createLocalJWKSet, jwtVerify } from "jose";
import { authWorker, bundle, COMPAT, enrollAdmin, migrate, randomKey, start, studioPost } from "./helpers.mjs";
import { supersedeUnprovenAccount } from "../../src/auth/admission-policy.mjs";

const app = "classcheck";
const makeCaller = (name, applicationId) => ({
  name, ...COMPAT, modules: true,
  script: `export default { async fetch(request, env) {
    const data = await request.json(), path = new URL(request.url).pathname;
    if (path === "/access") return Response.json(await env.VERIFY.resolveAccess(data));
    if (path === "/sync") return Response.json(await env.PROVISION.syncGrants(data));
    if (path === "/erase") return Response.json(await env.PROVISION.erase(data));
    return Response.json(await env.PROVISION.provision(data));
  } };`,
  serviceBindings: {
    PROVISION: { name: "auth", entrypoint: "NathanAppProvisioner", props: { applicationId } },
    VERIFY: { name: "auth", entrypoint: "NathanVerifier", props: { applicationId } }
  }
});
let mf, db, sentLogout;
const sql = (statement, ...args) => db.prepare(statement).bind(...args).run();
const first = (statement, ...args) => db.prepare(statement).bind(...args).first();
async function call(path, input, binding = "classcheck-web") {
  const worker = await mf.getWorker(binding);
  const response = await worker.fetch("https://caller.test" + path, { method: "POST", body: JSON.stringify(input) });
  assert.equal(response.status, 200);
  return response.json();
}
const provision = (input, binding) => call("/provision", input, binding);
const sync = (input, binding) => call("/sync", input, binding);
const erase = (input, binding) => call("/erase", input, binding);
before(async () => {
  mf = await start({ workers: [
    makeCaller("classcheck-web", app), makeCaller("other-web", "school"),
    {
      name: "auth", ...COMPAT, modules: true, scriptPath: bundle("auth"), d1Databases: { DB: "app-provision" },
      outboundService: async request => {
        assert.equal(request.url, "https://rp.example.test/logout");
        sentLogout = new URLSearchParams(await request.text()).get("logout_token");
        return new Response(null, { status: 204 });
      },
      durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
      bindings: { NATHAN_ADMIN_EMAILS: "operator@example.test", NATHAN_APP_ORIGIN: "https://classcheck.example.test",
        NATHAN_ISSUER: "https://id.example.test", NATHAN_APP_ID: app, NATHAN_INSTALL_ACTIVE: "true",
        NATHAN_ACCESS_TEAM_DOMAIN: "operators.cloudflareaccess.com", NATHAN_ACCESS_AUD: "a".repeat(64),
        NATHAN_CONFIG_KEY: randomKey(), NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_STEPUP_REQUIRED: "true",
        BETTER_AUTH_SECRET: randomKey() + randomKey() }
    }
  ] });
  db = await mf.getD1Database("DB", "auth");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(db, "migrations/" + file);
  await sql("INSERT INTO nathan_applications(id,hostname,enabled) VALUES (?,'classcheck.example.test',1)", app);
  for (const role of ["member", "guardian", "driver", "staff", "platform_admin", "auditor"]) {
    await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES (?,?)", app, role);
  }
  await sql("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES (?,'profile:read')", app);
  await sql("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES (?,'member','profile:read')", app);
});

test("role revisions reconcile only this source's app grants, and suspending overrides independent grants without deleting them", async () => {
  const identity = { externalId: "cc-active-driver", email: "active-driver@example.test" };
  const { sub } = await provision(identity);
  assert.ok(sub);
  const input = { externalId: identity.externalId, sub, roles: ["member", "driver"], revision: 1 };
  assert.deepEqual(await sync(input), { sub, revision: 1, applied: true });
  assert.deepEqual(await sync({ ...input, roles: ["driver", "member"] }), { sub, revision: 1, applied: false });
  assert.deepEqual(await sync({ ...input, roles: ["member", "staff"] }), { error: "identity_conflict" });
  assert.deepEqual(await sync({ ...input, revision: 2, roles: ["member", "admin"] }), { error: "invalid_input" });
  assert.deepEqual(await sync({ ...input, revision: 2, roles: ["member", "auditor"] }), { error: "invalid_input" });
  assert.deepEqual(await sync({ ...input, sub: "different" }), { error: "identity_conflict" });
  assert.deepEqual(await sync(input, "other-web"), { error: "not_configured" });

  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('unrelated',?,'auditor','user',?,'studio:owner')", app,sub);
  const suspended = { ...input, revision: 3, roles: [] };
  const [older, newer] = await Promise.all([sync({ ...input, revision: 2, roles: ["staff", "member"] }), sync(suspended)]);
  assert.deepEqual(newer, { sub, revision: 3, applied: true });
  assert.ok(older.applied === true || older.error === "stale_revision");
  assert.deepEqual(await sync(input), { error: "stale_revision" });
  assert.deepEqual(await sync(suspended), { sub, revision: 3, applied: false });
  assert.deepEqual(await provision(identity), { error: "identity_conflict" });
  assert.equal((await call("/access", { subject: sub })).allowed, false);
  assert.deepEqual((await db.prepare("SELECT role_key FROM nathan_rbac_grants WHERE app_id=? AND principal_id=?").bind(app,sub).all()).results, [{ role_key: "auditor" }]);
  assert.deepEqual(await sync({ ...input, revision: 4, roles: ["member", "guardian"] }), { sub, revision: 4, applied: true });
  assert.deepEqual((await call("/access", { subject: sub })).roles, ["auditor", "guardian", "member"]);
  await sql('UPDATE "user" SET banned=1 WHERE id=?', sub);
  assert.deepEqual(await sync({ ...input, revision: 5, roles: ["member", "platform_admin"] }), { error: "identity_conflict" });
  assert.equal((await first('SELECT role FROM "user" WHERE id=?', sub)).role, "user");
  assert.ok((await first("SELECT count(*) AS n FROM nathan_rbac_changes WHERE kind='grant.revoked' AND principal_id=?", sub)).n > 0);
});
after(() => mf?.dispose());

test("erasure withdraws the verified identity, sessions and delegated access, emits customer-issuer logout once, and cannot be replayed for another account", async () => {
  const identity = { externalId: "cc-erased", email: "erase@example.test" };
  const { sub } = await provision(identity);
  const deletion = { externalId: identity.externalId, sub, revision: 2 };
  assert.deepEqual(await sync({ ...deletion, roles: ["member", "staff"] }), { sub, revision: 2, applied: true });
  assert.deepEqual(await erase(deletion), { error: "identity_conflict" });
  assert.deepEqual(await erase({ ...deletion, revision: 1 }), { error: "stale_revision" });
  deletion.revision++;
  await sql("INSERT INTO oauthClient(id,clientId,redirectUris,backchannelLogoutUri) VALUES ('erase-rp','erase-rp','[]','https://rp.example.test/logout')");
  await sql("INSERT INTO session(id,token,expiresAt,createdAt,updatedAt,userId) VALUES ('erase-session','erase-token',9999999999,0,0,?)", sub);
  for (const table of ["oauthRefreshToken","oauthAccessToken"]) {
    await sql("INSERT INTO " + table + "(id,token,clientId,sessionId,userId,expiresAt,createdAt,scopes) " +
      "VALUES ('erase-oauth','erase-oauth','erase-rp','erase-session',?,9999999999,0,'[]')", sub);
  }
  await sql("INSERT INTO nathan_email_sign_ins(id,email,generation,subject_id,expires_at) VALUES ('erase-flow',?,'erase-generation',?,unixepoch()+300)", identity.email,sub);
  await sql("CREATE TRIGGER refuse_qa_erase BEFORE DELETE ON user WHEN OLD.id='" + sub + "' BEGIN SELECT RAISE(ABORT,'test rollback'); END");
  await assert.rejects(erase(deletion), /temporarily unavailable/);
  assert.deepEqual(await first("SELECT grant_revision FROM nathan_app_provisions WHERE user_id=?", sub), { grant_revision: 2 });
  assert.equal((await first("SELECT COUNT(*) AS n FROM session WHERE userId=?", sub)).n, 1);
  await sql("DROP TRIGGER refuse_qa_erase");
  assert.deepEqual(await erase({ ...deletion, sub: "somebody-else" }), { error: "identity_conflict" });
  const answers = await Promise.all([erase(deletion),erase(deletion)]);
  assert.deepEqual(answers.map(a => a.applied).sort(), [false,true]);
  assert.ok(answers.every(a => a.sub === sub && a.revision === 3));
  for (const table of ["session","oauthRefreshToken","oauthAccessToken"]) {
    assert.equal((await first("SELECT COUNT(*) AS n FROM " + table + " WHERE userId=?", sub)).n, 0);
  }
  assert.equal(await first("SELECT id FROM user WHERE id=?", sub), null);
  assert.equal(await first("SELECT id FROM nathan_email_sign_ins WHERE email=?", identity.email), null);
  assert.equal((await first("SELECT COUNT(*) AS n FROM nathan_app_provisions WHERE user_id IS NULL AND email IS NULL AND grant_revision=3")).n, 1);
  assert.deepEqual(await provision(identity), { error: "identity_conflict" });
  assert.deepEqual(await sync({ ...deletion, roles: ["member"], revision: 4 }), { error: "identity_conflict" });
  assert.deepEqual(await erase({ ...deletion, revision: 4 }), { error: "identity_conflict" });
  assert.deepEqual(await erase({ ...deletion, revision: 2 }), { error: "stale_revision" });
  assert.equal((await first("SELECT COUNT(*) AS n FROM nathan_backchannel_deliveries WHERE user_id=?", sub)).n, 1);
  await (await mf.getWorker("auth")).scheduled({ cron: "0 5 * * *" });
  const key = await first("SELECT id,publicKey FROM jwks ORDER BY createdAt DESC LIMIT 1");
  const jwks = createLocalJWKSet({ keys: [{ ...JSON.parse(key.publicKey), kid: key.id }] });
  const { payload } = await jwtVerify(sentLogout, jwks, { issuer: "https://classcheck.example.test/api/auth", audience: "erase-rp" });
  assert.equal(payload.sub, sub);
  assert.equal((await first("SELECT state FROM nathan_backchannel_deliveries WHERE user_id=?", sub)).state, "delivered");
});

test("a later Nathan operator or directory identity cannot be erased through an app binding", async () => {
  const identity = { externalId: "cc-operator", email: "future-operator@example.test" };
  const { sub } = await provision(identity);
  await sql('UPDATE "user" SET role=? WHERE id=?', "admin",sub);
  assert.deepEqual(await erase({ externalId: identity.externalId, sub, revision: 1 }), { error: "identity_conflict" });
  assert.equal((await first('SELECT role FROM "user" WHERE id=?', sub)).role, "admin");
  await sql('UPDATE "user" SET role=? WHERE id=?', "user",sub);
  await sql("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES ('app-directory','example.test','owner')");
  await sql("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,link_method) " +
    "VALUES ('app-directory','staff-1','external-1',?,1,?,'linked','email')", identity.email,sub);
  assert.deepEqual(await erase({ externalId: identity.externalId, sub, revision: 1 }), { error: "identity_conflict" });
});

test("concurrent first provisioning and retries return one new unverified subject for an existing local identity", async () => {
  const input = { externalId: "cc-guardian-14", email: " GUARDIAN@example.test " };
  const [a,b] = await Promise.all([provision(input), provision(input)]);
  assert.equal(typeof a.sub, "string");
  assert.deepEqual(b, a);
  assert.deepEqual(await provision({ ...input, email: "guardian@example.test" }), a);
  assert.deepEqual(await first('SELECT role, emailVerified FROM "user" WHERE id=? AND email=?', a.sub, "guardian@example.test"),
    { role: "user", emailVerified: 0 });
  assert.equal((await first("SELECT COUNT(*) AS n FROM nathan_security_audit WHERE action='app_user_provision' AND target=? AND outcome='created'", a.sub)).n, 1);
  assert.equal((await first('SELECT COUNT(*) AS n FROM session WHERE userId=?', a.sub)).n, 0);
  assert.deepEqual(await provision({ ...input, email: "changed@example.test" }), { error: "identity_conflict" });
  assert.deepEqual(await provision({ ...input, externalId: "cc-new-owner" }), { error: "identity_conflict" });
});

test("existing users, operator identities, wrong binding and disabled applications cannot be provisioned", async () => {
  const input = { externalId: "cc-conflict", email: "established@example.test" };
  await sql('INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES (?,?,?,1,datetime(\'now\'),datetime(\'now\'))', "established", "Existing", input.email);
  assert.deepEqual(await provision(input), { error: "identity_conflict" });
  assert.deepEqual(await provision({ ...input, email: "operator@example.test" }), { error: "identity_conflict" });
  await sql("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary','owner','bootstrap@example.test','pending')");
  assert.deepEqual(await provision({ ...input, email: "bootstrap@example.test" }), { error: "identity_conflict" });
  assert.deepEqual(await provision({ externalId: "cross", email: "other@example.test" }, "other-web"), { error: "not_configured" });
  assert.deepEqual(await provision({ externalId: "cc-1", email: "new@example.test", role: "admin" }), { error: "invalid_input" });
  await sql("UPDATE nathan_applications SET enabled=0 WHERE id=?", app);
  assert.deepEqual(await provision({ ...input, email: "offline@example.test" }), { error: "not_configured" });
  await sql("UPDATE nathan_applications SET enabled=1 WHERE id=?", app);
  assert.equal((await first('SELECT count(*) AS n FROM "user" WHERE email IN (?,?,?,?)',
    "operator@example.test", "bootstrap@example.test", "other@example.test", "offline@example.test")).n, 0);
});

test("ban, revocation and deletion survive a stale provisioning retry", async () => {
  const input = { externalId: "cc-retired-26", email: "retired@example.test" };
  const { sub } = await provision(input);
  assert.ok(sub);
  await sql('UPDATE "user" SET banned=1 WHERE id=?', sub);
  assert.deepEqual(await provision(input), { error: "identity_conflict" });
  await sql('UPDATE "user" SET banned=0 WHERE id=?', sub);
  await sql("DELETE FROM nathan_rbac_grants WHERE app_id=? AND principal_id=?", app, sub);
  await provision(input);
  assert.equal((await first("SELECT COUNT(*) AS n FROM nathan_rbac_grants WHERE principal_id=?", sub)).n, 0);
  await sql('DELETE FROM "user" WHERE id=?', sub);
  assert.deepEqual(await provision(input), { error: "identity_conflict" });
  assert.equal((await first('SELECT count(*) AS n FROM "user" WHERE email=?', input.email)).n, 0);
});

test("a source can suspend its banned member and a later unban keeps the newer withdrawal", async () => {
  const identity = { externalId: "ban-suspension", email: "suspend-banned@example.test" };
  const { sub } = await provision(identity);
  const grant = { externalId: identity.externalId, sub, revision: 1, roles: ["member","guardian"] };
  assert.deepEqual(await sync(grant), { sub, revision: 1, applied: true });
  await sql("UPDATE user SET banned=1 WHERE id=?", sub);
  const withdrawal = { ...grant, roles: [], revision: 3 };
  assert.deepEqual(await sync({ ...withdrawal, sub: "other" }), { error: "identity_conflict" });
  assert.deepEqual(await sync({ ...withdrawal, roles: ["member"] }), { error: "identity_conflict" });
  await sql("UPDATE user SET role='admin' WHERE id=?", sub);
  assert.deepEqual(await sync(withdrawal), { error: "identity_conflict" });
  await sql("UPDATE user SET role='user' WHERE id=?", sub);
  assert.deepEqual(await sync(withdrawal), { sub, revision: 3, applied: true });
  assert.deepEqual(await sync(withdrawal), { sub, revision: 3, applied: false });
  assert.deepEqual(await sync(grant), { error: "stale_revision" });
  await sql("UPDATE user SET banned=0 WHERE id=?", sub);
  assert.deepEqual(await sync(grant), { error: "stale_revision" });
  assert.equal((await call("/access", { subject: sub })).allowed, false);
  assert.equal((await first("SELECT COUNT(*) AS n FROM nathan_rbac_grants WHERE principal_id=?", sub)).n, 0);

  assert.deepEqual(await sync({ ...grant, revision: 4 }), { sub, revision: 4, applied: true });
  await sql("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES ('suspension-directory','school.test','owner')");
  await sql("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state) " +
    "VALUES ('suspension-directory','app-member','cc-staff',?,0,?,'deprovisioned')", identity.email, sub);
  await sql("UPDATE user SET banned=1 WHERE id=?", sub);
  assert.deepEqual(await sync({ ...withdrawal, revision: 5 }), { sub, revision: 5, applied: true });
  assert.deepEqual(await sync(grant), { error: "stale_revision" });
  assert.deepEqual(await sync({ ...grant, revision: 6 }), { error: "identity_conflict" });
  assert.equal((await first("SELECT link_state FROM nathan_scim_users WHERE user_id=?", sub)).link_state, "deprovisioned");
});

test("an erasure tombstone classifies an older grant only for the exact app, source ID and old subject", async () => {
  const identity = { externalId: "terminal-revision", email: "terminal-revision@example.test" };
  const { sub } = await provision(identity);
  const input = { externalId: identity.externalId, sub, revision: 7 };
  const oldDriverGrant = { ...input, roles: ["member", "driver"], revision: 6 };
  assert.deepEqual(await sync(oldDriverGrant), { sub, revision: 6, applied: true });
  assert.deepEqual(await erase(input), { sub, revision: 7, applied: true });
  await sql("DELETE FROM nathan_rbac_roles WHERE app_id=? AND key='driver'", app);
  try {
    assert.deepEqual(await sync(oldDriverGrant), { error: "stale_revision" });
    assert.deepEqual(await sync({ ...oldDriverGrant, revision: 8 }), { error: "identity_conflict" });
  } finally {
    await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES (?,'driver')", app);
  }
  for (const roles of [[], ["member"]]) {
    assert.deepEqual(await sync({ ...input, roles, revision: 6 }), { error: "stale_revision" });
    assert.deepEqual(await sync({ ...input, roles }), { error: "identity_conflict" });
    assert.deepEqual(await sync({ ...input, roles, revision: 8 }), { error: "identity_conflict" });
  }
  assert.deepEqual(await sync({ ...input, roles: [], revision: 6, sub: "other" }), { error: "identity_conflict" });
  assert.deepEqual(await sync({ ...input, roles: [], revision: 6, externalId: "other" }), { error: "identity_conflict" });
  assert.deepEqual(await sync({ ...input, roles: [], revision: 6 }, "other-web"), { error: "not_configured" });
});

test("app erasure preserves independent Better Auth organization ownership", async () => {
  const identity = { externalId: "organization-owner", email: "org-owner@example.test" };
  const { sub } = await provision(identity);
  const input = { externalId: identity.externalId, sub, revision: 2 };
  await sql("INSERT INTO organization(id,name,slug,createdAt) VALUES ('owned','Independent','independent',0)");
  await sql("INSERT INTO member(id,organizationId,userId,role,createdAt) VALUES ('owner','owned',?,'admin, owner',0)", sub);
  assert.deepEqual(await erase(input), { error: "identity_conflict" });
  assert.equal((await first("SELECT userId FROM member WHERE id='owner'")).userId, sub);
  assert.equal((await first("SELECT grant_revision FROM nathan_app_provisions WHERE user_id=?", sub)).grant_revision, 0);
  await sql("UPDATE member SET role='member' WHERE id='owner'");
  assert.deepEqual(await erase(input), { sub, revision: 2, applied: true });
});

test("a verified enterprise domain returns a reconciliation outcome before reserving a mailbox", async () => {
  const { sub } = await provision({ externalId: "sso-provider-admin", email: "sso-admin@example.test" });
  await sql("INSERT INTO ssoProvider(id,issuer,userId,providerId,domain,domainVerified) VALUES ('schools','https://idp.test',?,'schools','other.test, District.Test',1)", sub);
  for (const email of ["staff@district.test", "staff@school.district.test"]) {
    assert.deepEqual(await provision({ externalId: email, email }), { error: "identity_conflict", reason: "verified_enterprise_domain" });
    assert.equal(await first("SELECT id FROM user WHERE email=?", email), null);
    assert.equal(await first("SELECT user_id FROM nathan_app_provisions WHERE email=?", email), null);
  }
  assert.ok((await provision({ externalId: "unrelated-domain", email: "staff@notdistrict.test" })).sub);
  await sql("UPDATE ssoProvider SET domainVerified=0 WHERE id='schools'");
  assert.ok((await provision({ externalId: "unverified-domain", email: "unverified@district.test" })).sub);
});

test("Studio and verified-provider invitation recovery preserve a source-owned unverified subject", async () => {
  const host = "studio-provision.example.test", secret = randomKey(), email = "reserved@example.test";
  const worker = await authWorker(host, { BETTER_AUTH_SECRET: secret });
  try {
    const local = await worker.getD1Database("DB"), admin = await enrollAdmin(local, secret);
    await local.prepare("INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('reserved','',?,0,0,0)").bind(email).run();
    await local.prepare("INSERT INTO nathan_app_provisions(app_id,external_id_hash,subject_hash,user_id,email) VALUES ('classcheck','local','subject','reserved',?)").bind(email).run();
    const visit = body => studioPost({ fetch: (...args) => worker.dispatchFetch(...args) }, "https://" + host, "/studio/api/admission", body, admin.cookie);
    const invite = await visit({ op: "invite", email });
    assert.equal(invite.status, 409);
    assert.match((await invite.json()).error, /application/i);
    const recovery = await visit({ op: "reissue", email, confirm: "CONFIRM REISSUE INVITATION " + email });
    assert.equal(recovery.status, 409);
    assert.match((await recovery.json()).error, /application/i);
    await local.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('later',?,'studio',unixepoch()+3600)").bind(email).run();
    await local.prepare("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES (?,'reserved','password')").bind(email).run();
    assert.equal(await supersedeUnprovenAccount(local, email, "github"), null);
    assert.equal(await local.prepare("SELECT user_id FROM nathan_app_provisions WHERE email=?").bind(email).first("user_id"), "reserved");
  } finally { await worker.dispose(); }
});

test("failed provisioning transactions produce a bounded failure audit outside the rollback", async () => {
  const identity = { externalId: "failed-audit", email: "failed-audit@example.test" };
  const { sub } = await provision(identity);
  const removal = { externalId: identity.externalId, sub, revision: 5 };
  const grant = { ...removal, roles: ["member","staff"] };
  const failed = { externalId: "rollback-create", email: "rollback-create@example.test" };
  const requests = [
    ["app_user_provision", () => provision(failed)],
    ["app_grants_sync", () => sync(grant)],
    ["app_user_erase", () => erase(removal)]
  ];
  for (const [action, request] of requests) {
    await sql("CREATE TRIGGER interrupt_privileged_op BEFORE INSERT ON nathan_security_audit " +
      "WHEN NEW.action='" + action + "' AND NEW.outcome IN ('created','applied','erased') BEGIN SELECT RAISE(ABORT,'interrupted'); END");
    try {
      await assert.rejects(request(), /temporarily unavailable/);
      await assert.rejects(request(), /temporarily unavailable/);
      assert.deepEqual(await first("SELECT COUNT(*) AS n,MIN(target) AS target FROM nathan_security_audit " +
        "WHERE actor='app-provision:classcheck' AND action=? AND outcome='failed' AND created_at>=unixepoch()-60", action), { n: 1, target: "unmatched" });
    } finally { await sql("DROP TRIGGER interrupt_privileged_op"); }
  }
  assert.equal(await first("SELECT id FROM user WHERE email=?", failed.email), null);
  assert.equal((await first("SELECT grant_revision FROM nathan_app_provisions WHERE user_id=?", sub)).grant_revision, 0);
});
