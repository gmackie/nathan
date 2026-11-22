/**
 * NATH-13 Identity Studio RBAC writes and the Gatekeeper directory API in the built identity Worker.
 * Studio calls use a real Better Auth session for an enrolled, stepped-up administrator; the
 * directory uses a real client-credentials token minted by Nathan's own token endpoint.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, randomKey } from "./helpers.mjs";

const HOST = "login.example.test";
const ORIGIN = "https://" + HOST;
const ISSUER = ORIGIN + "/api/auth";
const SECRET = randomKey() + randomKey();
let mf, db;
after(() => mf?.dispose());

const sql = (statement, ...params) => db.prepare(statement).bind(...params).run();
const now = () => new Date().toISOString();
async function signedCookie(token) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token))).toString("base64");
  return "__Secure-nathan.session_token=" + encodeURIComponent(token + "." + signature);
}
async function user(id, email, role = "user") {
  await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,1,?,?,?)', id, id, email, now(), now(), role);
}
async function session(userId) {
  const id = "sess-" + crypto.randomUUID(), token = "tok" + randomKey();
  await sql('INSERT INTO "session"("id","expiresAt","token","createdAt","updatedAt","userId") VALUES (?,?,?,?,?,?)',
    id, new Date(Date.now() + 3600_000).toISOString(), token, now(), now(), userId);
  return { id, cookie: await signedCookie(token) };
}
let admin, member;
before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET });
  db = await mf.getD1Database("DB");
  await user("admin-1", "admin@example.test", "admin");
  await sql("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf','admin@example.test','admin-1','complete')");
  await sql('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (\'pk1\',\'x\',\'admin-1\',\'cred\',0,\'singleDevice\',0)');
  await sql('INSERT INTO "twoFactor"("id","secret","backupCodes","userId","verified") VALUES (\'tf1\',\'x\',\'x\',\'admin-1\',1)');
  admin = await session("admin-1");
  await sql("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES (?,?,'passkey')", admin.id, "admin-1");
  await user("u-alice", "alice@example.test");
  member = await session("u-alice");
});

const post = (path, body, { cookie = admin.cookie, origin = ORIGIN } = {}) => mf.dispatchFetch(ORIGIN + path, {
  method: "POST", body: JSON.stringify(body),
  headers: { Cookie: cookie, Origin: origin, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin" }
});
const get = (path, cookie = admin.cookie) => mf.dispatchFetch(ORIGIN + path, { headers: { Cookie: cookie } });
const rbac = body => post("/studio/api/rbac", body);
const count = async (statement, ...params) => (await db.prepare(statement).bind(...params).first()).n;

test("RBAC writes are refused to non-admins and cross-origin callers, and leave no trace", async () => {
  const body = { op: "group.upsert", id: "intruders", name: "Intruders" };
  assert.equal((await post("/studio/api/rbac", body, { cookie: member.cookie })).status, 403);
  assert.equal((await post("/studio/api/rbac", body, { cookie: "" })).status, 403);
  assert.equal((await post("/studio/api/rbac", body, { origin: "https://evil.example" })).status, 403);
  assert.equal((await get("/studio/api/rbac/groups", member.cookie)).status, 403);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_groups WHERE id='intruders'"), 0);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_rbac_changes"), 0);
});

test("an enrolled administrator manages permissions, roles, groups and grants; every write is audited and fed", async () => {
  const app = await post("/studio/api/apps", { id: "billing", hostname: "billing.example.test" });
  assert.equal(app.status, 200, await app.clone().text());
  const steps = [
    { op: "permission.upsert", app: "billing", key: "invoices:read", description: "Read invoices" },
    { op: "permission.upsert", app: "billing", key: "invoices:write", description: "Write invoices" },
    { op: "role.upsert", app: "billing", key: "editor", description: "Edit", permissions: ["invoices:read", "invoices:write"] },
    { op: "group.upsert", id: "finance", name: "Finance" },
    { op: "member.add", group: "finance", email: "alice@example.test" },
    { op: "grant.create", app: "billing", role: "editor", principalType: "group", group: "finance" }
  ];
  for (const step of steps) {
    const response = await rbac(step);
    assert.equal(response.status, 200, step.op + ": " + await response.clone().text());
  }
  const rejected = [
    [{ op: "role.upsert", app: "billing", key: "ghost", permissions: ["invoices:delete"] }, /Declare each permission/],
    [{ op: "access_mode", app: "billing", accessMode: "any_signed_in" }, /Explicit confirmation/],
    [{ op: "permission.upsert", app: "billing", key: "invoices:*" }, /Permission keys/],
    [{ op: "member.add", group: "finance", email: "nobody@example.test" }, /User not found/],
    [{ op: "grant.create", app: "missing", role: "editor", principalType: "user", email: "alice@example.test" }, /Unknown application/],
    [{ op: "drop.tables" }, /Unknown RBAC operation/]
  ];
  for (const [body, message] of rejected) {
    const response = await rbac(body);
    assert.equal(response.status, 409, JSON.stringify(body));
    assert.match((await response.json()).error, message);
  }
  // Rejected before commit, yet every attempt by the administrator is in the audit log.
  const refusals = (await db.prepare("SELECT action, target, actor FROM nathan_security_audit WHERE outcome='rejected' ORDER BY created_at, rowid").all()).results;
  assert.deepEqual(refusals.map(r => [r.action, r.target]), [
    ["rbac_role_upsert", "billing:ghost"], ["rbac_access_mode", "billing:any_signed_in"], ["rbac_permission_upsert", "billing:invoices:*"],
    ["rbac_member_add", "finance:nobody@example.test"], ["rbac_grant_create", "missing:editor"], ["rbac_unknown", "drop.tables"]
  ]);
  assert.ok(refusals.every(r => r.actor === "admin-1"));
  const overview = await (await get("/studio/api/rbac?app=billing")).json();
  assert.equal(overview.app.accessMode, "approved");
  assert.equal(overview.app.enabled, false);
  assert.deepEqual(overview.roles.map(r => [r.key, r.permissions]), [["editor", ["invoices:read", "invoices:write"]]]);
  assert.deepEqual(overview.grants.map(g => [g.role, g.principalType, g.principalId, g.label]), [["editor", "group", "finance", "Finance"]]);
  const members = await (await get("/studio/api/rbac/group?id=finance")).json();
  assert.deepEqual(members.members.map(m => m.email), ["alice@example.test"]);

  const audited = (await db.prepare("SELECT action, outcome, actor FROM nathan_security_audit WHERE action LIKE 'rbac_%' AND actor<>'migration:0011' ORDER BY created_at, rowid").all()).results;
  assert.deepEqual(audited.filter(a => a.outcome === "succeeded").map(a => a.action),
    ["rbac_permission_upsert", "rbac_permission_upsert", "rbac_role_upsert", "rbac_group_upsert", "rbac_member_add", "rbac_grant_create"]);
  assert.ok(audited.every(a => a.actor === "admin-1"));
  assert.equal(await count("SELECT count(*) AS n FROM nathan_rbac_changes"), 6);

  // Confirmed destructive operations work and are recorded.
  const grantId = overview.grants[0].id;
  assert.equal((await rbac({ op: "grant.revoke", id: grantId })).status, 200);
  assert.equal((await rbac({ op: "access_mode", app: "billing", accessMode: "any_signed_in", confirm: "CONFIRM ANY SIGNED IN billing" })).status, 200);
  assert.equal((await rbac({ op: "access_mode", app: "billing", accessMode: "approved" })).status, 200);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_rbac_changes"), 9);
  await rbac({ op: "grant.create", app: "billing", role: "editor", principalType: "group", group: "finance" });
});

test("permissions-as-code sync from Studio uses the shared plan and asks before pruning", async () => {
  const manifest = { permissions: { "invoices:read": "Read invoices", "reports:read": "Read reports" },
    roles: { viewer: { description: "Read-only", permissions: ["invoices:read", "reports:read"] } } };
  const dry = await (await rbac({ op: "sync", app: "billing", manifest, dryRun: true })).json();
  assert.deepEqual(dry.ops.map(o => o.op + ":" + o.key), ["permission.upsert:invoices:read", "permission.upsert:reports:read", "role.upsert:viewer"]);
  const applied = await (await rbac({ op: "sync", app: "billing", manifest })).json();
  assert.equal(applied.applied, 3);
  assert.deepEqual((await (await rbac({ op: "sync", app: "billing", manifest, dryRun: true })).json()).ops, []);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='rbac_manifest_sync' AND outcome='succeeded'"), 1);
  const unconfirmed = await rbac({ op: "sync", app: "billing", manifest: { permissions: {}, roles: {} }, prune: true });
  assert.equal(unconfirmed.status, 409);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_rbac_roles WHERE app_id='billing' AND key='viewer'"), 1);
});

let clientId, clientSecret;
async function directoryToken(id = clientId, secret = clientSecret, resource = ORIGIN + "/directory") {
  const response = await mf.dispatchFetch(ISSUER + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(id + ":" + secret) },
    body: new URLSearchParams({ grant_type: "client_credentials", scope: "nathan:directory.read", ...(resource ? { resource } : {}) }).toString()
  });
  return { status: response.status, body: await response.json() };
}
const directory = (path, token) => mf.dispatchFetch(ORIGIN + path, { headers: token ? { Authorization: "Bearer " + token } : {} });

test("an administrator registers a directory client; it gets a client-credentials token for the directory", async () => {
  const refused = await post("/studio/api/directory/clients", { name: "Gatekeeper PIP" });
  assert.equal(refused.status, 409, "needs explicit confirmation");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='directory_client_create' AND outcome='rejected' AND target='Gatekeeper PIP'"), 1);
  const created = await post("/studio/api/directory/clients", { name: "Gatekeeper PIP", confirm: "CONFIRM DIRECTORY CLIENT Gatekeeper PIP" });
  assert.equal(created.status, 200, await created.clone().text());
  const client = await created.json();
  clientId = client.client_id; clientSecret = client.client_secret;
  assert.ok(clientId && clientSecret);
  assert.deepEqual(client.client_credentials_scopes, ["nathan:directory.read"]);
  const token = await directoryToken();
  assert.equal(token.status, 200, JSON.stringify(token.body));
  const [header, payload] = token.body.access_token.split(".").slice(0, 2).map(p => JSON.parse(Buffer.from(p, "base64url")));
  assert.equal(header.typ, "at+jwt");
  assert.equal(payload.aud, ORIGIN + "/directory");
  assert.equal(payload.sub, clientId);
  assert.ok(payload.exp - payload.iat <= 300);
});

test("the directory returns the evaluator's roles keyed by issuer-qualified subject, plus a change feed", async () => {
  const { body } = await directoryToken();
  await sql("UPDATE nathan_applications SET enabled=1 WHERE id='billing'");
  const subject = encodeURIComponent(ISSUER + "#u-alice");
  const response = await directory("/directory/v1/principal?subject=" + subject, body.access_token);
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  const view = await response.json();
  assert.equal(view.subject, ISSUER + "#u-alice");
  assert.equal(view.active, true);
  assert.deepEqual(view.groups.map(g => g.id), ["finance"]);
  assert.deepEqual(view.applications.billing, {
    enabled: true, accessMode: "approved", allowed: true, reason: "granted", roles: ["editor"], permissions: ["invoices:read", "invoices:write"]
  });
  assert.ok(Date.parse(view.observedAt) <= Date.now());
  assert.equal(view.maxAgeSeconds, 30);

  const first = await (await directory("/directory/v1/changes?limit=5", body.access_token)).json();
  assert.equal(first.changes.length, 5);
  assert.equal(first.hasMore, true);
  const rest = await (await directory("/directory/v1/changes?cursor=" + first.cursor + "&limit=500", body.access_token)).json();
  assert.ok(rest.changes.length > 0);
  assert.ok(rest.changes.every(c => Number(c.seq) > Number(first.cursor)));
  const member = [...first.changes, ...rest.changes].find(c => c.kind === "member.added");
  assert.deepEqual(member.principal, { type: "user", id: "u-alice", subject: ISSUER + "#u-alice" });
  assert.equal((await directory("/directory/v1/principal?subject=" + encodeURIComponent(ISSUER + "#ghost"), body.access_token)).status, 404);
  assert.equal((await directory("/directory/v1/principal?subject=" + encodeURIComponent("https://other.example/api/auth#u-alice"), body.access_token)).status, 404);
  assert.equal((await directory("/directory/v1/changes?cursor=-1", body.access_token)).status, 400);
});

test("bans, unbans and deleted users' memberships reach the directory change feed (D1 triggers)", async () => {
  const { body } = await directoryToken();
  const head = (await (await directory("/directory/v1/changes?limit=500", body.access_token)).json()).cursor;
  await user("u-temp", "temp@example.test");
  await sql("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('finance','u-temp','test')");
  await sql('UPDATE "user" SET "banned"=1 WHERE "id"=\'u-temp\'');
  await sql('UPDATE "user" SET "banned"=0 WHERE "id"=\'u-temp\'');
  await sql('DELETE FROM "user" WHERE "id"=\'u-temp\'');
  const page = await (await directory("/directory/v1/changes?cursor=" + head + "&limit=500", body.access_token)).json();
  assert.deepEqual(page.changes.map(c => [c.kind, c.principal?.subject, c.detail]), [
    ["user.banned", ISSUER + "#u-temp", {}],
    ["user.unbanned", ISSUER + "#u-temp", {}],
    ["member.removed", ISSUER + "#u-temp", { group: "finance", cause: "user.deleted" }],
    ["user.deleted", ISSUER + "#u-temp", {}]
  ]);
});

test("the directory rejects missing, user-delegated, wrong-audience and disabled-client tokens", async () => {
  assert.equal((await directory("/directory/v1/principal?subject=x")).status, 401);
  assert.equal((await directory("/directory/v1/changes", "x".repeat(40))).status, 401);
  const opaque = await directoryToken(clientId, clientSecret, null);
  if (opaque.status === 200) assert.equal((await directory("/directory/v1/changes", opaque.body.access_token)).status, 401, "a token without the directory audience");
  const wrongSecret = await directoryToken(clientId, "wrong-secret");
  assert.notEqual(wrongSecret.status, 200);
  const { body } = await directoryToken();
  assert.equal((await directory("/directory/v1/changes", body.access_token)).status, 200);
  await sql('UPDATE "oauthClient" SET "disabled"=1 WHERE "clientId"=?', clientId);
  assert.equal((await directory("/directory/v1/changes", body.access_token)).status, 401, "disabling the client cuts access immediately");
  assert.equal((await mf.dispatchFetch(ORIGIN + "/directory/v1/changes", { method: "POST" })).status, 405);
});

test("Identity Studio renders the Roles and access section with a script that parses", async () => {
  const page = await get("/studio");
  assert.equal(page.status, 200, await page.clone().text());
  const html = await page.text();
  assert.match(html, /<h2>Roles and access<\/h2>/);
  assert.doesNotMatch(html, /id="app-roles"/, "the legacy required-roles field is gone");
  const script = html.match(/<script nonce="[^"]+">([\s\S]*)<\/script>/)[1];
  assert.doesNotThrow(() => new Function(script), "studio script must be valid JavaScript");
  assert.match(script, /\/studio\/api\/rbac/);
  assert.equal((await get("/studio", member.cookie)).status, 403);
});
