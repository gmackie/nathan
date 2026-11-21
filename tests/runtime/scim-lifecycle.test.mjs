/**
 * NATH-11 in workerd: inbound SCIM lifecycle through the built identity Worker, its per-connection
 * Durable Object, D1, and a real gateway. Nathan's back-channel logout POSTs are routed to the
 * gateway Worker, which verifies them against Nathan's own JWKS; the gateway resolves access over the
 * NathanVerifier binding with a 1 s cache, so blocking is observable within the cache window.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { bundle, migrate, randomKey, cookiesOf, start, COMPAT, enrollAdmin, insertSession, studioPost } from "./helpers.mjs";

const AUTH_HOST = "login.example.test";
const AUTH_ORIGIN = "https://" + AUTH_HOST;
const ISSUER = AUTH_ORIGIN + "/api/auth";
const ORIGIN = "https://billing.example.test";
const CLIENT = "billing-gateway";
const PRINCIPAL_KEY = randomKey();
const BETTER_AUTH_SECRET = randomKey() + randomKey();
const okta = JSON.parse(readFileSync("tests/fixtures/scim/okta.json", "utf8"));
const entra = JSON.parse(readFileSync("tests/fixtures/scim/entra.json", "utf8"));
const fill = (value, ids) => JSON.parse(Object.entries(ids).reduce((text, [k, v]) => text.replaceAll(k, v), JSON.stringify(value)));

const { privateKey, publicKey } = await generateKeyPair("ES256");
const mockJwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };
const issued = new Map();
/** The gateway's IdP: logins come from a mock token endpoint; JWKS also carries Nathan's real keys. */
async function idp(request) {
  const url = new URL(request.url);
  if (url.href === ISSUER + "/.well-known/openid-configuration")
    return Response.json({ issuer: ISSUER, authorization_endpoint: ISSUER + "/oauth2/authorize", token_endpoint: ISSUER + "/oauth2/token", jwks_uri: ISSUER + "/jwks" });
  if (url.href === ISSUER + "/jwks") {
    const nathan = await (await auth.fetch(ISSUER + "/jwks")).json();
    return Response.json({ keys: [mockJwk, ...nathan.keys] });
  }
  if (url.href === ISSUER + "/oauth2/token" && request.method === "POST") {
    const grant = issued.get(new URLSearchParams(await request.text()).get("code"));
    if (!grant) return Response.json({ error: "invalid_grant" }, { status: 400 });
    const idToken = await new SignJWT({ nonce: grant.nonce, email: grant.sub + "@acme.example", email_verified: true, sid: "sid-" + crypto.randomUUID() })
      .setProtectedHeader({ alg: "ES256", kid: "k1" }).setIssuer(ISSUER).setAudience(CLIENT).setSubject(grant.sub)
      .setIssuedAt().setExpirationTime("5m").sign(privateKey);
    return Response.json({ id_token: idToken, access_token: "x", token_type: "Bearer" });
  }
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

let mf, db, gatewayDb, auth, gateway, admin, member;
const tokens = {};
before(async () => {
  mf = await start({
    workers: [
      {
        name: "gateway", modules: true, ...COMPAT, scriptPath: bundle("gateway"),
        routes: ["billing.example.test/*"],
        d1Databases: { SESSIONS: "scim-gateway-sessions" },
        serviceBindings: { UPSTREAM: "upstream", NATHAN: { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "billing" } } },
        outboundService: idp,
        bindings: {
          NATHAN_ISSUER: ISSUER, PUBLIC_ORIGIN: ORIGIN, APPLICATION_ID: "billing",
          OIDC_CLIENT_ID: CLIENT, OIDC_CLIENT_SECRET: "s".repeat(40), SESSION_ENCRYPTION_KEY: randomKey(),
          SESSION_TTL_SECONDS: "3600", REQUIRE_AAL2: "false", NATHAN_PRINCIPAL_KEY: PRINCIPAL_KEY, ACCESS_CACHE_TTL_SECONDS: "1"
        }
      },
      {
        name: "upstream", modules: true, ...COMPAT, scriptPath: ".nathan/build-upstream/worker.js",
        serviceBindings: { NATHAN: { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "billing" } } },
        bindings: { NATHAN_PRINCIPAL_KEY: PRINCIPAL_KEY, NATHAN_APPLICATION_ID: "billing", NATHAN_GATEWAY_ORIGIN: ORIGIN,
          NATHAN_ISSUER: ISSUER, NATHAN_AUDIENCE: AUTH_ORIGIN + "/mcp" }
      },
      {
        name: "auth", modules: true, ...COMPAT, scriptPath: bundle("auth"),
        routes: [AUTH_HOST + "/*"],
        d1Databases: { DB: "scim-auth-db" },
        durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
        // Back-channel logout POSTs from Nathan (and its Durable Object) reach the gateway Worker.
        outboundService: "gateway",
        bindings: {
          NATHAN_ISSUER: AUTH_ORIGIN, NATHAN_ADMIN_EMAILS: "admin@example.test",
          NATHAN_SECURITY_PROFILE: "business", NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_INSTALL_ACTIVE: "true",
          NATHAN_MCP_WRITE_ENABLED: "false", NATHAN_REALM_APEX: "", ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false",
          NATHAN_ADMIN_STEPUP_REQUIRED: "true", BETTER_AUTH_SECRET, NATHAN_CONFIG_KEY: randomKey()
        }
      }
    ]
  });
  gatewayDb = await mf.getD1Database("SESSIONS", "gateway");
  await migrate(gatewayDb, "migrations/gateway/0001_sessions.sql");
  db = await mf.getD1Database("DB", "auth");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(db, "migrations/" + file);
  auth = await mf.getWorker("auth");
  gateway = await mf.getWorker("gateway");
  admin = await enrollAdmin(db, BETTER_AUTH_SECRET);
  // A signed-in user who is not an administrator.
  await user("u-member", "member@example.test");
  member = await insertSession(db, BETTER_AUTH_SECRET, "u-member");

  // acme.example is verified through Better Auth's enterprise SSO domain verification.
  await sql('INSERT INTO "ssoProvider"("id","issuer","userId","providerId","domain","domainVerified") VALUES (\'sso-1\',\'https://idp.acme.example\',\'admin-1\',\'acme-sso\',\'acme.example\',1)');
  // example.test (the bootstrap owner's domain) is verified too, for the corp connection.
  await sql('INSERT INTO "ssoProvider"("id","issuer","userId","providerId","domain","domainVerified") VALUES (\'sso-2\',\'https://idp.example.test\',\'admin-1\',\'corp-sso\',\'example.test\',1)');
  // The gateway is a registered OIDC client that supports back-channel logout.
  await sql('INSERT INTO "oauthClient"("id","clientId","redirectUris","backchannelLogoutUri","disabled","subjectType","createdAt","updatedAt") VALUES (?,?,?,?,0,\'public\',?,?)',
    "oc-1", CLIENT, JSON.stringify([ORIGIN + "/__nathan/callback"]), ORIGIN + "/__nathan/backchannel", now(), now());
  await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('billing','billing.example.test',1,'approved')");
  await sql("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES ('billing','invoices:read')");
  await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('billing','viewer')");
  await sql("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('billing','viewer','invoices:read')");
  for (const [id, name] of [["engineering", "Engineering"], ["support", "Support"], ["finance", "Finance"], ["entra-eng", "Entra engineering"]])
    await sql("INSERT INTO nathan_groups(id,name,created_by) VALUES (?,?,'test')", id, name);
  // Only the group grant carries access; mapping a SCIM group never grants anything by itself.
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g-eng','billing','viewer','group','engineering','test')");

  for (const [id, domain] of [["acme", "acme.example"], ["acme2", "acme.example"], ["other", "other.example"], ["corp", "example.test"]]) {
    const created = await studio("/studio/api/scim/connections", { id, domain });
    assert.equal(created.status, 200, await created.clone().text());
    tokens[id] = (await created.json()).bearerToken;
    assert.equal((await studio("/studio/api/scim/status", { id, enabled: true, confirm: "CONFIRM ENABLE " + id })).status, 200);
  }
});
after(() => mf?.dispose());

const now = () => new Date().toISOString();
const sql = (statement, ...params) => db.prepare(statement).bind(...params).run();
const one = (statement, ...params) => db.prepare(statement).bind(...params).first();
const all = async (statement, ...params) => (await db.prepare(statement).bind(...params).all()).results;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const studio = (path, body, cookie = admin.cookie) => studioPost(auth, AUTH_ORIGIN, path, body, cookie);
async function user(id, email, { verified = 1 } = {}) {
  await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,?,?,?,\'user\')', id, id, email, verified, now(), now());
}
function scim(connection, method, path, body, headers = {}) {
  return auth.fetch(AUTH_ORIGIN + "/scim/v2/" + connection + path, {
    method, body: body === undefined ? undefined : JSON.stringify(body),
    headers: { Authorization: "Bearer " + tokens[connection], ...(body === undefined ? {} : { "Content-Type": "application/scim+json" }), ...headers }
  });
}
async function ok(response, status = 200) {
  const text = await response.text();
  assert.equal(response.status, status, text);
  return text ? JSON.parse(text) : null;
}
/** OAuth tokens Nathan issued to the gateway client for a user (as its token endpoint would). */
async function issueTokens(userId, sessionId) {
  const expires = new Date(Date.now() + 3600_000).toISOString();
  await sql('INSERT INTO "oauthAccessToken"("id","token","clientId","sessionId","userId","expiresAt","createdAt","scopes") VALUES (?,?,?,?,?,?,?,\'openid\')',
    "at-" + crypto.randomUUID(), "t-" + randomKey(), CLIENT, sessionId, userId, expires, now());
  await sql('INSERT INTO "oauthRefreshToken"("id","token","clientId","sessionId","userId","expiresAt","createdAt","scopes") VALUES (?,?,?,?,?,?,?,\'openid offline_access\')',
    "rt-" + crypto.randomUUID(), "r-" + randomKey(), CLIENT, sessionId, userId, expires, now());
}
async function login(sub) {
  const begin = await gateway.fetch(ORIGIN + "/__nathan/login?returnTo=/whoami", { redirect: "manual" });
  const flow = cookiesOf(begin)["__Host-nathan-flow"].value;
  const authorize = new URL(begin.headers.get("Location"));
  const code = "code-" + crypto.randomUUID();
  issued.set(code, { nonce: authorize.searchParams.get("nonce"), sub });
  const callback = await gateway.fetch(ORIGIN + "/__nathan/callback?code=" + code + "&state=" + authorize.searchParams.get("state"),
    { redirect: "manual", headers: { Cookie: "__Host-nathan-flow=" + flow } });
  assert.equal(callback.status, 303, await callback.clone().text());
  return "__Host-nathan-session=" + cookiesOf(callback)["__Host-nathan-session"].value;
}
const viaGateway = cookie => gateway.fetch(ORIGIN + "/whoami", { headers: { Cookie: cookie } });
const nathanSession = async cookie => (await auth.fetch(ISSUER + "/get-session", { headers: { Cookie: cookie } })).json();
const feed = async userId => (await all("SELECT kind FROM nathan_rbac_changes WHERE principal_id=? ORDER BY seq", userId)).map(r => r.kind);
/** The live identity for an externalId (after a rehire, the deleted one shares it). */
const link = (connection, externalId) => one("SELECT * FROM nathan_scim_users WHERE connection_id=? AND external_id=? ORDER BY deleted LIMIT 1", connection, externalId);

const view = async (connection = "acme") => ok(await auth.fetch(AUTH_ORIGIN + "/studio/api/scim/connection?id=" + connection, { headers: { Cookie: admin.cookie } }));
const banned = async userId => Boolean((await one('SELECT "banned" AS banned FROM "user" WHERE "id"=?', userId)).banned);
const resync = connection => studio("/studio/api/scim/settings", { id: connection, linking: true, jit: false, confirm: "CONFIRM SCIM SETTINGS " + connection });
const directoryUser = (email, externalId) => ({ ...okta.createUser, userName: email, externalId, emails: [{ value: email, primary: true, type: "work" }] });
/** Another administrator (enabled admin grant, enrolled); `fresh` controls the passkey step-up's age. */
async function otherAdmin(id, email, { fresh = true } = {}) {
  await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,1,?,?,\'admin\')', id, id, email, now(), now());
  await sql("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES (?,?,'admin-1')", id, email);
  await sql('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (?,\'x\',?,?,0,\'singleDevice\',0)', "pk-" + id, id, "cred-" + id);
  await sql('INSERT INTO "twoFactor"("id","secret","backupCodes","userId","verified") VALUES (?,\'x\',\'x\',?,1)', "tf-" + id, id);
  const session = await insertSession(db, BETTER_AUTH_SECRET, id);
  await sql("INSERT INTO nathan_admin_assurance(session_id,user_id,method,verified_at) VALUES (?,?,'passkey',unixepoch()-?)", session.id, id, fresh ? 0 : 3600);
  return session;
}

let alice, oktaGroup, aliceCookie, aliceSession, gatewayCookie;

test("lifecycle settings and group mappings: admin-only, explicitly confirmed and audited", async () => {
  const settings = { id: "acme", linking: true, jit: false, confirm: "CONFIRM SCIM SETTINGS acme" };
  assert.equal((await studio("/studio/api/scim/settings", settings, member.cookie)).status, 403, "a non-admin session is refused");
  assert.equal((await studio("/studio/api/scim/settings", { ...settings, confirm: "yes" })).status, 409, "confirmation is exact");
  assert.equal((await auth.fetch(AUTH_ORIGIN + "/studio/api/scim/settings", { method: "POST", body: JSON.stringify(settings),
    headers: { Cookie: admin.cookie, Origin: "https://evil.example", "Content-Type": "application/json" } })).status, 403, "cross-origin is refused");
  const saved = await ok(await studio("/studio/api/scim/settings", settings));
  assert.deepEqual({ id: saved.id, linking: saved.linking, jit: saved.jit }, { id: "acme", linking: true, jit: false });
  for (const id of ["acme2", "other", "corp"])
    await ok(await studio("/studio/api/scim/settings", { id, linking: true, jit: false, confirm: "CONFIRM SCIM SETTINGS " + id }));

  const map = { op: "map", connection: "acme", refType: "displayName", ref: "x", group: "engineering", confirm: "CONFIRM MAP acme/x TO engineering" };
  assert.equal((await studio("/studio/api/scim/mappings", map)).status, 409, "only SCIM id or externalId references");
  assert.equal((await studio("/studio/api/scim/mappings", { ...map, refType: "externalId", ref: "grp-eng", group: "engineering" }, member.cookie)).status, 403);
  await ok(await studio("/studio/api/scim/mappings", { op: "map", connection: "acme", refType: "externalId", ref: "okta-eng", group: "engineering", confirm: "CONFIRM MAP acme/okta-eng TO engineering" }));
  await ok(await studio("/studio/api/scim/mappings", { op: "map", connection: "acme", refType: "externalId", ref: "okta-support", group: "support", confirm: "CONFIRM MAP acme/okta-support TO support" }));
  assert.equal((await studio("/studio/api/scim/mappings", { op: "map", connection: "acme2", refType: "externalId", ref: "z", group: "engineering", confirm: "CONFIRM MAP acme2/z TO engineering" })).status, 409,
    "a Nathan group is fed by one SCIM group only");
  assert.equal((await one("SELECT source FROM nathan_groups WHERE id='engineering'")).source, "scim");
  // Mapped groups are maintained by the directory, not by hand (NATH-13 extension point).
  await user("u-hand", "hand@example.test");
  const manual = await studio("/studio/api/rbac", { op: "member.add", group: "engineering", email: "hand@example.test" });
  assert.equal(manual.status, 409);
  assert.equal((await one("SELECT count(*) AS n FROM nathan_rbac_grants WHERE principal_id IN ('engineering','support')")).n, 1,
    "mapping created no grants");
  const audit = await all("SELECT action, outcome FROM nathan_security_audit WHERE action LIKE 'scim_%' ORDER BY created_at");
  assert.ok(audit.some(a => a.action === "scim_settings_update" && a.outcome === "succeeded"));
  assert.ok(audit.some(a => a.action === "scim_group_map" && a.outcome === "succeeded"));
  assert.ok(audit.some(a => a.action === "scim_settings_update" && a.outcome === "rejected"), "refused attempts are audited");
});

test("create (Okta) links by verified-domain email; the mapped group admits the user at the gateway", async () => {
  await user("u-alice", "alice@acme.example");
  aliceSession = await insertSession(db, BETTER_AUTH_SECRET, "u-alice");
  aliceCookie = aliceSession.cookie;
  await issueTokens("u-alice", aliceSession.id);
  alice = await ok(await scim("acme", "POST", "/Users", okta.createUser), 201);
  const row = await link("acme", okta.createUser.externalId);
  assert.equal(row.user_id, "u-alice");
  assert.equal(row.link_state, "linked");
  assert.equal(row.link_method, "email");
  oktaGroup = await ok(await scim("acme", "POST", "/Groups", { ...okta.createGroup, externalId: "okta-eng" }), 201);
  await ok(await scim("acme", "PATCH", "/Groups/" + oktaGroup.id, fill(okta.addMember, { USER_ID: alice.id })));
  const membership = await one("SELECT added_by FROM nathan_group_members WHERE group_id='engineering' AND user_id='u-alice'");
  assert.equal(membership.added_by, "scim:acme");
  assert.deepEqual((await feed("u-alice")).filter(k => k === "member.added"), ["member.added"]);
  gatewayCookie = await login("u-alice");
  const admitted = await viaGateway(gatewayCookie);
  assert.equal(admitted.status, 200, await admitted.clone().text());
  assert.deepEqual((await admitted.json()).roles, ["viewer"]);
});

test("deactivation bans, revokes sessions and tokens, logs out the gateway and blocks new gateway sessions", async () => {
  assert.equal((await nathanSession(aliceCookie))?.user?.id, "u-alice");
  const response = await scim("acme", "PATCH", "/Users/" + alice.id, okta.deactivateUser);
  const body = await ok(response);
  assert.equal(body.active, false);
  const user = await one('SELECT "banned" AS banned, "banReason" AS reason FROM "user" WHERE "id"=\'u-alice\'');
  assert.equal(user.banned, 1);
  assert.match(user.reason, /SCIM/);
  assert.equal((await one('SELECT count(*) AS n FROM "session" WHERE "userId"=\'u-alice\'')).n, 0);
  assert.equal(await nathanSession(aliceCookie), null, "the Nathan session cookie no longer works");
  assert.equal((await one('SELECT count(*) AS n FROM "oauthRefreshToken" WHERE "userId"=\'u-alice\' AND "revoked" IS NULL')).n, 0,
    "all refresh tokens are revoked, offline_access included");
  assert.equal((await one('SELECT count(*) AS n FROM "oauthAccessToken" WHERE "userId"=\'u-alice\' AND "revoked" IS NULL')).n, 0);
  assert.equal((await link("acme", okta.createUser.externalId)).link_state, "deprovisioned");
  const changes = await feed("u-alice");
  assert.ok(changes.includes("user.banned") && changes.includes("user.deprovisioned"), changes.join());
  // Back-channel logout was delivered and the gateway deleted the session.
  const delivery = await one("SELECT state, attempts, last_status FROM nathan_backchannel_deliveries WHERE user_id='u-alice'");
  assert.deepEqual({ ...delivery }, { state: "delivered", attempts: 1, last_status: "204" });
  assert.equal((await gatewayDb.prepare("SELECT count(*) AS n FROM nathan_gateway_sessions WHERE subject='u-alice'").first()).n, 0);
  assert.notEqual((await viaGateway(gatewayCookie)).status, 200);
  // A gateway session obtained anyway (here from the mock IdP) is refused within the 1 s cache window.
  const fresh = await login("u-alice");
  await sleep(1100);
  assert.equal((await viaGateway(fresh)).status, 403);
});

test("a replayed PATCH is a no-op: same version, no new feed, audit or delivery", async () => {
  const before = { feed: (await feed("u-alice")).length, audit: (await one("SELECT count(*) AS n FROM nathan_security_audit")).n,
    deliveries: (await one("SELECT count(*) AS n FROM nathan_backchannel_deliveries")).n };
  const first = await scim("acme", "GET", "/Users/" + alice.id);
  const replay = await scim("acme", "PATCH", "/Users/" + alice.id, okta.deactivateUser);
  assert.equal(replay.status, 200);
  assert.equal(replay.headers.get("ETag"), first.headers.get("ETag"));
  assert.equal((await feed("u-alice")).length, before.feed);
  assert.equal((await one("SELECT count(*) AS n FROM nathan_security_audit")).n, before.audit);
  assert.equal((await one("SELECT count(*) AS n FROM nathan_backchannel_deliveries")).n, before.deliveries);
  // A group PATCH re-adding an existing member changes nothing either.
  const group = await scim("acme", "GET", "/Groups/" + oktaGroup.id);
  const again = await scim("acme", "PATCH", "/Groups/" + oktaGroup.id, fill(okta.addMember, { USER_ID: alice.id }));
  assert.equal(again.headers.get("ETag"), group.headers.get("ETag"));
  // A stale If-Match is refused.
  assert.equal((await scim("acme", "PATCH", "/Users/" + alice.id, okta.reactivateUser, { "If-Match": 'W/"1"' })).status, 412);
});

test("the connection's alarm racing directory retries applies a pending deprovisioning exactly once", async () => {
  // Duplicate outbox rows and two appliers on one revision are exercised directly in tests/scim-apply.test.mjs.
  await user("u-race", "race@acme.example");
  const race = await ok(await scim("acme", "POST", "/Users", directoryUser("race@acme.example", "00u-race")), 201);
  const session = await insertSession(db, BETTER_AUTH_SECRET, "u-race");
  await issueTokens("u-race", session.id);
  await sql("ALTER TABLE nathan_backchannel_deliveries RENAME TO hidden_deliveries");
  let failed;
  try { failed = await scim("acme", "PATCH", "/Users/" + race.id, okta.deactivateUser); }
  finally { await sql("ALTER TABLE hidden_deliveries RENAME TO nathan_backchannel_deliveries"); }
  assert.equal(failed.status, 503, "staged, not applied; the alarm retries in about 2 s");
  assert.equal(await banned("u-race"), false);
  // Directory retries arrive around the alarm's due time, concurrently.
  await sleep(1700);
  const retries = await Promise.all([0, 100, 200, 300, 400, 500].map(async delay => {
    await sleep(delay);
    return (await scim("acme", "PATCH", "/Users/" + race.id, okta.deactivateUser)).status;
  }));
  assert.ok(retries.every(status => status === 200), retries.join());
  assert.equal(await banned("u-race"), true);
  assert.equal(await nathanSession(session.cookie), null);
  assert.deepEqual((await feed("u-race")).filter(k => k === "user.deprovisioned"), ["user.deprovisioned"], "one transition");
  assert.equal((await one("SELECT count(*) AS n FROM nathan_security_audit WHERE action='scim_user_deprovision' AND target='acme:u-race'")).n, 1);
  assert.equal((await one("SELECT count(*) AS n FROM nathan_backchannel_deliveries WHERE user_id='u-race'")).n, 1, "one logout delivery");
  assert.equal((await link("acme", "00u-race")).applied_revision, 2);
});

test("reactivation lifts the SCIM ban but does not restore sessions", async () => {
  await ok(await scim("acme", "PATCH", "/Users/" + alice.id, okta.reactivateUser));
  const user = await one('SELECT "banned" AS banned FROM "user" WHERE "id"=\'u-alice\'');
  assert.ok(!user.banned);
  assert.equal(await nathanSession(aliceCookie), null, "old Nathan sessions stay revoked");
  assert.equal((await one('SELECT count(*) AS n FROM "oauthRefreshToken" WHERE "userId"=\'u-alice\' AND "revoked" IS NULL')).n, 0);
  assert.equal((await link("acme", okta.createUser.externalId)).link_state, "linked");
  assert.ok((await feed("u-alice")).includes("user.reactivated"));
  // An administrator's own ban is never lifted by the directory.
  await sql('UPDATE "user" SET "banned"=1, "banReason"=\'admin decision\' WHERE "id"=\'u-alice\'');
  await ok(await scim("acme", "PATCH", "/Users/" + alice.id, okta.deactivateUser));
  await ok(await scim("acme", "PATCH", "/Users/" + alice.id, okta.reactivateUser));
  assert.equal((await one('SELECT "banned" AS banned FROM "user" WHERE "id"=\'u-alice\'')).banned, 1);
  await sql('UPDATE "user" SET "banned"=0, "banReason"=NULL WHERE "id"=\'u-alice\'');
});

test("removal from a SCIM group removes only that mapped membership", async () => {
  const support = await ok(await scim("acme", "POST", "/Groups", { ...okta.createGroup, displayName: "Okta Support", externalId: "okta-support" }), 201);
  await ok(await scim("acme", "PATCH", "/Groups/" + support.id, fill(okta.addMember, { USER_ID: alice.id })));
  await sql("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('finance','u-alice','admin-1')");
  const groups = async () => (await all("SELECT group_id FROM nathan_group_members WHERE user_id='u-alice' ORDER BY group_id")).map(r => r.group_id);
  assert.deepEqual(await groups(), ["engineering", "finance", "support"]);
  await ok(await scim("acme", "PATCH", "/Groups/" + oktaGroup.id, fill(okta.removeMember, { USER_ID: alice.id })));
  assert.deepEqual(await groups(), ["finance", "support"]);
  // Unmapped SCIM groups never touch Nathan groups.
  const unmapped = await ok(await scim("acme", "POST", "/Groups", { ...okta.createGroup, displayName: "Unmapped", members: [{ value: alice.id }] }), 201);
  assert.deepEqual(await groups(), ["finance", "support"]);
  await ok(await scim("acme", "DELETE", "/Groups/" + unmapped.id), 204);
  await ok(await scim("acme", "DELETE", "/Groups/" + support.id), 204);
  assert.deepEqual(await groups(), ["finance"], "deleting a mapped SCIM group empties only its Nathan group");
});

test("unverified email or domain never links, and a link never moves across connections", async () => {
  // Verified domain, but the Nathan user's email is unverified.
  await user("u-carol", "carol@acme.example", { verified: 0 });
  await ok(await scim("acme", "POST", "/Users", { ...okta.createUser, userName: "carol@acme.example", externalId: "00u-carol", emails: [{ value: "carol@acme.example", primary: true, type: "work" }] }), 201);
  assert.equal((await link("acme", "00u-carol")).user_id, null);
  // Verified Nathan email, but other.example is not a verified domain of the connection.
  await user("u-bob", "bob@other.example");
  await ok(await scim("other", "POST", "/Users", { ...okta.createUser, userName: "bob@other.example", externalId: "00u-bob", emails: [{ value: "bob@other.example", primary: true, type: "work" }] }), 201);
  const bob = await link("other", "00u-bob");
  assert.equal(bob.user_id, null);
  assert.match(bob.link_note, /domain/i);
  // A different connection for the same verified domain cannot take over alice's link.
  await ok(await scim("acme2", "POST", "/Users", { ...okta.createUser, externalId: "00u-alice-elsewhere" }), 201);
  assert.equal((await link("acme2", "00u-alice-elsewhere")).user_id, null);
  assert.equal((await one("SELECT connection_id FROM nathan_scim_users WHERE user_id='u-alice'")).connection_id, "acme");
  // ...and therefore cannot deprovision her.
  const other = await ok(await scim("acme2", "GET", "/Users?filter=" + encodeURIComponent('externalId eq "00u-alice-elsewhere"')));
  await ok(await scim("acme2", "PATCH", "/Users/" + other.Resources[0].id, okta.deactivateUser));
  assert.ok(!(await one('SELECT "banned" AS banned FROM "user" WHERE "id"=\'u-alice\'')).banned);
});

test("while an earlier change is pending, a different later change is refused (503) unstaged; then both apply in order", async () => {
  await user("u-kim", "kim@acme.example");
  const kim = await ok(await scim("acme", "POST", "/Users", directoryUser("kim@acme.example", "00u-kim")), 201);
  const session = await insertSession(db, BETTER_AUTH_SECRET, "u-alice");
  await issueTokens("u-alice", session.id);
  const addKim = fill(okta.addMember, { USER_ID: kim.id });
  await sql("ALTER TABLE nathan_backchannel_deliveries RENAME TO hidden_deliveries");
  let earlier, later, staged;
  try {
    earlier = await scim("acme", "PATCH", "/Users/" + alice.id, entra.disableUser);
    later = await scim("acme", "PATCH", "/Groups/" + oktaGroup.id, addKim);
    staged = await ok(await scim("acme", "GET", "/Groups/" + oktaGroup.id));
  } finally { await sql("ALTER TABLE hidden_deliveries RENAME TO nathan_backchannel_deliveries"); }
  assert.equal(earlier.status, 503, "the deactivation could not be applied");
  assert.equal(later.status, 503, "a different change is refused while an earlier one is pending");
  assert.equal(later.headers.get("Retry-After"), "10");
  assert.ok(!staged.members.some(m => m.value === kim.id), "the refused change was not staged");
  assert.equal(await banned("u-alice"), false, "nothing was applied");
  assert.equal((await nathanSession(session.cookie))?.user?.id, "u-alice");
  assert.equal(await one("SELECT 1 FROM nathan_group_members WHERE group_id='engineering' AND user_id='u-kim'"), null);
  // The directory retries the later change: the earlier one is applied first, then this one.
  await ok(await scim("acme", "PATCH", "/Groups/" + oktaGroup.id, addKim));
  assert.equal(await banned("u-alice"), true);
  assert.equal(await nathanSession(session.cookie), null);
  assert.equal((await link("acme", okta.createUser.externalId)).link_state, "deprovisioned");
  assert.ok(await one("SELECT 1 FROM nathan_group_members WHERE group_id='engineering' AND user_id='u-kim'"));
  const order = await all("SELECT seq, principal_id AS who FROM nathan_rbac_changes WHERE (principal_id='u-alice' AND kind='user.deprovisioned') OR (principal_id='u-kim' AND kind='member.added') ORDER BY seq DESC LIMIT 2");
  assert.deepEqual(order.map(r => r.who), ["u-kim", "u-alice"], "applied in the order the directory sent them");
  const errors = await all("SELECT message FROM nathan_scim_errors WHERE connection_id='acme'");
  assert.ok(errors.length >= 1, "the failure is in the connection's error log");
  await ok(await scim("acme", "PATCH", "/Users/" + alice.id, entra.enableUser));
});

test("a change that failed to apply is retried by the connection's alarm, without a directory retry", async () => {
  await user("u-gina", "gina@acme.example");
  const session = await insertSession(db, BETTER_AUTH_SECRET, "u-gina");
  const gina = await ok(await scim("acme", "POST", "/Users", { ...okta.createUser, userName: "gina@acme.example", externalId: "00u-gina",
    emails: [{ value: "gina@acme.example", primary: true, type: "work" }] }), 201);
  await sql("ALTER TABLE nathan_backchannel_deliveries RENAME TO hidden_deliveries");
  let failed;
  try { failed = await scim("acme", "PATCH", "/Users/" + gina.id, okta.deactivateUser); }
  finally { await sql("ALTER TABLE hidden_deliveries RENAME TO nathan_backchannel_deliveries"); }
  assert.equal(failed.status, 503);
  assert.equal(failed.headers.get("Retry-After"), "10");
  let banned = false;
  for (let i = 0; i < 40 && !banned; i++) {
    await sleep(250);
    banned = Boolean((await one('SELECT "banned" AS banned FROM "user" WHERE "id"=\'u-gina\'')).banned);
  }
  assert.ok(banned, "the alarm applied the staged deactivation");
  assert.equal(await nathanSession(session.cookie), null);
});

test("a failed back-channel delivery stays queued and is retried by the scheduled handler", async () => {
  await user("u-hal", "hal@acme.example");
  const session = await insertSession(db, BETTER_AUTH_SECRET, "u-hal");
  await issueTokens("u-hal", session.id);
  const hal = await ok(await scim("acme", "POST", "/Users", { ...okta.createUser, userName: "hal@acme.example", externalId: "00u-hal",
    emails: [{ value: "hal@acme.example", primary: true, type: "work" }] }), 201);
  // The gateway cannot record the logout, so it answers 503 (retry).
  await gatewayDb.prepare("ALTER TABLE nathan_gateway_logout_jti RENAME TO hidden_jti").run();
  try { await ok(await scim("acme", "PATCH", "/Users/" + hal.id, okta.deactivateUser)); }
  finally { await gatewayDb.prepare("ALTER TABLE hidden_jti RENAME TO nathan_gateway_logout_jti").run(); }
  assert.equal((await one('SELECT "banned" AS banned FROM "user" WHERE "id"=\'u-hal\'')).banned, 1, "revocation does not wait for relying parties");
  const pending = await one("SELECT state, attempts, last_status FROM nathan_backchannel_deliveries WHERE user_id='u-hal'");
  assert.deepEqual({ ...pending }, { state: "pending", attempts: 1, last_status: "503" });
  await sql("UPDATE nathan_backchannel_deliveries SET next_attempt_at=0 WHERE user_id='u-hal'");
  await auth.scheduled({ cron: "0 5 * * *" });
  const done = await one("SELECT state, attempts, last_status FROM nathan_backchannel_deliveries WHERE user_id='u-hal'");
  assert.deepEqual({ ...done }, { state: "delivered", attempts: 2, last_status: "204" });
});

test("Entra payloads end to end: create, filtered email update, group by externalId, string 'False', DELETE", async () => {
  await user("u-erin", "test_user_ab6490ee@acme.example");
  await ok(await studio("/studio/api/scim/mappings", { op: "map", connection: "acme", refType: "externalId", ref: entra.createGroup.externalId, group: "entra-eng",
    confirm: "CONFIRM MAP acme/" + entra.createGroup.externalId + " TO entra-eng" }));
  const erin = await ok(await scim("acme", "POST", "/Users", entra.createUser), 201);
  assert.equal((await link("acme", entra.createUser.externalId)).user_id, "u-erin");
  const found = await ok(await scim("acme", "GET", "/Users?filter=" + encodeURIComponent('userName eq "test_user_ab6490ee@acme.example"')));
  assert.equal(found.totalResults, 1, "userName filters are case-insensitive");
  const updated = await ok(await scim("acme", "PATCH", "/Users/" + erin.id, entra.updateUser));
  assert.equal(updated.emails[0].value, "updated.email@acme.example");
  await ok(await scim("acme", "PATCH", "/Users/" + erin.id, entra.pathlessReplace));
  const group = await ok(await scim("acme", "POST", "/Groups", entra.createGroup), 201);
  assert.equal(group.externalId, entra.createGroup.externalId);
  await ok(await scim("acme", "PATCH", "/Groups/" + group.id, fill(entra.addMember, { USER_ID: erin.id })));
  assert.ok(await one("SELECT 1 FROM nathan_group_members WHERE group_id='entra-eng' AND user_id='u-erin'"));
  const lean = await ok(await scim("acme", "GET", "/Groups/" + group.id + "?excludedAttributes=members"));
  assert.equal(lean.members, undefined);
  await ok(await scim("acme", "PATCH", "/Groups/" + group.id, entra.renameGroup));
  await ok(await scim("acme", "PATCH", "/Groups/" + group.id, fill(entra.removeMember, { USER_ID: erin.id })));
  assert.equal(await one("SELECT 1 FROM nathan_group_members WHERE group_id='entra-eng' AND user_id='u-erin'"), null);
  await ok(await scim("acme", "PATCH", "/Groups/" + group.id, fill(entra.addMember, { USER_ID: erin.id })));
  await ok(await scim("acme", "PATCH", "/Users/" + erin.id, entra.disableUser));
  assert.equal((await one('SELECT "banned" AS banned FROM "user" WHERE "id"=\'u-erin\'')).banned, 1);
  await ok(await scim("acme", "PATCH", "/Users/" + erin.id, entra.enableUser));
  await ok(await scim("acme", "DELETE", "/Users/" + erin.id), 204);
  assert.equal((await one('SELECT "banned" AS banned FROM "user" WHERE "id"=\'u-erin\'')).banned, 1, "DELETE bans; it never deletes the Nathan user");
  assert.equal(await one("SELECT 1 FROM nathan_group_members WHERE group_id='entra-eng' AND user_id='u-erin'"), null);
  assert.equal((await link("acme", entra.createUser.externalId)).deleted, 1);
});

test("Okta PUT replaces the user; a PUT without externalId keeps it", async () => {
  const replaced = await ok(await scim("acme", "PUT", "/Users/" + alice.id, fill(okta.putUser, { USER_ID: alice.id })));
  assert.equal(replaced.displayName, "Alice Example-Smith");
  const { externalId, ...withoutExternalId } = fill(okta.putUser, { USER_ID: alice.id });
  const again = await ok(await scim("acme", "PUT", "/Users/" + alice.id, { ...withoutExternalId, displayName: "Alice E." }));
  assert.equal(again.externalId, externalId);
  assert.equal((await scim("acme", "PUT", "/Users/" + alice.id, { ...withoutExternalId, externalId: "changed" })).status, 409);
});

test("just-in-time creation is off by default and creates an unverified, linked account when enabled", async () => {
  const dave = { ...okta.createUser, userName: "dave@acme.example", externalId: "00u-dave", emails: [{ value: "dave@acme.example", primary: true, type: "work" }] };
  await ok(await scim("acme", "POST", "/Users", dave), 201);
  assert.equal((await link("acme", "00u-dave")).user_id, null);
  assert.equal(await one('SELECT 1 FROM "user" WHERE "email"=\'dave@acme.example\''), null);
  await ok(await studio("/studio/api/scim/settings", { id: "acme", linking: true, jit: true, confirm: "CONFIRM SCIM SETTINGS acme" }));
  const row = await link("acme", "00u-dave");
  assert.equal(row.link_method, "jit", "enabling JIT reconciles staged users");
  const created = await one('SELECT "email" AS email, "emailVerified" AS verified FROM "user" WHERE "id"=?', row.user_id);
  assert.equal(created.email, "dave@acme.example");
  assert.ok(!created.verified, "a directory record does not verify an email address");
  await ok(await studio("/studio/api/scim/settings", { id: "acme", linking: true, jit: false, confirm: "CONFIRM SCIM SETTINGS acme" }));
});

test("Studio connection view: link status, mappings, last sync and error log (admin only)", async () => {
  assert.equal((await auth.fetch(AUTH_ORIGIN + "/studio/api/scim/connection?id=acme", { headers: { Cookie: member.cookie } })).status, 403);
  const view = await ok(await auth.fetch(AUTH_ORIGIN + "/studio/api/scim/connection?id=acme", { headers: { Cookie: admin.cookie } }));
  assert.equal(view.connection.id, "acme");
  assert.equal(view.connection.linking, true);
  assert.equal(view.connection.domainVerified, true);
  assert.ok(view.connection.lastSyncAt);
  assert.ok(view.users.some(u => u.externalId === okta.createUser.externalId && u.linkState === "linked" && u.email === "alice@acme.example"));
  assert.ok(view.mappings.some(m => m.group === "engineering" && m.ref === "okta-eng"));
  assert.ok(view.groups.length >= 1);
  assert.ok(view.errors.length >= 1);
  const unmap = await studio("/studio/api/scim/mappings", { op: "unmap", connection: "acme", group: "support", confirm: "CONFIRM UNMAP support" });
  await ok(unmap);
  assert.equal((await one("SELECT source FROM nathan_groups WHERE id='support'")).source, "studio");
});

test("every SCIM lifecycle route refuses an administrator without a fresh passkey step-up", async () => {
  const stale = await otherAdmin("u-stale", "stale@example.test", { fresh: false });
  const get = path => auth.fetch(AUTH_ORIGIN + path, { headers: { Cookie: stale.cookie } });
  const writes = [
    ["/studio/api/scim/settings", { id: "acme", linking: true, jit: false, confirm: "CONFIRM SCIM SETTINGS acme" }],
    ["/studio/api/scim/mappings", { op: "map", connection: "acme", refType: "externalId", ref: "x", group: "finance", confirm: "CONFIRM MAP acme/x TO finance" }],
    ["/studio/api/scim/mappings", { op: "unmap", connection: "acme", group: "engineering", confirm: "CONFIRM UNMAP engineering" }],
    ["/studio/api/scim/users", { op: "approve", connection: "acme", review: crypto.randomUUID(), confirm: "x" }],
    ["/studio/api/scim/users", { op: "dismiss", connection: "acme", review: crypto.randomUUID(), confirm: "x" }],
    ["/studio/api/scim/users", { op: "keep-active", connection: "acme", scimId: alice.id, confirm: "CONFIRM KEEP ACTIVE alice@acme.example" }],
    ["/studio/api/scim/users", { op: "unlink", connection: "acme", scimId: alice.id, confirm: "CONFIRM UNLINK alice@acme.example" }],
    ["/studio/api/scim/outbox", { op: "skip", connection: "acme", kind: "User", id: alice.id, seq: 1, confirm: "CONFIRM SKIP USER " + alice.id }]
  ];
  for (const path of ["/studio/api/scim/connection?id=acme", "/studio/api/scim/outbox?id=acme"])
    assert.equal((await get(path)).status, 403, path);
  for (const [path, body] of writes)
    assert.equal((await studio(path, body, stale.cookie)).status, 403, path + " " + body.op);
  assert.equal((await one("SELECT source FROM nathan_groups WHERE id='engineering'")).source, "scim", "nothing changed");
  // The same administrator after a fresh step-up is let through: the refusals were the step-up.
  await sql("UPDATE nathan_admin_assurance SET verified_at=unixepoch() WHERE session_id=?", stale.id);
  assert.equal((await get("/studio/api/scim/outbox?id=acme")).status, 200);
});

test("SCIM never links or deprovisions a Nathan administrator by itself; an approved review does, once", async () => {
  const bossSession = await otherAdmin("u-boss", "boss@acme.example");
  await issueTokens("u-boss", bossSession.id);
  const boss = await ok(await scim("acme", "POST", "/Users", directoryUser("boss@acme.example", "00u-boss")), 201);
  let row = await link("acme", "00u-boss");
  assert.equal(row.user_id, null, "not linked automatically");
  assert.match(row.link_note, /administrator review/);
  const linkReview = (await view()).reviews.find(r => r.userId === "u-boss" && r.action === "link");
  assert.equal(linkReview.state, "pending");
  assert.equal((await studio("/studio/api/scim/users", { op: "approve", connection: "acme", review: linkReview.id, confirm: "yes" })).status, 409, "exact confirmation");
  assert.equal((await studio("/studio/api/scim/users", { op: "approve", connection: "acme", review: linkReview.id, confirm: "CONFIRM APPROVE LINK boss@acme.example" }, member.cookie)).status, 403);
  const linked = await ok(await studio("/studio/api/scim/users", { op: "approve", connection: "acme", review: linkReview.id, confirm: "CONFIRM APPROVE LINK boss@acme.example" }));
  assert.equal(linked.state, "applied", JSON.stringify(linked));
  row = await link("acme", "00u-boss");
  assert.deepEqual([row.user_id, row.link_method], ["u-boss", "approved"]);

  // Deactivation (as a leaked SCIM token could send it) is held: no ban, no session or token revoked.
  await ok(await scim("acme", "PATCH", "/Users/" + boss.id, okta.deactivateUser));
  assert.equal(await banned("u-boss"), false);
  assert.equal((await nathanSession(bossSession.cookie))?.user?.id, "u-boss", "the administrator's session still works");
  assert.equal((await one('SELECT count(*) AS n FROM "oauthRefreshToken" WHERE "userId"=\'u-boss\' AND "revoked" IS NULL')).n, 1);
  assert.equal((await one("SELECT count(*) AS n FROM nathan_backchannel_deliveries WHERE user_id='u-boss'")).n, 0);
  assert.ok(!(await feed("u-boss")).includes("user.deprovisioned"));
  assert.ok(await one("SELECT 1 FROM nathan_security_audit WHERE action='scim_admin_review_open' AND target='acme:u-boss:deprovision'"), "the held change is audited");
  // A forced resync does not apply it either.
  await ok(await resync("acme"));
  assert.equal(await banned("u-boss"), false);
  const held = (await view()).reviews.filter(r => r.userId === "u-boss" && r.action === "deprovision");
  assert.deepEqual(held.map(r => r.state), ["pending"], "one review item, not one per replay");
  // Another administrator approves with exact confirmation: applied once.
  const done = await ok(await studio("/studio/api/scim/users", { op: "approve", connection: "acme", review: held[0].id, confirm: "CONFIRM APPROVE DEPROVISION boss@acme.example" }));
  assert.equal(done.state, "applied", JSON.stringify(done));
  assert.equal(await banned("u-boss"), true);
  assert.equal(await nathanSession(bossSession.cookie), null);
  assert.equal((await one('SELECT count(*) AS n FROM "oauthRefreshToken" WHERE "userId"=\'u-boss\' AND "revoked" IS NULL')).n, 0);
  assert.deepEqual((await feed("u-boss")).filter(k => k === "user.deprovisioned"), ["user.deprovisioned"]);
  assert.ok(await one("SELECT 1 FROM nathan_security_audit WHERE action='scim_review_approve' AND outcome='succeeded' AND actor='admin-1'"));
  await ok(await resync("acme"));
  assert.deepEqual((await feed("u-boss")).filter(k => k === "user.deprovisioned"), ["user.deprovisioned"], "a replay does not repeat it");
});

test("the bootstrap owner, the last administrator, is never deprovisioned by SCIM", async () => {
  const owner = await ok(await scim("corp", "POST", "/Users", directoryUser("admin@example.test", "00u-owner")), 201);
  assert.equal((await link("corp", "00u-owner")).user_id, null);
  const linkReview = (await view("corp")).reviews.find(r => r.userId === "admin-1" && r.action === "link");
  assert.equal((await ok(await studio("/studio/api/scim/users", { op: "approve", connection: "corp", review: linkReview.id,
    confirm: "CONFIRM APPROVE LINK admin@example.test" }))).state, "applied");
  for (const change of [() => scim("corp", "PATCH", "/Users/" + owner.id, okta.deactivateUser), () => scim("corp", "DELETE", "/Users/" + owner.id)])
    assert.ok((await change()).status < 300);
  assert.equal(await banned("admin-1"), false);
  assert.equal((await nathanSession(admin.cookie))?.user?.id, "admin-1", "the owner is still signed in");
  assert.match((await link("corp", "00u-owner")).link_note, /administrator review/);
  const review = (await view("corp")).reviews.find(r => r.userId === "admin-1" && r.action === "deprovision" && r.state === "pending");
  const self = await studio("/studio/api/scim/users", { op: "approve", connection: "corp", review: review.id, confirm: "CONFIRM APPROVE DEPROVISION admin@example.test" });
  assert.equal(self.status, 409);
  assert.match((await self.json()).error, /own deprovisioning/);
  // Dismissed: the deletion is kept from applying, through resyncs too.
  await ok(await studio("/studio/api/scim/users", { op: "dismiss", connection: "corp", review: review.id, confirm: "CONFIRM DISMISS DEPROVISION admin@example.test" }));
  await ok(await resync("corp"));
  assert.equal(await banned("admin-1"), false);
  assert.equal((await view("corp")).reviews.filter(r => r.userId === "admin-1" && r.state === "pending").length, 0);
  assert.ok(await one("SELECT 1 FROM nathan_security_audit WHERE action='scim_review_approve' AND outcome='rejected'"), "the refused approval is audited");
});

test("keep active survives a forced resync; only a new deprovision change from the directory blocks again", async () => {
  await user("u-lee", "lee@acme.example");
  const lee = await ok(await scim("acme", "POST", "/Users", directoryUser("lee@acme.example", "00u-lee")), 201);
  await ok(await scim("acme", "PATCH", "/Users/" + lee.id, okta.deactivateUser));
  assert.equal(await banned("u-lee"), true);
  const keep = { op: "keep-active", connection: "acme", scimId: lee.id, confirm: "CONFIRM KEEP ACTIVE lee@acme.example" };
  assert.equal((await studio("/studio/api/scim/users", { ...keep, confirm: "CONFIRM KEEP ACTIVE someone@acme.example" })).status, 409);
  await ok(await studio("/studio/api/scim/users", keep));
  assert.equal(await banned("u-lee"), false);
  let row = await link("acme", "00u-lee");
  assert.deepEqual([row.override_cause, row.override_by], ["deactivated", "admin-1"]);
  assert.ok(row.override_at);
  await ok(await resync("acme"));
  assert.equal(await banned("u-lee"), false, "resync leaves the administrator's decision alone");
  await ok(await scim("acme", "PATCH", "/Users/" + lee.id, okta.deactivateUser));
  assert.equal(await banned("u-lee"), false, "a replay of the same deactivation too");
  // The directory reactivates and later deactivates again: a new deprovision change.
  await ok(await scim("acme", "PATCH", "/Users/" + lee.id, okta.reactivateUser));
  assert.equal((await link("acme", "00u-lee")).override_cause, null);
  await ok(await scim("acme", "PATCH", "/Users/" + lee.id, okta.deactivateUser));
  assert.equal(await banned("u-lee"), true);
  // An unban made directly in D1 is detected and kept the same way.
  await sql('UPDATE "user" SET "banned"=0, "banReason"=NULL WHERE "id"=\'u-lee\'');
  await ok(await resync("acme"));
  assert.equal(await banned("u-lee"), false);
  row = await link("acme", "00u-lee");
  assert.match(row.override_by, /out-of-band/);
  assert.ok(await one("SELECT 1 FROM nathan_security_audit WHERE action='scim_user_keep_active' AND outcome='succeeded'"));
  await ok(await scim("acme", "PATCH", "/Users/" + lee.id, okta.reactivateUser));
});

test("unlink: an administrator detaches a directory user, its directory memberships go, and it is not re-linked", async () => {
  const lee = (await ok(await scim("acme", "GET", "/Users?filter=" + encodeURIComponent('externalId eq "00u-lee"')))).Resources[0];
  await ok(await scim("acme", "PATCH", "/Groups/" + oktaGroup.id, fill(okta.addMember, { USER_ID: lee.id })));
  assert.ok(await one("SELECT 1 FROM nathan_group_members WHERE group_id='engineering' AND user_id='u-lee'"));
  const unlink = { op: "unlink", connection: "acme", scimId: lee.id, confirm: "CONFIRM UNLINK lee@acme.example" };
  assert.equal((await studio("/studio/api/scim/users", { ...unlink, confirm: "CONFIRM UNLINK" })).status, 409);
  await ok(await studio("/studio/api/scim/users", unlink));
  const row = await link("acme", "00u-lee");
  assert.equal(row.user_id, null);
  assert.match(row.link_hold, /Unlinked by an administrator/);
  assert.equal(await one("SELECT 1 FROM nathan_group_members WHERE group_id='engineering' AND user_id='u-lee'"), null);
  assert.ok((await feed("u-lee")).includes("user.unlinked"));
  await ok(await resync("acme"));
  assert.equal((await link("acme", "00u-lee")).user_id, null, "not linked again automatically");
  assert.ok(await one("SELECT 1 FROM nathan_security_audit WHERE action='scim_user_unlink' AND outcome='succeeded'"));
});

test("after a linked Nathan account is deleted, no connection re-links its email without an administrator", async () => {
  await user("u-ivy", "ivy@acme.example");
  await ok(await scim("acme", "POST", "/Users", directoryUser("ivy@acme.example", "00u-ivy")), 201);
  assert.equal((await link("acme", "00u-ivy")).user_id, "u-ivy");
  await sql('DELETE FROM "user" WHERE "id"=\'u-ivy\'');
  await user("u-ivy2", "ivy@acme.example");
  // Another connection for the same verified domain cannot take the new account...
  await ok(await scim("acme2", "POST", "/Users", directoryUser("ivy@acme.example", "00u-ivy-other")), 201);
  assert.equal((await link("acme2", "00u-ivy-other")).user_id, null);
  // ...nor does the original connection re-link silently on a resync.
  await ok(await resync("acme"));
  assert.equal((await link("acme", "00u-ivy")).user_id, null);
  const [mine] = (await view("acme")).reviews.filter(r => r.userId === "u-ivy2" && r.state === "pending");
  const [theirs] = (await view("acme2")).reviews.filter(r => r.userId === "u-ivy2" && r.state === "pending");
  assert.ok(mine && theirs, "each claim waits for an administrator");
  assert.match(theirs.reason, /connection acme/);
  // The administrator decides: the original connection gets the link, the other one cannot.
  await ok(await studio("/studio/api/scim/users", { op: "approve", connection: "acme", review: mine.id, confirm: "CONFIRM APPROVE LINK ivy@acme.example" }));
  assert.equal((await link("acme", "00u-ivy")).user_id, "u-ivy2");
  const refused = await studio("/studio/api/scim/users", { op: "approve", connection: "acme2", review: theirs.id, confirm: "CONFIRM APPROVE LINK ivy@acme.example" });
  assert.equal(refused.status, 409);
  assert.match((await refused.json()).error, /already linked/);
});

test("a rehire after DELETE reuses userName and externalId (and a group its displayName)", async () => {
  await user("u-rae", "rae@acme.example");
  const rae = await ok(await scim("acme", "POST", "/Users", directoryUser("rae@acme.example", "00u-rae")), 201);
  await ok(await scim("acme", "DELETE", "/Users/" + rae.id), 204);
  assert.equal(await banned("u-rae"), true);
  const again = await ok(await scim("acme", "POST", "/Users", directoryUser("rae@acme.example", "00u-rae")), 201);
  assert.notEqual(again.id, rae.id);
  assert.equal((await link("acme", "00u-rae")).user_id, "u-rae", "the rehire takes over the deleted identity's link");
  assert.equal(await banned("u-rae"), false, "and the SCIM ban is lifted for the active directory user");
  assert.equal((await scim("acme", "GET", "/Users/" + rae.id)).status, 404, "the deleted identity stays deleted");
  const group = await ok(await scim("acme", "POST", "/Groups", { ...okta.createGroup, displayName: "Rehire group" }), 201);
  await ok(await scim("acme", "DELETE", "/Groups/" + group.id), 204);
  await ok(await scim("acme", "POST", "/Groups", { ...okta.createGroup, displayName: "Rehire group" }), 201);
});

// ---- re-review fixes ---------------------------------------------------------------------------

const banOf = userId => one('SELECT "banned" AS banned, "banReason" AS reason, "banExpires" AS expires FROM "user" WHERE "id"=?', userId);
const SCIM_BAN = connection => "SCIM deprovisioned (connection " + connection + ")";

test("a 7-day suspension does not end a directory deprovisioning: Nathan takes the ban over; expiry and resync keep it", async () => {
  await user("u-sus", "sus@acme.example");
  const sus = await ok(await scim("acme", "POST", "/Users", directoryUser("sus@acme.example", "00u-sus")), 201);
  // An administrator suspends the user for 7 days (Better Auth banUser writes reason and expiry).
  await sql('UPDATE "user" SET "banned"=1, "banReason"=\'Suspended\', "banExpires"=? WHERE "id"=\'u-sus\'', new Date(Date.now() + 7 * 86400_000).toISOString());
  await ok(await scim("acme", "PATCH", "/Users/" + sus.id, okta.deactivateUser));
  assert.deepEqual({ ...(await banOf("u-sus")) }, { banned: 1, reason: SCIM_BAN("acme"), expires: null });
  // Better Auth lifts an expired ban at sign-in; there is no expiry left to lapse, and a resync keeps the block.
  await sql('UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL WHERE "id"=\'u-sus\' AND "banExpires" IS NOT NULL');
  await ok(await resync("acme"));
  assert.equal(await banned("u-sus"), true);
  assert.equal((await link("acme", "00u-sus")).override_cause, null, "no override recorded");
});

test("an administrator's expiring re-ban over the SCIM ban lapses at sign-in; the next resync bans again, with no override", async () => {
  await user("u-cool", "cool@acme.example");
  const cool = await ok(await scim("acme", "POST", "/Users", directoryUser("cool@acme.example", "00u-cool")), 201);
  await ok(await scim("acme", "PATCH", "/Users/" + cool.id, okta.deactivateUser));
  assert.equal((await banOf("u-cool")).reason, SCIM_BAN("acme"));
  const overrides = (await one("SELECT count(*) AS n FROM nathan_security_audit WHERE action='scim_override_detected'")).n;
  // Re-banned with an expiry (Better Auth banUser over the SCIM ban), then lifted at sign-in once expired.
  await sql('UPDATE "user" SET "banned"=1, "banReason"=\'Cooling off\', "banExpires"=? WHERE "id"=\'u-cool\'', new Date(Date.now() - 1000).toISOString());
  assert.equal((await link("acme", "00u-cool")).scim_banned, 0, "workerd D1 ran the trigger: the ban is no longer Nathan's");
  await sql('UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL WHERE "id"=\'u-cool\'');
  await ok(await resync("acme"));
  assert.deepEqual({ ...(await banOf("u-cool")) }, { banned: 1, reason: SCIM_BAN("acme"), expires: null });
  assert.equal((await link("acme", "00u-cool")).override_cause, null);
  assert.equal((await one("SELECT count(*) AS n FROM nathan_security_audit WHERE action='scim_override_detected'")).n, overrides);
});

test("two administrators in different connections approving each other's deprovisioning: at least one stays", async () => {
  const sessions = {};
  for (const connection of ["acme", "acme2"]) await ok(await resync(connection));   // linking on
  for (const [id, connection] of [["u-ra", "acme"], ["u-rb", "acme2"]]) {
    const email = id.slice(2) + "@acme.example";
    sessions[id] = await otherAdmin(id, email);
    const created = await ok(await scim(connection, "POST", "/Users", directoryUser(email, "00" + id)), 201);
    const review = (await view(connection)).reviews.find(r => r.userId === id && r.action === "link");
    assert.equal((await ok(await studio("/studio/api/scim/users", { op: "approve", connection, review: review.id, confirm: "CONFIRM APPROVE LINK " + email }))).state, "applied");
    await ok(await scim(connection, "PATCH", "/Users/" + created.id, okta.deactivateUser));
    assert.equal(await banned(id), false, "held for review");
  }
  // Every other administrator is blocked, so u-ra and u-rb are each other's only remaining administrator.
  const others = await all("SELECT u.\"id\" AS id FROM \"user\" u WHERE u.\"id\" NOT IN ('u-ra','u-rb') AND ifnull(u.\"banned\",0)=0 AND (" +
    "EXISTS(SELECT 1 FROM nathan_bootstrap_status b WHERE b.admin_user_id=u.\"id\") OR EXISTS(SELECT 1 FROM nathan_admin_grants g WHERE g.user_id=u.\"id\" AND g.enabled=1))");
  for (const o of others) await sql('UPDATE "user" SET "banned"=1, "banReason"=\'test: out of the way\' WHERE "id"=?', o.id);
  try {
    const pending = async (connection, id) => (await view(connection)).reviews.find(r => r.userId === id && r.action === "deprovision" && r.state === "pending");
    const [ra, rb] = [await pending("acme", "u-ra"), await pending("acme2", "u-rb")];
    const results = await Promise.all([
      studio("/studio/api/scim/users", { op: "approve", connection: "acme2", review: rb.id, confirm: "CONFIRM APPROVE DEPROVISION rb@acme.example" }, sessions["u-ra"].cookie),
      studio("/studio/api/scim/users", { op: "approve", connection: "acme", review: ra.id, confirm: "CONFIRM APPROVE DEPROVISION ra@acme.example" }, sessions["u-rb"].cookie)
    ]);
    for (const r of results) assert.ok(r.status === 200 || r.status === 409 || r.status === 403, String(r.status));
    // Let both connections' Durable Objects finish applying (alarms included).
    for (let i = 0; i < 20 && (await one("SELECT count(*) AS n FROM nathan_scim_reviews WHERE user_id IN ('u-ra','u-rb') AND action='deprovision' AND state='approved'")).n; i++) await sleep(100);
    const active = [];
    for (const id of ["u-ra", "u-rb"]) if (!await banned(id)) active.push(id);
    assert.equal(active.length, 1, "exactly one of the two administrators remains: " + JSON.stringify(await all("SELECT user_id, state FROM nathan_scim_reviews WHERE user_id IN ('u-ra','u-rb') AND action='deprovision'")));
  } finally {
    for (const o of others) await sql('UPDATE "user" SET "banned"=0, "banReason"=NULL WHERE "id"=?', o.id);
  }
});

test("Studio review list: pending first and oldest first, counts per state, filter and paging; bad filters are refused", async () => {
  const v = await view();
  assert.ok(v.reviewCounts && typeof v.reviewCounts === "object");
  assert.equal(v.reviewPage.limit, 100);
  const order = v.reviews.map(r => r.state === "pending" ? 0 : r.state === "approved" ? 1 : 2);
  assert.deepEqual(order, [...order].sort((a, b) => a - b), "open items first");
  const filtered = await ok(await auth.fetch(AUTH_ORIGIN + "/studio/api/scim/connection?id=acme&reviewState=applied", { headers: { Cookie: admin.cookie } }));
  assert.ok(filtered.reviews.every(r => r.state === "applied"));
  assert.equal(filtered.reviewPage.total, v.reviewCounts.applied ?? 0);
  const bad = await auth.fetch(AUTH_ORIGIN + "/studio/api/scim/connection?id=acme&reviewOffset=-5", { headers: { Cookie: admin.cookie } });
  assert.equal(bad.status, 400);
});
