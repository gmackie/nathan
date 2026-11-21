/**
 * NATH-13 in workerd: the built identity Worker, gateway and an SDK-using upstream run together.
 * The gateway resolves access over the NATHAN service binding (real NathanVerifier RPC and the real
 * evaluator against a migrated D1), signs X-Nathan-Principal, and the upstream verifies it.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { SignJWT, UnsecuredJWT, exportJWK, generateKeyPair } from "jose";
import { bundle, migrate, randomKey, cookiesOf, start, COMPAT } from "./helpers.mjs";

const AUTH_HOST = "login.example.test";
const ISSUER = "https://" + AUTH_HOST + "/api/auth";
const ORIGIN = "https://billing.example.test";
const CLIENT = "billing-gateway";
const API_AUDIENCE = "https://api.billing.example.test";
const PRINCIPAL_KEY = randomKey();
const BETTER_AUTH_SECRET = randomKey() + randomKey();
const TTL_SECONDS = 1;
const { privateKey, publicKey } = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };

/** Mock OIDC provider for the gateway's login and the SDK's JWKS. */
const issued = new Map();
async function idp(request) {
  const url = new URL(request.url);
  if (url.href === ISSUER + "/.well-known/openid-configuration")
    return Response.json({ issuer: ISSUER, authorization_endpoint: ISSUER + "/oauth2/authorize", token_endpoint: ISSUER + "/oauth2/token", jwks_uri: ISSUER + "/jwks" });
  if (url.href === ISSUER + "/jwks") return Response.json({ keys: [jwk] });
  if (url.href === ISSUER + "/oauth2/token" && request.method === "POST") {
    const grant = issued.get(new URLSearchParams(await request.text()).get("code"));
    if (!grant) return Response.json({ error: "invalid_grant" }, { status: 400 });
    const idToken = await new SignJWT({ nonce: grant.nonce, email: grant.sub + "@example.test", email_verified: true, sid: "sid-" + grant.sub })
      .setProtectedHeader({ alg: "ES256", kid: "k1" }).setIssuer(ISSUER).setAudience(CLIENT).setSubject(grant.sub)
      .setIssuedAt().setExpirationTime("5m").sign(privateKey);
    return Response.json({ id_token: idToken, access_token: "x", token_type: "Bearer" });
  }
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

let mf, authDb, gateway, upstream, auth;
before(async () => {
  mf = await start({
    workers: [
      {
        name: "gateway", modules: true, ...COMPAT, scriptPath: bundle("gateway"),
        d1Databases: { SESSIONS: "rbac-gateway-sessions" },
        serviceBindings: { UPSTREAM: "upstream", NATHAN: { name: "auth", entrypoint: "NathanVerifier" } },
        outboundService: idp,
        bindings: {
          NATHAN_ISSUER: ISSUER, PUBLIC_ORIGIN: ORIGIN, APPLICATION_ID: "billing",
          OIDC_CLIENT_ID: CLIENT, OIDC_CLIENT_SECRET: "s".repeat(40), SESSION_ENCRYPTION_KEY: randomKey(),
          SESSION_TTL_SECONDS: "3600", REQUIRE_AAL2: "false", NATHAN_PRINCIPAL_KEY: PRINCIPAL_KEY,
          ACCESS_CACHE_TTL_SECONDS: String(TTL_SECONDS)
        }
      },
      {
        name: "upstream", modules: true, ...COMPAT, scriptPath: ".nathan/build-upstream/worker.js",
        serviceBindings: { NATHAN: { name: "auth", entrypoint: "NathanVerifier" } },
        outboundService: idp,
        bindings: { NATHAN_PRINCIPAL_KEY: PRINCIPAL_KEY, NATHAN_APPLICATION_ID: "billing", NATHAN_GATEWAY_ORIGIN: ORIGIN,
          NATHAN_ISSUER: ISSUER, NATHAN_AUDIENCE: API_AUDIENCE }
      },
      {
        name: "auth", modules: true, ...COMPAT, scriptPath: bundle("auth"),
        d1Databases: { DB: "rbac-auth-db" },
        durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
        bindings: {
          NATHAN_ISSUER: "https://" + AUTH_HOST, NATHAN_ADMIN_EMAILS: "admin@example.test",
          NATHAN_SECURITY_PROFILE: "business", NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_INSTALL_ACTIVE: "true",
          NATHAN_MCP_WRITE_ENABLED: "false", NATHAN_REALM_APEX: "", ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false",
          NATHAN_ADMIN_STEPUP_REQUIRED: "true", BETTER_AUTH_SECRET, NATHAN_CONFIG_KEY: randomKey()
        }
      }
    ]
  });
  await migrate(await mf.getD1Database("SESSIONS", "gateway"), "migrations/gateway/0001_sessions.sql");
  authDb = await mf.getD1Database("DB", "auth");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(authDb, "migrations/" + file);
  gateway = await mf.getWorker("gateway");
  upstream = await mf.getWorker("upstream");
  auth = await mf.getWorker("auth");
});
after(() => mf?.dispose());

const sql = (statement, ...params) => authDb.prepare(statement).bind(...params).run();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function user(id, { banned = 0, role = "user" } = {}) {
  await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role","banned") VALUES (?,?,?,?,?,?,?,?)',
    id, id, id + "@example.test", 1, new Date().toISOString(), new Date().toISOString(), role, banned);
}
async function billingApp({ enabled = 1, accessMode = "approved" } = {}) {
  await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('billing','billing.example.test',?,?) " +
    "ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, access_mode=excluded.access_mode", enabled, accessMode);
}
async function billingRoles() {
  await sql("INSERT OR IGNORE INTO nathan_rbac_permissions(app_id,key) VALUES ('billing','invoices:read'),('billing','invoices:write')");
  await sql("INSERT OR IGNORE INTO nathan_rbac_roles(app_id,key) VALUES ('billing','viewer'),('billing','editor')");
  await sql("INSERT OR IGNORE INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES " +
    "('billing','viewer','invoices:read'),('billing','editor','invoices:read'),('billing','editor','invoices:write')");
}
const grant = (id, role, type, principal) =>
  sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES (?,?,?,?,?,'test')", id, "billing", role, type, principal);

async function login(sub) {
  const begin = await gateway.fetch(ORIGIN + "/__nathan/login?returnTo=/whoami", { redirect: "manual" });
  assert.equal(begin.status, 302);
  const flow = cookiesOf(begin)["__Host-nathan-flow"].value;
  const authorize = new URL(begin.headers.get("Location"));
  const code = "code-" + crypto.randomUUID();
  issued.set(code, { nonce: authorize.searchParams.get("nonce"), sub });
  const callback = await gateway.fetch(ORIGIN + "/__nathan/callback?code=" + code + "&state=" + authorize.searchParams.get("state"),
    { redirect: "manual", headers: { Cookie: "__Host-nathan-flow=" + flow } });
  assert.equal(callback.status, 303, await callback.clone().text());
  return "__Host-nathan-session=" + cookiesOf(callback)["__Host-nathan-session"].value;
}
const viaGateway = (cookie, path = "/whoami", headers = {}) => gateway.fetch(ORIGIN + path, { headers: { Cookie: cookie, ...headers } });
const accessToken = sub => new SignJWT({ scope: "openid" }).setProtectedHeader({ alg: "ES256", kid: "k1", typ: "at+jwt" })
  .setIssuer(ISSUER).setAudience(API_AUDIENCE).setSubject(sub).setIssuedAt().setExpirationTime("5m").sign(privateKey);

test("deny by default: a new app with no grants gets 403 at the gateway", async () => {
  await billingApp();
  await billingRoles();
  await user("u-new");
  const response = await viaGateway(await login("u-new"));
  assert.equal(response.status, 403);
  assert.match(await response.text(), /Access denied/);
});

test("a granted user reaches the upstream with a verified principal; inbound X-Nathan-* headers are stripped", async () => {
  await user("u-editor");
  await grant("g-editor", "editor", "user", "u-editor");
  const forged = new UnsecuredJWT({ sub: "root", app: "billing", roles: ["admin"], permissions: ["invoices:write"] })
    .setIssuer(ORIGIN).setAudience("billing").setIssuedAt().setExpirationTime("30s").encode();
  const response = await viaGateway(await login("u-editor"), "/whoami", { "X-Nathan-Principal": forged, "X-Nathan-Subject": "root", "x-nathan-email": "root@example.test" });
  assert.equal(response.status, 200, await response.clone().text());
  const body = await response.json();
  assert.equal(body.via, "gateway");
  assert.equal(body.sub, "u-editor");
  assert.equal(body.email, "u-editor@example.test");
  assert.deepEqual(body.roles, ["editor"]);
  assert.deepEqual(body.permissions, ["invoices:read", "invoices:write"]);
  assert.equal(body.canWrite, true);
  assert.equal(body.forwarded["x-nathan-subject"], "u-editor", "the gateway overwrote the inbound subject");
  assert.equal(body.forwarded["x-nathan-email"], "u-editor@example.test");
  assert.equal((await viaGateway(await login("u-editor"), "/invoices/write")).status, 200);
});

test("a group grant gives the group's role; require() answers 403 for a missing permission", async () => {
  await user("u-member");
  await sql("INSERT INTO nathan_groups(id,name,created_by) VALUES ('finance','Finance','test')");
  await sql("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('finance','u-member','test')");
  await grant("g-finance", "viewer", "group", "finance");
  const cookie = await login("u-member");
  const body = await (await viaGateway(cookie)).json();
  assert.deepEqual(body.roles, ["viewer"]);
  const denied = await viaGateway(cookie, "/invoices/write");
  assert.equal(denied.status, 403);
  assert.deepEqual(await denied.json(), { error: "forbidden", permission: "invoices:write" });
});

test("grant removal takes effect at the gateway within the cache window", async () => {
  await user("u-revoke");
  await grant("g-revoke", "viewer", "user", "u-revoke");
  const cookie = await login("u-revoke");
  assert.equal((await viaGateway(cookie)).status, 200);
  await sql("DELETE FROM nathan_rbac_grants WHERE id='g-revoke'");
  // Within the window the cached decision may still be used, but never beyond it.
  assert.equal((await viaGateway(cookie)).status, 200, "cached for at most ACCESS_CACHE_TTL_SECONDS");
  await sleep(TTL_SECONDS * 1000 + 150);
  assert.equal((await viaGateway(cookie)).status, 403, "revoked after the cache window");
});

test("blocking a user or disabling the app denies within the cache window", async () => {
  await user("u-block");
  await grant("g-block", "viewer", "user", "u-block");
  const cookie = await login("u-block");
  assert.equal((await viaGateway(cookie)).status, 200);
  await sql('UPDATE "user" SET "banned"=1 WHERE "id"=\'u-block\'');
  await sleep(TTL_SECONDS * 1000 + 150);
  assert.equal((await viaGateway(cookie)).status, 403);

  const other = await login("u-editor");
  assert.equal((await viaGateway(other)).status, 200);
  await billingApp({ enabled: 0 });
  await sleep(TTL_SECONDS * 1000 + 150);
  assert.equal((await viaGateway(other)).status, 403);
  await billingApp({ enabled: 1 });
});

test("the upstream SDK rejects forged, unsigned and re-keyed principals sent directly", async () => {
  const claims = { email: null, app: "billing", roles: ["editor"], permissions: ["invoices:write"] };
  const signed = key => new SignJWT(claims).setProtectedHeader({ alg: "HS256", typ: "nathan-principal+jwt" })
    .setIssuer(ORIGIN).setAudience("billing").setSubject("attacker").setIssuedAt().setExpirationTime("30s")
    .sign(Buffer.from(key, "base64url"));
  const attempts = {
    unsigned: new UnsecuredJWT(claims).setIssuer(ORIGIN).setAudience("billing").setSubject("attacker").setIssuedAt().setExpirationTime("30s").encode(),
    otherKey: await signed(randomKey()),
    garbage: "definitely-not-a-jws",
    noHeader: null
  };
  for (const [name, value] of Object.entries(attempts)) {
    const response = await upstream.fetch("https://billing.internal/invoices/write", { headers: value ? { "X-Nathan-Principal": value } : {} });
    assert.equal(response.status, 401, name);
  }
  // Control: the real key is accepted, so the rejections above are about the signature.
  assert.equal((await upstream.fetch("https://billing.internal/invoices/write", { headers: { "X-Nathan-Principal": await signed(PRINCIPAL_KEY) } })).status, 200);
});

test("same answers through the gateway principal and the SDK bearer-token path (table)", async () => {
  const scenarios = [
    { name: "direct grant", setup: async id => grant("t-" + id, "editor", "user", id) },
    { name: "group grant", setup: async id => { await sql("INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES ('finance',?,'test')", id); } },
    { name: "no grant", setup: async () => {} },
    { name: "any signed-in user", app: { accessMode: "any_signed_in" }, setup: async () => {} },
    { name: "blocked user", app: { accessMode: "any_signed_in" }, banned: 1, setup: async () => {} },
    { name: "disabled app", app: { enabled: 0 }, setup: async id => grant("t-" + id, "editor", "user", id) }
  ];
  let i = 0;
  for (const scenario of scenarios) {
    const id = "u-table-" + i++;
    await user(id, { banned: 0 });
    await scenario.setup(id);
    // Log in before blocking: a blocked user cannot complete a fresh Nathan login.
    const cookie = await login(id);
    if (scenario.banned) await sql('UPDATE "user" SET "banned"=1 WHERE "id"=?', id);
    await billingApp({ enabled: 1, accessMode: "approved", ...scenario.app });
    const answer = async response => ({ status: response.status, body: response.status === 200 ? await response.json() : null });
    const gatewaySide = await answer(await viaGateway(cookie));
    const tokenSide = await answer(await upstream.fetch("https://billing.internal/whoami", { headers: { Authorization: "Bearer " + await accessToken(id) } }));
    const comparable = side => side.body ? { status: side.status, sub: side.body.sub, email: side.body.email, roles: side.body.roles,
      permissions: side.body.permissions, canRead: side.body.canRead, canWrite: side.body.canWrite, isEditor: side.body.isEditor } : { status: side.status };
    assert.deepEqual(comparable(tokenSide), comparable(gatewaySide), scenario.name);
    const writeGateway = (await viaGateway(cookie, "/invoices/write")).status;
    const writeToken = (await upstream.fetch("https://billing.internal/invoices/write", { headers: { Authorization: "Bearer " + await accessToken(id) } })).status;
    assert.equal(writeToken, writeGateway, scenario.name + " (require)");
  }
  await billingApp({ enabled: 1, accessMode: "approved" });
});
