import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { bundle, COMPAT, cookiesOf, insertSession, migrate, migrateGateway, randomKey, start } from "./helpers.mjs";

const origin = "https://school.example.test", issuer = origin + "/api/auth", signingSecret = randomKey();
const clients = ["broad", "per-session"], secret = randomKey();
const rp = client => "https://" + client + ".example.test";
const binding = { name: "auth", entrypoint: "NathanAppAuth", props: { applicationId: "classcheck" } };
let mf, db;
const receipts = new Map();
const run = (query, ...parameters) => db.prepare(query).bind(...parameters).run();
const all = (database, query, ...parameters) => database.prepare(query).bind(...parameters).all().then(r => r.results);
const call = async (method, input) => (await mf.dispatchFetch(origin + "/jobs/" + method, {
  method: "POST", body: JSON.stringify(input) })).json();

before(async () => {
  mf = await start({ workers: [
    { name: "web", ...COMPAT, modules: true, routes: ["school.example.test/*"], serviceBindings: {
      AUTH: binding, JOB: { ...binding, entrypoint: "NathanAppProvisioner" } },
      script: `export default { async fetch(request, env) {
        const url = new URL(request.url);
        if (url.pathname === "/jobs/provision") return Response.json(await env.JOB.provision(await request.json()));
        if (url.pathname === "/jobs/erase") return Response.json(await env.JOB.erase(await request.json()));
        if (url.pathname === "/api/auth/oauth2/token") {
          const body = new URLSearchParams(await request.text());
          body.set("resource", url.origin + "/api");
          return env.AUTH.fetch(new Request(url.href, {method: "POST", headers: request.headers, body}));
        }
        return env.AUTH.fetch(request);
      } }` },
    ...clients.map(client => ({ name: client, ...COMPAT, modules: true, scriptPath: bundle("gateway"),
      d1Databases: { SESSIONS: "erase-rp-" + client }, outboundService: "web",
      bindings: { NATHAN_ISSUER: issuer, PUBLIC_ORIGIN: rp(client), OIDC_CLIENT_ID: client,
        OIDC_CLIENT_SECRET: secret, SESSION_ENCRYPTION_KEY: randomKey() } })),
    { name: "auth", ...COMPAT, modules: true, scriptPath: bundle("auth"), d1Databases: { DB: "erase-rp-issuer" },
      durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
      outboundService: async request => {
        const client = new URL(request.url).hostname.split(".")[0];
        assert.ok(clients.includes(client));
        const token = new URLSearchParams(await request.clone().text()).get("logout_token");
        receipts.set(client, JSON.parse(Buffer.from(token.split(".")[1], "base64url")));
        return (await mf.getWorker(client)).fetch(request.url, { method: "POST", headers: request.headers, body: await request.text() });
      },
      bindings: { NATHAN_ADMIN_EMAILS: "operator@example.test", NATHAN_ISSUER: "https://id.example.test",
        NATHAN_APP_ORIGIN: origin, NATHAN_APP_ID: "classcheck", NATHAN_INSTALL_ACTIVE: "true",
        NATHAN_ACCESS_TEAM_DOMAIN: "test.cloudflareaccess.com", NATHAN_ACCESS_AUD: "a".repeat(64),
        NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_STEPUP_REQUIRED: "true", NATHAN_CONFIG_KEY: randomKey(),
        NATHAN_PAIRWISE_SECRET: randomKey(), BETTER_AUTH_SECRET: signingSecret } }
  ] });
  db = await mf.getD1Database("DB", "auth");
  for (const name of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(db, "migrations/" + name);
  await run("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('classcheck','school.example.test',1,'approved')");
  await run("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('classcheck','member')");
  await run("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES ('classcheck','profile:read')");
  await run("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('classcheck','member','profile:read')");
  await run("INSERT INTO oauthResource(id,identifier,name,allowedScopes) VALUES ('res',?,'API','[\"openid\",\"email\",\"profile\"]')", origin + "/api");
  await run("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,'classcheck','test')", origin + "/api");
  for (const client of clients) {
    await migrateGateway(await mf.getD1Database("SESSIONS", client));
    await run("INSERT INTO oauthClient(id,clientId,clientSecret,redirectUris,skipConsent,requirePKCE,grantTypes,scopes," +
      "tokenEndpointAuthMethod,backchannelLogoutUri,backchannelLogoutSessionRequired,subjectType) VALUES(?,?,?,?,1,1," +
      "'[\"authorization_code\"]','[\"openid\",\"profile\",\"email\"]','client_secret_basic',?,?,?)",
      client, client, createHash("sha256").update(secret).digest("base64url"), JSON.stringify([rp(client) + "/__nathan/callback"]),
      rp(client) + "/__nathan/backchannel", client === "per-session" ? 1 : 0, client === "broad" ? "pairwise" : "public");
    await run("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES (?,?,?)", client, client, origin + "/api");
  }
});
after(() => mf?.dispose());

async function login(client, sub, expectedStatus = 303) {
  const rpWorker = await mf.getWorker(client), local = await mf.getD1Database("SESSIONS", client);
  const browser = await insertSession(db, signingSecret, sub);
  const begin = await rpWorker.fetch(rp(client) + "/__nathan/login", { redirect: "manual" });
  const authorization = new URL(begin.headers.get("Location"));
  authorization.searchParams.set("resource", origin + "/api");
  const approved = await mf.dispatchFetch(authorization.href, { redirect: "manual", headers: { Cookie: browser.cookie } });
  const callback = approved.headers.get("Location") ?? (await approved.json()).url;
  assert.equal(new URL(callback).pathname, "/__nathan/callback");
  const flow = cookiesOf(begin)["__Host-nathan-flow"].value;
  const session = await rpWorker.fetch(callback, { redirect: "manual", headers: { Cookie: "__Host-nathan-flow=" + flow } });
  assert.equal(session.status, expectedStatus, await session.clone().text());
  if (expectedStatus !== 303) {
    assert.equal(cookiesOf(session)["__Host-nathan-session"], undefined);
    assert.deepEqual(await all(local, "SELECT sid FROM nathan_gateway_sessions WHERE sid=?", browser.id), []);
    return;
  }
  const receipt = (await all(local, "SELECT subject,sid FROM nathan_gateway_sessions WHERE sid=?", browser.id))[0];
  assert.equal(receipt.sid, browser.id);
  return receipt;
}

test("erasure reaches real JWT-only RPs after Nathan sessions expire and revokes exactly the issued subjects and sessions", async () => {
  const identity = { externalId: "local-user", email: "member@example.test" };
  const { sub } = await call("provision", identity);
  assert.ok(sub);
  await run("UPDATE user SET emailVerified=1 WHERE id=?", sub);
  const broad = await login("broad", sub), scoped = await login("per-session", sub);
  assert.notEqual(broad.subject, sub, "pairwise subject from the actual ID token");
  assert.equal(scoped.subject, sub);
  for (const table of ["oauthConsent","oauthAccessToken","oauthRefreshToken"])
    assert.deepEqual(await all(db, "SELECT id FROM " + table + " WHERE userId=?", sub), []);
  const wideStore = await mf.getD1Database("SESSIONS", "broad");
  await wideStore.prepare("INSERT INTO nathan_gateway_sessions(id_hash,subject,issuer,client_id,sid,expires_at) " +
    "VALUES ('old-browser',?,?,'broad','previous-op-session',unixepoch()+3600),('unrelated','different',?,'broad','other',unixepoch()+3600)")
    .bind(broad.subject,issuer,issuer).run();
  await run("UPDATE session SET expiresAt='2001-01-01' WHERE userId=?", sub);
  await run("DELETE FROM session WHERE userId=?", sub);
  // The sector configuration can change after the RP established its session.
  await run("UPDATE oauthClient SET redirectUris='[\"https://new-sector.example.test/callback\"]' WHERE clientId='broad'");
  assert.deepEqual(await call("erase", { externalId: identity.externalId, sub, revision: 1 }), { sub, revision: 1, applied: true });
  await (await mf.getWorker("auth")).scheduled({ cron: "0 5 * * *" });
  assert.deepEqual(await all(wideStore, "SELECT id_hash FROM nathan_gateway_sessions"), [{ id_hash: "unrelated" }]);
  assert.deepEqual(await all(await mf.getD1Database("SESSIONS","per-session"), "SELECT id_hash FROM nathan_gateway_sessions"), []);
  assert.equal(receipts.get("broad").sub, broad.subject);
  assert.equal(receipts.get("broad").sid, undefined);
  assert.equal(receipts.get("per-session").sub, scoped.subject);
  assert.equal(receipts.get("per-session").sid, scoped.sid);
});

test("the issuer withholds tokens when it cannot record the participating RP", async () => {
  const { sub } = await call("provision", { externalId: "retry-user", email: "retry@example.test" });
  assert.ok(sub);
  await run("UPDATE user SET emailVerified=1 WHERE id=?", sub);
  await run("CREATE TRIGGER fail_participation BEFORE INSERT ON nathan_app_rp_sessions BEGIN SELECT RAISE(ABORT,'participation unavailable'); END");
  try {
    await login("per-session", sub, 401);
    assert.deepEqual(await all(db, "SELECT session_id FROM nathan_app_rp_sessions WHERE user_id=?", sub), []);
  } finally {
    await run("DROP TRIGGER fail_participation");
  }
  assert.equal((await login("per-session", sub)).subject, sub);
});
