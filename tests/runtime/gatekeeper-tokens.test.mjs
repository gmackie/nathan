/**
 * NATH-15 in workerd: the built identity Worker mints Gatekeeper-ready access tokens through its
 * real Better Auth token endpoint, for (a) a user via authorization code + PKCE, (b) a machine via
 * client credentials and (c) an administrator-marked agent. Each token is checked against the
 * Gatekeeper provider entry published in docs/gatekeeper.md, with a mirror of Gatekeeper's
 * adapter rules and, when a Gatekeeper checkout is available, with Gatekeeper's own resolver.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, copyFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { authWorker, randomKey, base64url } from "./helpers.mjs";
import { providerEntryFromDocs, verifyLikeGatekeeper } from "./gatekeeper-verifier.mjs";

// The documented entry is used verbatim, so the test install lives at its placeholder host.
const PROVIDER = providerEntryFromDocs();
const HOST = new URL(PROVIDER.issuer).host;
const ORIGIN = "https://" + HOST;
const ISSUER = ORIGIN + "/api/auth";
const AUDIENCE = PROVIDER.audience;
const OTHER_AUDIENCE = "https://reports.example.com/api";
const REDIRECT = "https://billing.example.com/callback";
const SECRET = randomKey() + randomKey();
let mf, db;
after(() => mf?.dispose());

const sql = (statement, ...params) => db.prepare(statement).bind(...params).run();
const now = () => new Date().toISOString();
const decode = token => token.split(".").slice(0, 2).map(p => JSON.parse(Buffer.from(p, "base64url")));
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
const post = (path, body, cookie) => mf.dispatchFetch(ORIGIN + path, {
  method: "POST", body: JSON.stringify(body),
  headers: { Cookie: cookie, Origin: ORIGIN, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin" }
});
const count = async (statement, ...params) => (await db.prepare(statement).bind(...params).first()).n;
async function jwks() {
  const response = await mf.dispatchFetch(PROVIDER.jwksUri);
  assert.equal(response.status, 200, "the documented jwksUri serves Nathan's keys");
  return response.json();
}

let admin, alice, bob, webClient, machine, agent, otherClient;
const tokens = {};
async function tokenRequest(params, client) {
  const response = await mf.dispatchFetch(ISSUER + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(client.client_id + ":" + client.client_secret) },
    body: new URLSearchParams(params).toString()
  });
  return { status: response.status, body: await response.json() };
}
/** Authorization code + PKCE (S256) with resource indicators, as a browser would drive it. */
async function authorizationCode(who, client = webClient, resource = AUDIENCE) {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = randomKey();
  const query = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: REDIRECT,
    scope: "openid profile", state, code_challenge: challenge, code_challenge_method: "S256", resource });
  const authorize = await mf.dispatchFetch(ISSUER + "/oauth2/authorize?" + query,
    { redirect: "manual", headers: { Cookie: who.cookie, Accept: "text/html", "Sec-Fetch-Mode": "navigate" } });
  // Better Auth answers either with a 302 or, for fetch-style requests, with {redirect: true, url}.
  let target = authorize.headers.get("Location");
  if (authorize.status === 200) {
    const redirect = await authorize.json();
    assert.equal(redirect.redirect, true, JSON.stringify(redirect));
    target = redirect.url;
  } else assert.equal(authorize.status, 302, await authorize.clone().text());
  const location = new URL(target);
  assert.equal(location.origin + location.pathname, REDIRECT, location.href);
  assert.equal(location.searchParams.get("state"), state);
  const code = location.searchParams.get("code");
  assert.ok(code, location.href);
  const token = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, resource }, client);
  assert.equal(token.status, 200, JSON.stringify(token.body));
  return token.body;
}
const clientCredentials = (client, resource = AUDIENCE) =>
  tokenRequest({ grant_type: "client_credentials", scope: "nathan:api", resource }, client);

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
  await user("u-bob", "bob@example.test");
  alice = await session("u-alice");
  bob = await session("u-bob");
  // Alice's session was created by a verified passkey sign-in (the after-hook writes this row); Bob's was not.
  await sql("INSERT INTO nathan_admin_assurance(session_id,user_id,method,verified_at) VALUES (?,?,'passkey',?)", alice.id, "u-alice", Math.floor(Date.now() / 1000) - 60);
  await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('billing','billing.example.com',1,'approved')");
  await sql("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES ('billing','invoices:read'),('billing','invoices:write')");
  await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('billing','editor')");
  await sql("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('billing','editor','invoices:read'),('billing','editor','invoices:write')");
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','billing','editor','user','u-alice','test')");
});

test("token-profile administration is refused to non-administrators and cross-origin callers", async () => {
  const body = { op: "audience.register", identifier: AUDIENCE };
  assert.equal((await post("/studio/api/tokens", body, alice.cookie)).status, 403);
  assert.equal((await post("/studio/api/tokens", body, "")).status, 403);
  const crossOrigin = await mf.dispatchFetch(ORIGIN + "/studio/api/tokens", { method: "POST", body: JSON.stringify(body),
    headers: { Cookie: admin.cookie, Origin: "https://evil.example", "Content-Type": "application/json" } });
  assert.equal(crossOrigin.status, 403);
  assert.equal((await mf.dispatchFetch(ORIGIN + "/studio/api/tokens", { headers: { Cookie: alice.cookie } })).status, 403);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_token_audiences"), 0);
  assert.equal(await count('SELECT count(*) AS n FROM "oauthResource" WHERE "identifier"=?', AUDIENCE), 0);
});

test("an administrator registers the Gatekeeper audience, bound to an app, and the clients that may use it", async () => {
  for (const [body, message] of [
    [{ op: "audience.register", identifier: "http://gatekeeper.example.com/api" }, /audience/],
    [{ op: "audience.register", identifier: ORIGIN + "/mcp" }, /reserved/],
    [{ op: "audience.register", identifier: AUDIENCE, app: "nope" }, /Unknown application/],
    [{ op: "client.kind", clientId: "missing", kind: "agent" }, /Unknown OAuth client/],
    [{ op: "nuke" }, /Unknown token operation/]
  ]) {
    const response = await post("/studio/api/tokens", body, admin.cookie);
    assert.equal(response.status, 409, JSON.stringify(body));
    assert.match((await response.json()).error, message);
  }
  const registered = await post("/studio/api/tokens", { op: "audience.register", identifier: AUDIENCE, app: "billing" }, admin.cookie);
  assert.equal(registered.status, 200, await registered.clone().text());
  assert.equal((await post("/studio/api/tokens", { op: "audience.register", identifier: OTHER_AUDIENCE }, admin.cookie)).status, 200);
  // Re-registering updates Better Auth's resource policy back to Nathan's, even after an out-of-band edit.
  await sql('UPDATE "oauthResource" SET "accessTokenTtl"=3600, "customClaims"=? WHERE "identifier"=?', JSON.stringify({ principal_kind: "user" }), AUDIENCE);
  assert.equal((await post("/studio/api/tokens", { op: "audience.register", identifier: AUDIENCE, app: "billing" }, admin.cookie)).status, 200);
  const resource = await db.prepare('SELECT "accessTokenTtl" AS ttl, "customClaims" AS claims FROM "oauthResource" WHERE "identifier"=?').bind(AUDIENCE).first();
  assert.equal(resource.ttl, 900);
  // Better Auth stores a cleared JSON column as null or "null"; tokens below prove nothing overrides principal_kind.
  assert.ok([null, "null"].includes(resource.claims), String(resource.claims));

  const created = await post("/studio/api/clients", { name: "Billing web", kind: "external", redirectUri: REDIRECT }, admin.cookie);
  assert.equal(created.status, 200, await created.clone().text());
  webClient = await created.json();
  // Test shortcut: consent is Better Auth's own page; the token claims are what this test is about.
  await sql('UPDATE "oauthClient" SET "skipConsent"=1 WHERE "clientId"=?', webClient.client_id);
  for (const identifier of [AUDIENCE, OTHER_AUDIENCE]) {
    const linked = await post("/studio/api/tokens", { op: "audience.link", identifier, clientId: webClient.client_id }, admin.cookie);
    assert.equal(linked.status, 200, await linked.clone().text());
  }

  const machineResponse = await post("/studio/api/tokens", { op: "machine.create", name: "Billing jobs", audience: AUDIENCE }, admin.cookie);
  assert.equal(machineResponse.status, 409, "needs explicit confirmation");
  machine = await (await post("/studio/api/tokens", { op: "machine.create", name: "Billing jobs", audience: AUDIENCE,
    confirm: "CONFIRM MACHINE CLIENT Billing jobs" }, admin.cookie)).json();
  assert.ok(machine.client_id && machine.client_secret, JSON.stringify(machine));
  assert.equal(machine.principalKind, "machine");
  agent = await (await post("/studio/api/tokens", { op: "machine.create", name: "Support agent", audience: AUDIENCE, kind: "agent",
    confirm: "CONFIRM MACHINE CLIENT Support agent" }, admin.cookie)).json();
  assert.equal(agent.principalKind, "agent");
  otherClient = await (await post("/studio/api/tokens", { op: "machine.create", name: "Reports", audience: OTHER_AUDIENCE,
    confirm: "CONFIRM MACHINE CLIENT Reports" }, admin.cookie)).json();

  const overview = await (await mf.dispatchFetch(ORIGIN + "/studio/api/tokens", { headers: { Cookie: admin.cookie } })).json();
  const gk = overview.audiences.find(a => a.identifier === AUDIENCE);
  assert.equal(gk.app, "billing");
  assert.equal(gk.accessTokenTtl, 900);
  assert.deepEqual(new Set(gk.clients), new Set([webClient.client_id, machine.client_id, agent.client_id]));
  assert.equal(overview.clients.find(c => c.id === agent.client_id).principalKind, "agent");
  assert.equal(overview.clients.find(c => c.id === webClient.client_id).principalKind, "auto");

  const audited = (await db.prepare("SELECT action FROM nathan_security_audit WHERE outcome='succeeded' AND actor='admin-1'").all()).results.map(r => r.action);
  for (const action of ["token_audience_register", "token_audience_link", "machine_client_create", "client_principal_kind"])
    assert.ok(audited.includes(action), action + " is audited");
});

test("(a) a user token from authorization code + PKCE carries the Gatekeeper profile and verifies with the documented entry", async () => {
  const body = await authorizationCode(alice);
  tokens.user = body.access_token;
  tokens.id = body.id_token;
  assert.ok(body.expires_in <= 900);
  const [header, claims] = decode(body.access_token);
  assert.equal(header.typ, "at+jwt");
  assert.ok(PROVIDER.algorithms.includes(header.alg), header.alg);
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.sub, "u-alice", "the directory subject is <issuer>#<sub>");
  assert.ok([].concat(claims.aud).includes(AUDIENCE));
  assert.equal(claims.client_id, webClient.client_id);
  assert.ok(claims.jti);
  assert.equal(claims.principal_kind, "user");
  assert.equal(claims.exp - claims.iat, 900);
  assert.deepEqual(claims.roles, ["editor"], "a hint from the evaluator for the audience's app");
  assert.deepEqual(claims.nathan_amr, ["pop"]);
  assert.equal(claims.nathan_acr, "urn:nathan:acr:passkey");
  assert.equal(typeof claims.nathan_auth_time, "number");
  for (const reserved of ["acr", "amr", "auth_time", "nonce", "cnf", "act", "token_use"]) assert.ok(!(reserved in claims), reserved);

  const discovery = await (await mf.dispatchFetch(ISSUER + "/.well-known/openid-configuration")).json();
  assert.equal(discovery.issuer, PROVIDER.issuer, "the documented issuer is the discovered one");
  assert.equal(discovery.jwks_uri, PROVIDER.jwksUri, "the documented jwksUri is the discovered one");
  const principal = await verifyLikeGatekeeper(body.access_token, PROVIDER, await jwks());
  assert.equal(principal.kind, "human");
  assert.equal(principal.subject, "u-alice");
  assert.equal(principal.mfa, false, "Nathan tokens never establish MFA for Gatekeeper");
});

test("a user without passkey evidence or grants gets neither evidence claims nor a roles hint", async () => {
  const [, claims] = decode((await authorizationCode(bob)).access_token);
  assert.equal(claims.principal_kind, "user");
  assert.equal(claims.sub, "u-bob");
  for (const key of ["roles", "nathan_amr", "nathan_acr", "nathan_auth_time"]) assert.ok(!(key in claims), key);
});

test("(b) a client-credentials token is a machine: sub is the client, no roles and no evidence", async () => {
  const token = await clientCredentials(machine);
  assert.equal(token.status, 200, JSON.stringify(token.body));
  tokens.machine = token.body.access_token;
  const [header, claims] = decode(tokens.machine);
  assert.equal(header.typ, "at+jwt");
  assert.equal(claims.principal_kind, "machine");
  assert.equal(claims.sub, machine.client_id);
  assert.equal(claims.client_id, machine.client_id);
  assert.equal(claims.aud, AUDIENCE);
  assert.equal(claims.scope, "nathan:api");
  assert.equal(claims.exp - claims.iat, 900);
  for (const key of ["roles", "nathan_amr", "nathan_acr", "nathan_auth_time", "sid"]) assert.ok(!(key in claims), key);
  const principal = await verifyLikeGatekeeper(tokens.machine, PROVIDER, await jwks());
  assert.equal(principal.kind, "service");
  assert.equal(principal.clientId, machine.client_id);
});

test("(c) an administrator-marked agent client is an agent, for client credentials and for user delegation", async () => {
  const token = await clientCredentials(agent);
  assert.equal(token.status, 200, JSON.stringify(token.body));
  tokens.agent = token.body.access_token;
  assert.equal(decode(tokens.agent)[1].principal_kind, "agent");
  assert.equal((await verifyLikeGatekeeper(tokens.agent, PROVIDER, await jwks())).kind, "agent");

  assert.equal((await post("/studio/api/tokens", { op: "client.kind", clientId: webClient.client_id, kind: "agent" }, admin.cookie)).status, 200);
  const [, delegated] = decode((await authorizationCode(alice)).access_token);
  assert.equal(delegated.principal_kind, "agent", "an agent acting for Alice is never classified as Alice");
  assert.equal(delegated.sub, "u-alice");
  const unconfirmed = await post("/studio/api/tokens", { op: "client.kind", clientId: webClient.client_id, kind: "auto" }, admin.cookie);
  assert.equal(unconfirmed.status, 409, "classifying an agent by grant again widens it and needs confirmation");
  assert.equal((await post("/studio/api/tokens", { op: "client.kind", clientId: webClient.client_id, kind: "auto",
    confirm: "CONFIRM CLASSIFY BY GRANT " + webClient.client_id }, admin.cookie)).status, 200);
  assert.equal(decode((await authorizationCode(alice)).access_token)[1].principal_kind, "user");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='client_principal_kind' AND target LIKE ?", webClient.client_id + "%"), 2);
});

test("the documented entry rejects ID tokens and tokens for another audience", async () => {
  const keys = await jwks();
  await assert.rejects(verifyLikeGatekeeper(tokens.id, PROVIDER, keys), /InvalidCredentials/, "ID token");
  // Even an entry mistakenly set to the client id as audience, with a day-long lifetime limit
  // (Better Auth ID tokens live 10 hours), refuses the ID token by its profile.
  await assert.rejects(verifyLikeGatekeeper(tokens.id, { ...PROVIDER, audience: webClient.client_id, maxTokenLifetimeSeconds: 86400 }, keys), /rfc9068 profile/);
  const other = await clientCredentials(otherClient, OTHER_AUDIENCE);
  assert.equal(other.status, 200, JSON.stringify(other.body));
  assert.equal(decode(other.body.access_token)[1].aud, OTHER_AUDIENCE);
  await assert.rejects(verifyLikeGatekeeper(other.body.access_token, PROVIDER, keys), /InvalidCredentials/, "another audience");
  const otherUser = (await authorizationCode(alice, webClient, OTHER_AUDIENCE)).access_token;
  assert.ok(!("roles" in decode(otherUser)[1]), "an audience without an app gets no roles hint");
  await assert.rejects(verifyLikeGatekeeper(otherUser, PROVIDER, keys), /InvalidCredentials/);
  // A client not linked to the audience cannot get a token for it at all.
  assert.equal((await clientCredentials(otherClient, AUDIENCE)).status, 400);
  // Expired by Gatekeeper's clock: past exp.
  await assert.rejects(verifyLikeGatekeeper(tokens.machine, PROVIDER, keys, Date.now() + 901_000), /InvalidCredentials/);
});

test("every access token Nathan issues is capped at 900 seconds", async () => {
  const directoryClient = await (await post("/studio/api/directory/clients", { name: "PIP", confirm: "CONFIRM DIRECTORY CLIENT PIP" }, admin.cookie)).json();
  const response = await tokenRequest({ grant_type: "client_credentials", scope: "nathan:directory.read" }, directoryClient);
  assert.equal(response.status, 200, JSON.stringify(response.body));
  assert.ok(response.body.expires_in <= 900, "an opaque token without a resource is capped too: " + response.body.expires_in);
});

test("Identity Studio renders the Access tokens section with a script that parses", async () => {
  const html = await (await mf.dispatchFetch(ORIGIN + "/studio", { headers: { Cookie: admin.cookie } })).text();
  assert.match(html, /<h2>Access tokens for Gatekeeper and APIs<\/h2>/);
  const script = html.match(/<script nonce="[^"]+">([\s\S]*)<\/script>/)[1];
  assert.doesNotThrow(() => new Function(script));
  assert.match(script, /\/studio\/api\/tokens/);
});

// Contract test with Gatekeeper's own adapter, copied unmodified out of a read-only checkout so
// that `jose` resolves from this repository. Skipped when no checkout is available.
const GATEKEEPER = process.env.GATEKEEPER_REPO ?? "/Volumes/dev/gatekeeper";
const gatekeeperFiles = ["identity/jwt.ts", "identity/config.ts", "core/model.ts", "principal/model.ts", "net/bounded.ts"];
const haveGatekeeper = gatekeeperFiles.every(f => existsSync(join(GATEKEEPER, "packages", f)));
test("Gatekeeper's own resolver accepts Nathan's user, machine and agent tokens and refuses the ID token", { skip: !haveGatekeeper && "no Gatekeeper checkout (set GATEKEEPER_REPO)" }, async () => {
  const copy = resolve(".nathan/gatekeeper-contract");
  rmSync(copy, { recursive: true, force: true });
  for (const file of gatekeeperFiles) {
    mkdirSync(dirname(join(copy, "packages", file)), { recursive: true });
    copyFileSync(join(GATEKEEPER, "packages", file), join(copy, "packages", file));
  }
  const { createIdentityResolver } = await import(pathToFileURL(join(copy, "packages/identity/jwt.ts")).href);
  const resolver = createIdentityResolver([PROVIDER], { fetcher: (url, init) => mf.dispatchFetch(String(url), { ...init, signal: undefined }) });
  const resolveToken = token => resolver.resolve(new Request("https://gatekeeper.example.com/api/decide", { headers: { Authorization: "Bearer " + token } }));
  const human = await resolveToken(tokens.user);
  assert.equal(human.kind, "human");
  assert.equal(human.subject, "u-alice");
  assert.equal(human.mfa, false);
  assert.equal(human.authentication.clientId, webClient.client_id);
  assert.equal((await resolveToken(tokens.machine)).kind, "service");
  assert.equal((await resolveToken(tokens.agent)).kind, "agent");
  await assert.rejects(resolveToken(tokens.id), e => e.code === "InvalidCredentials");
});

test("unlinking a client and removing an audience stop new tokens for it", async () => {
  assert.equal((await post("/studio/api/tokens", { op: "audience.unlink", identifier: OTHER_AUDIENCE, clientId: otherClient.client_id }, admin.cookie)).status, 200);
  assert.equal((await clientCredentials(otherClient, OTHER_AUDIENCE)).status, 400, "an unlinked client gets invalid_target");
  assert.equal((await post("/studio/api/tokens", { op: "audience.remove", identifier: OTHER_AUDIENCE }, admin.cookie)).status, 409, "needs confirmation");
  const removed = await post("/studio/api/tokens", { op: "audience.remove", identifier: OTHER_AUDIENCE, confirm: "CONFIRM REMOVE AUDIENCE " + OTHER_AUDIENCE }, admin.cookie);
  assert.equal(removed.status, 200, await removed.clone().text());
  const query = new URLSearchParams({ response_type: "code", client_id: webClient.client_id, redirect_uri: REDIRECT, scope: "openid",
    state: "s", code_challenge: "x".repeat(43), code_challenge_method: "S256", resource: OTHER_AUDIENCE });
  const refused = await mf.dispatchFetch(ISSUER + "/oauth2/authorize?" + query, { redirect: "manual", headers: { Cookie: alice.cookie, Accept: "text/html" } });
  const where = refused.status === 200 ? (await refused.json()).url ?? "" : refused.headers.get("Location") ?? "";
  assert.doesNotMatch(where, /[?&]code=/, "no authorization code for a removed audience");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_token_audiences WHERE identifier=?", OTHER_AUDIENCE), 0);
  for (const action of ["token_audience_unlink", "token_audience_remove"])
    assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action=? AND outcome='succeeded'", action), 1, action);
});
