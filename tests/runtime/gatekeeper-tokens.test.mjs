/**
 * NATH-15 in workerd: the built identity Worker mints Gatekeeper-ready access tokens through its
 * real Better Auth token endpoint, for (a) a user via authorization code + PKCE, (b) a machine via
 * client credentials and (c) an administrator-marked agent. Each token is checked against the
 * Gatekeeper provider entry published in docs/gatekeeper.md with Gatekeeper's own resolver (a
 * pinned, unmodified copy in tests/vendor/gatekeeper).
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { authWorker, randomKey, base64url } from "./helpers.mjs";
import { providerEntryFromDocs, gatekeeper, invalidCredentials, vendoredHashes } from "./gatekeeper-verifier.mjs";
import { softwarePasskey, passkeySignIn } from "./passkey-authenticator.mjs";

// The documented entry is used verbatim, so the test install lives at its placeholder host.
const PROVIDER = providerEntryFromDocs();
const HOST = new URL(PROVIDER.issuer).host;
const ORIGIN = "https://" + HOST;
const ISSUER = ORIGIN + "/api/auth";
const AUDIENCE = PROVIDER.audience;
const OTHER_AUDIENCE = "https://reports.example.com/api";
const BILLING_API = "https://billing-api.example.com/api";
const REDIRECT = "https://billing.example.com/callback";
const SECRET = randomKey() + randomKey();
let mf, db, gk;
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
const tokensApi = (body, cookie = admin.cookie) => post("/studio/api/tokens", body, cookie);
const count = async (statement, ...params) => (await db.prepare(statement).bind(...params).first()).n;
/** Form body; array values become repeated parameters (RFC 8707 allows several `resource`s); null and undefined are left out. */
function form(params) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) for (const v of [].concat(value)) if (v !== undefined && v !== null) body.append(key, v);
  return body;
}

let admin, alice, bob, webClient, agentWeb, machine, agent, otherClient;
const tokens = {};
async function tokenRequest(params, client) {
  // This file makes more token requests than the endpoint's 30-per-minute rate limit allows.
  await sql('DELETE FROM "rateLimit"');
  const response = await mf.dispatchFetch(ISSUER + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(client.client_id + ":" + client.client_secret) },
    body: form(params).toString()
  });
  return { status: response.status, body: await response.json() };
}
/** Starts authorization code + PKCE (S256) with resource indicators, as a browser would. Returns the code or the refusal. */
async function authorize(who, { client = webClient, resource = AUDIENCE, scope = "openid profile" } = {}) {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const state = randomKey();
  const query = form({ response_type: "code", client_id: client.client_id, redirect_uri: REDIRECT, scope, state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource });
  const response = await mf.dispatchFetch(ISSUER + "/oauth2/authorize?" + query,
    { redirect: "manual", headers: { Cookie: who.cookie, Accept: "text/html", "Sec-Fetch-Mode": "navigate" } });
  // Better Auth answers either with a 302 or, for fetch-style requests, with {redirect: true, url}.
  let target = response.headers.get("Location");
  if (response.status === 200) target = (await response.clone().json()).url;
  const code = target ? new URL(target, ORIGIN).searchParams.get("code") : null;
  if (code) assert.equal(new URL(target).searchParams.get("state"), state);
  return { code, verifier, status: response.status, target, body: response.status >= 400 ? await response.json() : null };
}
const exchange = (started, { client = webClient, resource = AUDIENCE } = {}) =>
  tokenRequest({ grant_type: "authorization_code", code: started.code, redirect_uri: REDIRECT, code_verifier: started.verifier, resource }, client);
async function authorizationCode(who, options = {}) {
  const started = await authorize(who, options);
  assert.ok(started.code, "no authorization code: " + started.status + " " + (started.target ?? JSON.stringify(started.body)));
  const token = await exchange(started, options);
  assert.equal(token.status, 200, JSON.stringify(token.body));
  return token.body;
}
const refresh = (refreshToken, { client = webClient, resource = AUDIENCE } = {}) =>
  tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken, resource }, client);
const clientCredentials = (client, resource = AUDIENCE) =>
  tokenRequest({ grant_type: "client_credentials", scope: "nathan:api", resource }, client);
async function webClientNamed(name) {
  const created = await post("/studio/api/clients", { name, kind: "external", redirectUri: REDIRECT }, admin.cookie);
  assert.equal(created.status, 200, await created.clone().text());
  const client = await created.json();
  // Test shortcut: consent is Better Auth's own page; the token claims are what this test is about.
  await sql('UPDATE "oauthClient" SET "skipConsent"=1 WHERE "clientId"=?', client.client_id);
  return client;
}
const link = async (identifier, client) => {
  const linked = await tokensApi({ op: "audience.link", identifier, clientId: client.client_id });
  assert.equal(linked.status, 200, await linked.clone().text());
};

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET });
  db = await mf.getD1Database("DB");
  gk = gatekeeper(mf, PROVIDER);
  await user("admin-1", "admin@example.test", "admin");
  await sql("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf','admin@example.test','admin-1','complete')");
  await sql('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (\'pk1\',\'x\',\'admin-1\',\'cred\',0,\'singleDevice\',0)');
  await sql('INSERT INTO "twoFactor"("id","secret","backupCodes","userId","verified") VALUES (\'tf1\',\'x\',\'x\',\'admin-1\',1)');
  admin = await session("admin-1");
  await sql("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES (?,?,'passkey')", admin.id, "admin-1");
  await user("u-alice", "alice@example.test");
  await user("u-bob", "bob@example.test");
  // Alice signs in with a real passkey assertion; the Worker's after-hook records the evidence. Bob has a plain session.
  const passkey = softwarePasskey();
  await sql('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (?,?,?,?,0,\'multiDevice\',1)',
    "pk-alice", passkey.publicKey, "u-alice", passkey.credentialId);
  alice = await passkeySignIn(mf, ORIGIN, passkey, "u-alice");
  bob = await session("u-bob");
  await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('billing','billing.example.com',1,'approved')");
  await sql("INSERT INTO nathan_rbac_permissions(app_id,key) VALUES ('billing','invoices:read'),('billing','invoices:write')");
  await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('billing','editor')");
  await sql("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('billing','editor','invoices:read'),('billing','editor','invoices:write')");
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','billing','editor','user','u-alice','test')");
});

test("the vendored Gatekeeper resolver is the pinned, unmodified copy", () => {
  const files = vendoredHashes();
  assert.equal(files.length, 5);
  for (const { file, recorded, actual } of files) assert.equal(actual, recorded, file + " differs from tests/vendor/gatekeeper/SOURCE.md");
});

test("a real passkey sign-in records the evidence through the Worker's after-hook", async () => {
  const row = await db.prepare("SELECT user_id, method, verified_at FROM nathan_admin_assurance WHERE session_id=?").bind(alice.id).first();
  assert.equal(row?.user_id, "u-alice");
  assert.equal(row.method, "passkey");
  assert.ok(Math.abs(row.verified_at - Date.now() / 1000) < 60, String(row.verified_at));
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
    const response = await tokensApi(body);
    assert.equal(response.status, 409, JSON.stringify(body));
    assert.match((await response.json()).error, message);
  }
  const registered = await tokensApi({ op: "audience.register", identifier: AUDIENCE, app: "billing" });
  assert.equal(registered.status, 200, await registered.clone().text());
  assert.equal((await tokensApi({ op: "audience.register", identifier: OTHER_AUDIENCE })).status, 200);
  assert.equal((await tokensApi({ op: "audience.register", identifier: BILLING_API, app: "billing" })).status, 200);
  // Re-registering updates Better Auth's resource policy back to Nathan's, even after an out-of-band edit.
  await sql('UPDATE "oauthResource" SET "accessTokenTtl"=3600, "customClaims"=? WHERE "identifier"=?', JSON.stringify({ principal_kind: "user" }), AUDIENCE);
  assert.equal((await tokensApi({ op: "audience.register", identifier: AUDIENCE, app: "billing" })).status, 200);
  const resource = await db.prepare('SELECT "accessTokenTtl" AS ttl, "customClaims" AS claims FROM "oauthResource" WHERE "identifier"=?').bind(AUDIENCE).first();
  assert.equal(resource.ttl, 900);
  // Better Auth stores a cleared JSON column as null or "null"; tokens below prove nothing overrides principal_kind.
  assert.ok([null, "null"].includes(resource.claims), String(resource.claims));

  webClient = await webClientNamed("Billing web");
  agentWeb = await webClientNamed("Support agent web");
  for (const identifier of [AUDIENCE, OTHER_AUDIENCE, BILLING_API]) await link(identifier, webClient);
  await link(AUDIENCE, agentWeb);
  assert.equal((await tokensApi({ op: "client.kind", clientId: agentWeb.client_id, kind: "agent" })).status, 200);

  const machineResponse = await tokensApi({ op: "machine.create", name: "Billing jobs", audience: AUDIENCE });
  assert.equal(machineResponse.status, 409, "needs explicit confirmation");
  machine = await (await tokensApi({ op: "machine.create", name: "Billing jobs", audience: AUDIENCE,
    confirm: "CONFIRM MACHINE CLIENT Billing jobs" })).json();
  assert.ok(machine.client_id && machine.client_secret, JSON.stringify(machine));
  assert.equal(machine.principalKind, "machine");
  agent = await (await tokensApi({ op: "machine.create", name: "Support agent", audience: AUDIENCE, kind: "agent",
    confirm: "CONFIRM MACHINE CLIENT Support agent" })).json();
  assert.equal(agent.principalKind, "agent");
  otherClient = await (await tokensApi({ op: "machine.create", name: "Reports", audience: OTHER_AUDIENCE,
    confirm: "CONFIRM MACHINE CLIENT Reports" })).json();

  const overview = await (await mf.dispatchFetch(ORIGIN + "/studio/api/tokens", { headers: { Cookie: admin.cookie } })).json();
  const entry = overview.audiences.find(a => a.identifier === AUDIENCE);
  assert.equal(entry.app, "billing");
  assert.equal(entry.accessTokenTtl, 900);
  assert.deepEqual(new Set(entry.clients), new Set([webClient.client_id, agentWeb.client_id, machine.client_id, agent.client_id]));
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
  assert.equal(claims.sid, alice.id);
  assert.ok(claims.jti);
  assert.equal(claims.principal_kind, "user");
  assert.equal(claims.exp - claims.iat, 900);
  assert.deepEqual(claims.roles, ["editor"], "a hint from the evaluator for the audience's app");
  // From the evidence row the passkey after-hook wrote for this session.
  assert.deepEqual(claims.nathan_amr, ["pop"]);
  assert.equal(claims.nathan_acr, "urn:nathan:acr:passkey");
  assert.equal(claims.nathan_auth_time, (await db.prepare("SELECT verified_at AS t FROM nathan_admin_assurance WHERE session_id=?").bind(alice.id).first()).t);
  for (const reserved of ["acr", "amr", "auth_time", "nonce", "cnf", "act", "token_use"]) assert.ok(!(reserved in claims), reserved);

  const discovery = await (await mf.dispatchFetch(ISSUER + "/.well-known/openid-configuration")).json();
  assert.equal(discovery.issuer, PROVIDER.issuer, "the documented issuer is the discovered one");
  assert.equal(discovery.jwks_uri, PROVIDER.jwksUri, "the documented jwksUri is the discovered one");
  const principal = await gk(body.access_token);
  assert.equal(principal.kind, "human");
  assert.equal(principal.subject, "u-alice");
  assert.equal(principal.id, "principal:" + encodeURIComponent(ISSUER) + ":sub:u-alice", "Gatekeeper's principal id carries no kind");
  assert.equal(principal.mfa, false, "Nathan tokens never establish MFA for Gatekeeper");
  assert.equal(principal.authentication.clientId, webClient.client_id);
  assert.deepEqual(principal.authentication.scopes, ["openid", "profile"]);
  // Even an entry that maps Nathan's passkey ACR to MFA gets no MFA: Nathan never emits `acr`/`auth_time`.
  const mfaEntry = { ...PROVIDER, mfa: { acrValues: ["urn:nathan:acr:passkey"], maxAgeSeconds: 3600 } };
  assert.equal((await gatekeeper(mf, mfaEntry)(body.access_token)).mfa, false);
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
  const principal = await gk(tokens.machine);
  assert.equal(principal.kind, "service");
  assert.equal(principal.authentication.clientId, machine.client_id);
  assert.deepEqual(principal.authentication.scopes, ["nathan:api"]);
});

test("(c) an administrator-marked agent client is an agent, for client credentials and for user delegation", async () => {
  const token = await clientCredentials(agent);
  assert.equal(token.status, 200, JSON.stringify(token.body));
  tokens.agent = token.body.access_token;
  assert.equal(decode(tokens.agent)[1].principal_kind, "agent");
  assert.equal((await gk(tokens.agent)).kind, "agent");

  assert.equal((await tokensApi({ op: "client.kind", clientId: webClient.client_id, kind: "agent" })).status, 200);
  const [, delegated] = decode((await authorizationCode(alice)).access_token);
  assert.equal(delegated.principal_kind, "agent", "an agent acting for Alice is never classified as Alice");
  assert.equal(delegated.sub, "u-alice");
  const unconfirmed = await tokensApi({ op: "client.kind", clientId: webClient.client_id, kind: "auto" });
  assert.equal(unconfirmed.status, 409, "classifying an agent by grant again widens it and needs confirmation");
  assert.equal((await tokensApi({ op: "client.kind", clientId: webClient.client_id, kind: "auto",
    confirm: "CONFIRM CLASSIFY BY GRANT " + webClient.client_id })).status, 200);
  assert.equal(decode((await authorizationCode(alice)).access_token)[1].principal_kind, "user");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='client_principal_kind' AND target LIKE ?", webClient.client_id + "%"), 2);
});

test("the documented entry rejects ID tokens and tokens for another audience", async () => {
  await assert.rejects(gk(tokens.id), invalidCredentials, "ID token");
  // Even an entry mistakenly set to the client id as audience, with a day-long lifetime limit
  // (Better Auth ID tokens live 10 hours), refuses the ID token: it has no `typ: at+jwt` (RFC 9068 profile).
  assert.equal(decode(tokens.id)[0].typ, undefined);
  await assert.rejects(gatekeeper(mf, { ...PROVIDER, audience: webClient.client_id, maxTokenLifetimeSeconds: 86400 })(tokens.id), invalidCredentials);
  const other = await clientCredentials(otherClient, OTHER_AUDIENCE);
  assert.equal(other.status, 200, JSON.stringify(other.body));
  assert.equal(decode(other.body.access_token)[1].aud, OTHER_AUDIENCE);
  await assert.rejects(gk(other.body.access_token), invalidCredentials, "another audience");
  const otherUser = (await authorizationCode(alice, { resource: OTHER_AUDIENCE })).access_token;
  assert.ok(!("roles" in decode(otherUser)[1]), "an audience without an app gets no roles hint");
  await assert.rejects(gk(otherUser), invalidCredentials);
  // A client not linked to the audience cannot get a token for it at all.
  assert.equal((await clientCredentials(otherClient, AUDIENCE)).status, 400);
  // Expired by Gatekeeper's clock: past exp.
  await assert.rejects(gatekeeper(mf, PROVIDER, { now: () => Date.now() + 901_000 })(tokens.machine), invalidCredentials);
});

test("several API audiences in one request: roles only when every audience is bound to the same app", async () => {
  // Gatekeeper's audience (bound to billing) together with an unbound audience: no roles hint for either.
  const mixed = await authorizationCode(alice, { resource: [AUDIENCE, OTHER_AUDIENCE] });
  const [, mixedClaims] = decode(mixed.access_token);
  assert.ok([AUDIENCE, OTHER_AUDIENCE].every(a => [].concat(mixedClaims.aud).includes(a)), JSON.stringify(mixedClaims.aud));
  assert.ok(!("roles" in mixedClaims), "billing roles must not reach the unbound audience");
  assert.equal(mixedClaims.principal_kind, "user");
  assert.equal((await gk(mixed.access_token)).kind, "human", "Gatekeeper still accepts its audience");
  // Two audiences both bound to billing: the hint is billing's.
  const [, sameApp] = decode((await authorizationCode(alice, { resource: [AUDIENCE, BILLING_API] })).access_token);
  assert.deepEqual(sameApp.roles, ["editor"]);
  // Bound to a different app: none.
  await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('crm','crm.example.com',1,'approved')");
  await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('crm','editor')");
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g-crm','crm','editor','user','u-alice','test')");
  assert.equal((await tokensApi({ op: "audience.register", identifier: OTHER_AUDIENCE, app: "crm" })).status, 200);
  const [, crossApp] = decode((await authorizationCode(alice, { resource: [AUDIENCE, OTHER_AUDIENCE] })).access_token);
  assert.ok(!("roles" in crossApp), "one app's roles never go to a differently bound audience");
  assert.equal((await tokensApi({ op: "audience.register", identifier: OTHER_AUDIENCE })).status, 200, "unbind again");
});

test("a refresh mints user tokens only while the user's session is live", async () => {
  const signedIn = await session("u-alice");
  const scope = "openid profile offline_access";
  const first = await authorizationCode(signedIn, { scope });
  assert.ok(first.refresh_token, "offline_access gives a refresh token");
  const refreshed = await refresh(first.refresh_token);
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
  const [, claims] = decode(refreshed.body.access_token);
  assert.equal(claims.principal_kind, "user");
  assert.equal(claims.sid, signedIn.id);
  assert.deepEqual(claims.roles, ["editor"]);
  assert.equal(claims.exp - claims.iat, 900, "the 900 s cap holds for refreshed tokens");
  assert.ok(refreshed.body.expires_in <= 900);

  // Signing out (Better Auth deletes the session row) ends the grant: no more user tokens.
  await sql('DELETE FROM "session" WHERE "id"=?', signedIn.id);
  const afterSignOut = await refresh(refreshed.body.refresh_token);
  assert.equal(afterSignOut.status, 400, JSON.stringify(afterSignOut.body));
  assert.equal(afterSignOut.body.error, "invalid_grant");

  // An expired session ends it too.
  const expiring = await session("u-alice");
  const second = await authorizationCode(expiring, { scope });
  await sql('UPDATE "session" SET "expiresAt"=? WHERE "id"=?', new Date(Date.now() - 1000).toISOString(), expiring.id);
  const afterExpiry = await refresh(second.refresh_token);
  assert.equal(afterExpiry.status, 400);
  assert.equal(afterExpiry.body.error, "invalid_grant");

  // A banned user gets nothing, even with a live session row and a fresh authorization code.
  const live = await session("u-alice");
  const third = await authorizationCode(live, { scope });
  const code = await authorize(live);
  await sql('UPDATE "user" SET "banned"=1 WHERE "id"=?', "u-alice");
  try {
    for (const response of [await refresh(third.refresh_token), await exchange(code)]) {
      assert.equal(response.status, 400, JSON.stringify(response.body));
      assert.equal(response.body.error, "invalid_grant");
    }
  } finally {
    await sql('UPDATE "user" SET "banned"=0 WHERE "id"=?', "u-alice");
  }
  assert.equal((await refresh(third.refresh_token)).status, 200, "the grant itself was not consumed by the refusal");
});

test("an agent's delegated refresh outlives the browser session but not a ban", async () => {
  const signedIn = await session("u-alice");
  const first = await authorizationCode(signedIn, { client: agentWeb, scope: "openid offline_access" });
  await sql('DELETE FROM "session" WHERE "id"=?', signedIn.id);
  const refreshed = await refresh(first.refresh_token, { client: agentWeb });
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
  const [, claims] = decode(refreshed.body.access_token);
  assert.equal(claims.principal_kind, "agent", "offline agent access is an agent token, never a user token");
  assert.equal(claims.sub, "u-alice");
  assert.ok(!claims.sid && !("nathan_amr" in claims), "no session, no session evidence");
  await sql('UPDATE "user" SET "banned"=1 WHERE "id"=?', "u-alice");
  try {
    const banned = await refresh(refreshed.body.refresh_token, { client: agentWeb });
    assert.equal(banned.status, 400);
    assert.equal(banned.body.error, "invalid_grant");
  } finally {
    await sql('UPDATE "user" SET "banned"=0 WHERE "id"=?', "u-alice");
  }
});

test("nathan:api is never delegated by a user through a client not marked agent", async () => {
  // Asked for explicitly, or implied by an omitted scope (Better Auth's default is every scope).
  for (const scope of ["openid nathan:api", null]) {
    const refused = await authorize(alice, { scope });
    assert.equal(refused.code, null, "no authorization code for scope " + scope);
    assert.equal(refused.status, 400, refused.target ?? "");
    assert.equal(refused.body.error, "invalid_scope");
  }
  // An administrator-marked agent client may ask for it on behalf of a user.
  const delegated = await authorizationCode(alice, { client: agentWeb, scope: "openid nathan:api offline_access" });
  const [, claims] = decode(delegated.access_token);
  assert.equal(claims.principal_kind, "agent");
  assert.ok(claims.scope.split(" ").includes("nathan:api"));
  assert.ok((await gk(delegated.access_token)).authentication.scopes.includes("nathan:api"));

  // Code issued while the client was an agent, exchanged after it is classified by grant again: refused.
  const pending = await authorize(alice, { client: agentWeb, scope: "openid nathan:api" });
  assert.ok(pending.code);
  assert.equal((await tokensApi({ op: "client.kind", clientId: agentWeb.client_id, kind: "auto",
    confirm: "CONFIRM CLASSIFY BY GRANT " + agentWeb.client_id })).status, 200);
  const exchanged = await exchange(pending, { client: agentWeb });
  assert.equal(exchanged.status, 400, JSON.stringify(exchanged.body));
  assert.equal(exchanged.body.error, "invalid_scope");
  // Its outstanding nathan:api refresh tokens were revoked with the change.
  const refreshed = await refresh(delegated.refresh_token, { client: agentWeb });
  assert.equal(refreshed.status, 400, JSON.stringify(refreshed.body));
  assert.equal(await count('SELECT count(*) AS n FROM "oauthRefreshToken" WHERE "clientId"=? AND instr("scopes",\'nathan:api\')>0', agentWeb.client_id), 0);
  assert.equal((await tokensApi({ op: "client.kind", clientId: agentWeb.client_id, kind: "agent" })).status, 200);
});

test("every access token Nathan issues is capped at 900 seconds", async () => {
  // An opaque client-credentials token without a resource.
  const directoryClient = await (await post("/studio/api/directory/clients", { name: "PIP", confirm: "CONFIRM DIRECTORY CLIENT PIP" }, admin.cookie)).json();
  const response = await tokenRequest({ grant_type: "client_credentials", scope: "nathan:directory.read" }, directoryClient);
  assert.equal(response.status, 200, JSON.stringify(response.body));
  assert.ok(response.body.expires_in <= 900, "an opaque token without a resource is capped too: " + response.body.expires_in);
  // A user grant without a resource (opaque access token).
  const opaque = await authorizationCode(bob, { resource: null });
  assert.equal(opaque.access_token.split(".").length, 1, "no resource: an opaque token");
  assert.ok(opaque.expires_in <= 900, "user grant without a resource: " + opaque.expires_in);
  // A resource whose configured lifetime is longer (an out-of-band edit) still gets 900 s at most.
  await sql('UPDATE "oauthResource" SET "accessTokenTtl"=86400 WHERE "identifier"=?', AUDIENCE);
  try {
    const user = await authorizationCode(bob);
    const [, userClaims] = decode(user.access_token);
    assert.equal(userClaims.exp - userClaims.iat, 900);
    const service = await clientCredentials(machine);
    const [, serviceClaims] = decode(service.body.access_token);
    assert.equal(serviceClaims.exp - serviceClaims.iat, 900);
  } finally {
    await sql('UPDATE "oauthResource" SET "accessTokenTtl"=900 WHERE "identifier"=?', AUDIENCE);
  }
});

test("Identity Studio renders the Access tokens section with a script that parses", async () => {
  const html = await (await mf.dispatchFetch(ORIGIN + "/studio", { headers: { Cookie: admin.cookie } })).text();
  assert.match(html, /<h2>Access tokens for Gatekeeper and APIs<\/h2>/);
  const script = html.match(/<script nonce="[^"]+">([\s\S]*)<\/script>/)[1];
  assert.doesNotThrow(() => new Function(script));
  assert.match(script, /\/studio\/api\/tokens/);
});

test("unlinking a client stops new tokens for it", async () => {
  assert.equal((await tokensApi({ op: "audience.unlink", identifier: OTHER_AUDIENCE, clientId: otherClient.client_id })).status, 200);
  assert.equal((await clientCredentials(otherClient, OTHER_AUDIENCE)).status, 400, "an unlinked client gets invalid_target");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='token_audience_unlink' AND outcome='succeeded'"), 1);
});

test("removing an audience drops its client links, so re-registering it does not restore old clients", async () => {
  const JOBS = "https://jobs.example.com/api";
  assert.equal((await tokensApi({ op: "audience.register", identifier: JOBS })).status, 200);
  const jobs = await (await tokensApi({ op: "machine.create", name: "Jobs", audience: JOBS, confirm: "CONFIRM MACHINE CLIENT Jobs" })).json();
  await link(JOBS, webClient);
  assert.equal((await clientCredentials(jobs, JOBS)).status, 200, "linked machine client works before removal");
  const signedIn = await session("u-bob");
  const grant = await authorizationCode(signedIn, { resource: JOBS, scope: "openid offline_access" });

  assert.equal((await tokensApi({ op: "audience.remove", identifier: JOBS })).status, 409, "needs confirmation");
  const removed = await tokensApi({ op: "audience.remove", identifier: JOBS, confirm: "CONFIRM REMOVE AUDIENCE " + JOBS });
  assert.equal(removed.status, 200, await removed.clone().text());
  assert.equal((await removed.json()).unlinkedClients, 2);
  assert.equal(await count('SELECT count(*) AS n FROM "oauthClientResource" WHERE "resourceId"=?', JOBS), 0);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_token_audiences WHERE identifier=?", JOBS), 0);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='token_audience_remove' AND outcome='succeeded' AND target=?", JOBS + " unlinked=2"), 1);
  assert.equal((await clientCredentials(jobs, JOBS)).status, 400, "removed audience");
  const refused = await authorize(alice, { resource: JOBS, scope: "openid" });
  assert.equal(refused.code, null, "no authorization code for a removed audience");

  // Registering the same identifier again starts with no clients.
  assert.equal((await tokensApi({ op: "audience.register", identifier: JOBS })).status, 200);
  const overview = await (await mf.dispatchFetch(ORIGIN + "/studio/api/tokens", { headers: { Cookie: admin.cookie } })).json();
  assert.deepEqual(overview.audiences.find(a => a.identifier === JOBS).clients, []);
  const again = await clientCredentials(jobs, JOBS);
  assert.equal(again.status, 400, "the old machine client cannot get tokens: " + JSON.stringify(again.body));
  assert.equal(again.body.error, "invalid_target");
  const oldRefresh = await refresh(grant.refresh_token, { resource: JOBS });
  assert.equal(oldRefresh.status, 400, "the old user grant cannot refresh into the re-registered audience: " + JSON.stringify(oldRefresh.body));
});
