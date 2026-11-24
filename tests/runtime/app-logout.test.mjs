import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter, once } from "node:events";
import { readdirSync } from "node:fs";
import { SignJWT, createLocalJWKSet, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { symmetricDecrypt } from "better-auth/crypto";
import { bundle, COMPAT, insertSession, migrate, randomKey, start } from "./helpers.mjs";

const origin = "https://school.example.test", issuer = origin + "/api/auth", resource = origin + "/api";
const client = "cc-web", secret = randomKey(), issuerSecret = randomKey(), target = origin + "/sign-in";
const hash = value => createHash("sha256").update(value).digest("base64url");
let mf, db;
const backchannel = origin + "/auth/backchannel", deliveries = [];
const receiver = new EventEmitter();
const sql = (statement, ...args) => db.prepare(statement).bind(...args).run();
const one = (statement, ...args) => db.prepare(statement).bind(...args).first();
const get = (path, options = {}) => mf.dispatchFetch(origin + path, { redirect: "manual", ...options });
const exists = sessionId => one("SELECT id FROM session WHERE id=?", sessionId);
const endPath = "/api/auth/oauth2/end-session";
const end = (params, cookie, overrides = {}) => get(endPath, { method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin, Cookie: cookie, Accept: "text/html", ...overrides },
  body: new URLSearchParams(params).toString() });

before(async () => {
  mf = await start({ workers: [
    { name: "classcheck", ...COMPAT, modules: true, routes: ["school.example.test/*"], script: "export default {fetch(r,e){return e.AUTH.fetch(r)}}",
      serviceBindings: { AUTH: { name: "auth", entrypoint: "NathanAppAuth", props: { applicationId: "classcheck" } } } },
    { name: "auth", ...COMPAT, modules: true, scriptPath: bundle("auth"),
      d1Databases: { DB: "app-logout" }, durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
      outboundService: async request => {
        assert.equal(request.url, backchannel, "the private issuer resolves its own signing keys locally");
        deliveries.push(new URLSearchParams(await request.text()).get("logout_token"));
        receiver.emit("delivery");
        return new Response(null, { status: 204 });
      },
      bindings: { BETTER_AUTH_SECRET: issuerSecret, NATHAN_CONFIG_KEY: randomKey(), NATHAN_ISSUER: "https://management.example.test",
        NATHAN_APP_ORIGIN: origin, NATHAN_APP_ID: "classcheck", NATHAN_ACCESS_TEAM_DOMAIN: "test.cloudflareaccess.com", NATHAN_ACCESS_AUD: "a".repeat(64),
        NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_STEPUP_REQUIRED: "true", NATHAN_INSTALL_ACTIVE: "true", NATHAN_ADMIN_EMAILS: "owner@example.test",
        NATHAN_PAIRWISE_SECRET: randomKey(), ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false" } }
  ] });
  db = await mf.getD1Database("DB", "auth");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(db, "migrations/" + file);
  await sql("INSERT INTO nathan_applications(id,hostname,enabled) VALUES ('classcheck','school.example.test',1)");
  await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('classcheck','member')");
  await sql("INSERT INTO oauthResource(id,identifier,name,allowedScopes,accessTokenTtl,disabled) VALUES ('api',?,'API',?,900,0)", resource, '["openid","email","offline_access","nathan:api"]');
  await sql("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,'classcheck','operator')", resource);
  await sql("INSERT INTO oauthClient(id,clientId,clientSecret,redirectUris,postLogoutRedirectUris,enableEndSession,skipConsent,requirePKCE,tokenEndpointAuthMethod,grantTypes,scopes) " +
    "VALUES ('cc',?,?,?,?,1,1,1,'client_secret_basic',?,?)", client, hash(secret), JSON.stringify([origin + "/auth/callback"]), JSON.stringify([target]), '["authorization_code","refresh_token"]', '["openid","email","offline_access"]');
  await sql("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES ('link',?,?)", client,resource);
});
after(() => mf?.dispose());

async function grant(scope = "openid email", existing, rpClient = client) {
  const sub = existing?.sub ?? crypto.randomUUID(), now = new Date().toISOString(), verifier = randomKey();
  if (!existing) {
    await sql("INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES (?,'Member',?,1,?,?)", sub,sub + "@example.test",now,now);
    await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES (?,'classcheck','member','user',?,'test')", crypto.randomUUID(),sub);
  }
  const session = existing ?? await insertSession(db,issuerSecret,sub);
  const nonce = randomKey(), state = randomKey(), callback = origin + "/auth/callback";
  const query = new URLSearchParams({ client_id: rpClient, redirect_uri: callback, resource, response_type: "code", scope,
    state, nonce, code_challenge: hash(verifier), code_challenge_method: "S256" });
  const response = await get("/api/auth/oauth2/authorize?" + query, { headers: { Cookie: session.cookie, Accept: "application/json" } });
  const location = new URL(response.headers.get("location") ?? (await response.json()).url);
  assert.equal(location.origin + location.pathname, callback);
  const exchanged = await get("/api/auth/oauth2/token", { method: "POST", headers: {
    "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(rpClient + ":" + secret)
  }, body: new URLSearchParams({ client_id: rpClient, grant_type: "authorization_code", code: location.searchParams.get("code"),
    redirect_uri: callback, resource, code_verifier: verifier }).toString() });
  assert.equal(exchanged.status, 200);
  const tokens = await exchanged.json();
  assert.equal(decodeJwt(tokens.id_token).sid, session.id);
  return { ...session, sub, tokens, params: { client_id: rpClient, id_token_hint: tokens.id_token, post_logout_redirect_uri: target } };
}

test("discovery advertises the private end-session operation and a real ID token ends only its current browser session", async () => {
  const metadata = await (await get("/api/auth/.well-known/openid-configuration")).json();
  assert.equal(metadata.end_session_endpoint, origin + endPath);
  const a = await grant(), other = await grant(), state = "return+/=&";
  const keys = createLocalJWKSet(await (await get("/api/auth/jwks")).json());
  const { payload } = await jwtVerify(a.tokens.access_token, keys, { issuer, audience: resource, typ: "at+jwt", algorithms: ["EdDSA"] });
  assert.equal(payload.principal_kind, "user");
  assert.equal(payload.sub, a.sub);
  assert.equal(payload.client_id, client);
  assert.equal(payload.sid, a.id);
  assert.ok(payload.aud.includes(issuer + "/oauth2/userinfo"));
  assert.ok(payload.exp - payload.iat <= 900);
  const profile = await (await get("/api/auth/oauth2/userinfo", { headers: { Authorization: "Bearer " + a.tokens.access_token } })).json();
  assert.deepEqual(profile, { sub: a.sub, email: a.sub + "@example.test", email_verified: true });
  const response = await end({ ...a.params, state }, a.cookie + "; classcheck_session=local-only");
  assert.equal(response.status, 200, response.ok ? "" : await response.clone().text());
  const expected = new URL(target);
  expected.searchParams.set("state", state);
  assert.deepEqual(await response.json(), { url: expected.href });
  assert.match(response.headers.get("Cache-Control"), /no-store/);
  assert.ok(response.headers.getSetCookie().some(cookie => /^__Secure-nathan\.session_token=;/.test(cookie)));
  assert.equal(response.headers.getSetCookie().some(cookie => cookie.startsWith("classcheck_") || /;\s*Domain=/i.test(cookie)), false);
  assert.equal(await exists(a.id), null);
  assert.ok(await exists(other.id));
  const info = await get("/api/auth/oauth2/userinfo", { headers: { Authorization: "Bearer " + a.tokens.access_token } });
  assert.equal(info.status, 401);
});

test("hinted logout stops refresh and signs the registered client's back-channel session notification", async () => {
  await sql("UPDATE oauthClient SET backchannelLogoutUri=?", backchannel);
  try {
    const a = await grant("openid email offline_access");
    assert.ok(a.tokens.refresh_token);
    const sent = once(receiver, "delivery", { signal: AbortSignal.timeout(8000) });
    assert.equal((await end(a.params, a.cookie)).status, 200);
    const refresh = await get("/api/auth/oauth2/token", { method: "POST", headers: {
      "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(client + ":" + secret)
    }, body: new URLSearchParams({ client_id: client, grant_type: "refresh_token", refresh_token: a.tokens.refresh_token, resource }).toString() });
    assert.equal(refresh.status, 400);
    assert.equal((await refresh.json()).error, "invalid_grant");
    await sent;
    assert.equal(deliveries.length, 1);
    const keys = createLocalJWKSet(await (await get("/api/auth/jwks")).json());
    const { payload } = await jwtVerify(deliveries[0], keys, { issuer, audience: client, typ: "logout+jwt", algorithms: ["EdDSA"] });
    assert.equal(payload.sub, a.sub);
    assert.equal(payload.sid, a.id);
    assert.deepEqual(payload.events, { "http://schemas.openid.net/event/backchannel-logout": {} });
    assert.equal(payload.nonce, undefined);
    assert.ok(payload.jti);
  } finally {
    await sql("UPDATE oauthClient SET backchannelLogoutUri=NULL");
  }
});

test("a registered district client gets a stage-bound machine token and cannot use UserInfo", async () => {
  const district = "classcheck-district", credential = randomKey();
  await sql("INSERT INTO oauthClient(id,clientId,clientSecret,redirectUris,tokenEndpointAuthMethod,grantTypes,scopes,clientCredentialsScopes) " +
    "VALUES ('district',?,?,'[]','client_secret_basic','[\"client_credentials\"]','[\"nathan:api\"]','[\"nathan:api\"]')", district, hash(credential));
  await sql("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES ('district-link',?,?)", district,resource);
  const exchange = target => get("/api/auth/oauth2/token", { method: "POST", headers: {
    "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(district + ":" + credential)
  }, body: new URLSearchParams({ client_id: district, grant_type: "client_credentials", scope: "nathan:api", resource: target }).toString() });
  const denied = await exchange("https://other.example.test/api");
  assert.equal(denied.status, 400);
  assert.equal((await denied.json()).error, "invalid_target");
  const response = await exchange(resource);
  assert.equal(response.status, 200, response.ok ? "" : await response.clone().text());
  const { access_token } = await response.json();
  const jwks = createLocalJWKSet(await (await get("/api/auth/jwks")).json());
  const { payload } = await jwtVerify(access_token, jwks, { algorithms: ["EdDSA"], typ: "at+jwt", issuer, audience: resource });
  assert.equal(payload.aud, resource);
  assert.equal(payload.sub, district);
  assert.equal(payload.client_id, district);
  assert.equal(payload.principal_kind, "machine");
  assert.equal(payload.scope, "nathan:api");
  assert.equal(payload.sid, undefined);
  assert.equal((await get("/api/auth/oauth2/userinfo", { headers: { Authorization: "Bearer " + access_token } })).status, 401);
});

test("an invalid hint, client binding, return URL or browser context leaves the session intact", async () => {
  const a = await grant(), other = await grant();
  for (const [params, cookie] of [
    [{ ...a.params, id_token_hint: "" }, a.cookie], [{ ...a.params, id_token_hint: a.tokens.access_token }, a.cookie],
    [{ ...a.params, client_id: "other-client" }, a.cookie], [{ ...a.params, post_logout_redirect_uri: target + "?redirect=other" }, a.cookie],
    [{ ...a.params, post_logout_redirect_uri: "https://management.example.test/sign-in" }, a.cookie], [a.params, other.cookie], [a.params, ""],
    [[...Object.entries(a.params), ["client_id",client]], a.cookie], [{ ...a.params, state: "x".repeat(2049) }, a.cookie],
    [{ ...a.params, state: "unauthorized\nheader" }, a.cookie], [{ ...a.params, extra: "ignored" }, a.cookie]
  ]) {
    const result = await end(params,cookie);
    assert.ok(result.status >= 400);
    assert.match(result.headers.get("content-type"), /application\/json/);
    assert.equal(result.headers.getSetCookie().length, 0);
    assert.equal(result.headers.get("location"), null);
    assert.ok(await exists(a.id));
    assert.ok(await exists(other.id));
  }
  assert.equal((await end(a.params,a.cookie,{Origin:"https://elsewhere.example.test"})).status, 403);
  assert.equal((await get(endPath + "?client_id=cc-web")).status, 405);
  assert.equal((await get(endPath + "/confirm")).status, 404);
  assert.equal((await get(endPath + "?state=query", { method: "POST", headers: { Origin: origin, Cookie: a.cookie,
    "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(a.params).toString() })).status, 400);
  for (const [off,on] of [
    ["UPDATE oauthClient SET enableEndSession=0","UPDATE oauthClient SET enableEndSession=1"],
    ["UPDATE oauthResource SET disabled=1","UPDATE oauthResource SET disabled=0"],
    ["UPDATE oauthClient SET postLogoutRedirectUris='broken'","UPDATE oauthClient SET postLogoutRedirectUris=json_array('" + target + "')"],
    ["UPDATE oauthClient SET subjectType='pairwise'","UPDATE oauthClient SET subjectType='public'"]
  ]) {
    await sql(off);
    try {
      assert.equal((await end(a.params,a.cookie)).status, 400);
      const metadata = await (await get("/api/auth/.well-known/openid-configuration")).json();
      assert.equal(metadata.end_session_endpoint, undefined);
    } finally { await sql(on); }
    assert.ok(await exists(a.id));
  }
});

test("a recently expired signed ID hint is usable for its live session; other signed token profiles and stale hints are refused", async () => {
  const a = await grant(), header = decodeProtectedHeader(a.tokens.id_token), original = decodeJwt(a.tokens.id_token);
  const stored = await one("SELECT privateKey FROM jwks WHERE id=?",header.kid);
  const privateKey = await importJWK(JSON.parse(await symmetricDecrypt({ key: issuerSecret, data: JSON.parse(stored.privateKey) })), "EdDSA");
  const now = Math.floor(Date.now()/1000);
  const signed = (claims, typ) => new SignJWT(claims).setProtectedHeader({alg:"EdDSA",kid:header.kid,...(typ ? {typ} : {})}).sign(privateKey);
  for (const [claims, typ] of [
    [{ ...original, iat: now - 8*86400, exp: now - 7*86400 }, undefined], [{ ...original, iat: now + 86400 }, undefined],
    [{ ...original, iss: "https://management.example.test/api/auth" }, undefined], [{ ...original, azp: "another-client" }, undefined],
    [{ ...original, sub: "other" }, undefined], [{ ...original, client_id: client, scope: "openid" }, "at+jwt"],
    [{ ...original, events: {} }, "logout+jwt"], [{ ...original, at_hash: undefined }, undefined]
  ]) {
    const result = await end({ ...a.params, id_token_hint: await signed(claims,typ) },a.cookie);
    assert.ok(result.status >= 400);
    assert.ok(await exists(a.id));
  }
  const expired = await signed({ ...original, iat: now - 36_100, exp: now - 100 },undefined);
  assert.equal((await end({ ...a.params, id_token_hint: expired },a.cookie)).status, 200);
  assert.equal(await exists(a.id), null);
});

test("a failed session deletion retains the browser credential and reports a retryable failure", async () => {
  const a = await grant();
  const previous = deliveries.length;
  await sql("UPDATE oauthClient SET backchannelLogoutUri=?", backchannel);
  await sql("CREATE TRIGGER test_refuse_logout BEFORE DELETE ON session BEGIN SELECT RAISE(ABORT,'session store unavailable'); END");
  try {
    const response = await end(a.params, a.cookie);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "temporarily_unavailable" });
    assert.equal(response.headers.getSetCookie().length, 0);
    assert.ok(await exists(a.id));
    await (await mf.getWorker("auth")).scheduled({ cron: "0 5 * * *" });
    assert.equal(deliveries.length, previous);
  } finally {
    await sql("DROP TRIGGER test_refuse_logout");
  }
  try {
    const sent = once(receiver, "delivery", { signal: AbortSignal.timeout(8000) });
    assert.equal((await end(a.params, a.cookie)).status, 200);
    await sent;
    assert.equal(deliveries.length, previous + 1);
    assert.equal((await one("SELECT COUNT(*) AS n FROM nathan_backchannel_deliveries WHERE session_id=?", a.id)).n, 1);
  } finally {
    await sql("UPDATE oauthClient SET backchannelLogoutUri=NULL");
  }
});

for (const mode of ["hinted", "ordinary"]) test(mode + " logout notifies both JWT-only RPs with the subjects and SID they actually received", async () => {
  const secondary = "second-" + mode, previous = deliveries.length;
  await sql("UPDATE oauthClient SET backchannelLogoutUri=? WHERE clientId=?", backchannel, client);
  await sql("INSERT INTO oauthClient(id,clientId,clientSecret,redirectUris,skipConsent,requirePKCE,grantTypes,scopes," +
    "tokenEndpointAuthMethod,backchannelLogoutUri,subjectType) VALUES (?,?,?,?,1,1,'[\"authorization_code\"]','[\"openid\",\"email\"]'," +
    "'client_secret_basic',?,'pairwise')", secondary, secondary, hash(secret), JSON.stringify([origin + "/auth/callback"]), backchannel);
  await sql("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES (?,?,?)", secondary, secondary, resource);
  try {
    const a = await grant(), b = await grant("openid email", a, secondary);
    await sql("UPDATE oauthClient SET redirectUris='[\"https://rotated-sector.example.test/auth/callback\"]' WHERE clientId=?", secondary);
    const response = mode === "hinted" ? await end(a.params,a.cookie) : await get("/api/auth/sign-out", {
      method: "POST", headers: { Cookie: a.cookie, Origin: origin, "Content-Type": "application/json" }, body: "{}" });
    assert.equal(response.status, 200);
    assert.equal((await one("SELECT count(*) AS n FROM nathan_backchannel_deliveries WHERE session_id=?", a.id)).n, 2);
    const timeout = AbortSignal.timeout(8000);
    while (deliveries.length < previous + 2) await once(receiver, "delivery", {signal:timeout});
    const keys = createLocalJWKSet(await (await get("/api/auth/jwks")).json());
    const seen = new Map();
    for (const token of deliveries.slice(previous)) {
      const { payload } = await jwtVerify(token, keys, { issuer, typ:"logout+jwt", algorithms:["EdDSA"] });
      assert.equal(payload.sid, a.id);
      seen.set(payload.aud, payload.sub);
    }
    assert.deepEqual(seen, new Map([[client,a.sub],[secondary,decodeJwt(b.tokens.id_token).sub]]));
    assert.notEqual(seen.get(secondary),a.sub);
  } finally {
    await sql("UPDATE oauthClient SET backchannelLogoutUri=NULL WHERE clientId IN (?,?)", client,secondary);
  }
});
