import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { bundle, migrateGateway, randomKey, cookiesOf, start, COMPAT } from "./helpers.mjs";

const ISSUER = "https://login.example.test/api/auth";
const ORIGIN = "https://app.example.test";
const CLIENT = "gateway-client";
const { privateKey, publicKey } = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };

/** Per-test IdP behaviour: the authorization code maps to the nonce the gateway sent. */
const issued = new Map();
const outage = { discovery: false, jwks: false };
async function idp(request) {
  const url = new URL(request.url);
  if (outage.discovery && url.pathname.endsWith("/openid-configuration")) return new Response("down", { status: 502 });
  if (outage.jwks && url.pathname.endsWith("/jwks")) return new Response("down", { status: 502 });
  if (url.href === ISSUER + "/.well-known/openid-configuration")
    return Response.json({
      issuer: ISSUER,
      authorization_endpoint: ISSUER + "/oauth2/authorize",
      token_endpoint: ISSUER + "/oauth2/token",
      jwks_uri: ISSUER + "/jwks"
    });
  if (url.href === ISSUER + "/jwks") return Response.json({ keys: [jwk] });
  if (url.href === ISSUER + "/oauth2/token" && request.method === "POST") {
    const form = new URLSearchParams(await request.text());
    const grant = issued.get(form.get("code"));
    if (!grant) return Response.json({ error: "invalid_grant" }, { status: 400 });
    const claims = new SignJWT({ nonce: grant.nonce, email: "user@example.test", email_verified: true, sid: grant.sid })
      .setProtectedHeader({ alg: "ES256", kid: "k1" })
      .setIssuer(ISSUER).setAudience(CLIENT).setSubject(grant.sub).setExpirationTime("5m");
    if (grant.iat !== null) claims.setIssuedAt(grant.iat);
    const idToken = await claims.sign(privateKey);
    if (grant.afterIssue) await grant.afterIssue();
    return Response.json({ id_token: idToken, access_token: "x", token_type: "Bearer" });
  }
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

let mf, db;
before(async () => {
  mf = await start({
    workers: [{
      name: "gateway", modules: true, ...COMPAT,
      scriptPath: bundle("gateway"),
      d1Databases: { SESSIONS: "gateway-sessions" },
      serviceBindings: { UPSTREAM: () => new Response("upstream ok"), NATHAN: { name: "nathan-stub", entrypoint: "NathanVerifier" } },
      outboundService: idp,
      bindings: {
        NATHAN_ISSUER: ISSUER, PUBLIC_ORIGIN: ORIGIN, APPLICATION_ID: "dashboard",
        OIDC_CLIENT_ID: CLIENT, OIDC_CLIENT_SECRET: "s".repeat(40),
        SESSION_ENCRYPTION_KEY: randomKey(), SESSION_TTL_SECONDS: "3600", REQUIRE_AAL2: "false",
        NATHAN_PRINCIPAL_KEY: randomKey()
      }
    }, {
      // Access decisions are covered by rbac.test.mjs; this suite exercises login and logout.
      name: "nathan-stub", modules: true, ...COMPAT,
      script: 'import { WorkerEntrypoint } from "cloudflare:workers";\n' +
        'export class NathanVerifier extends WorkerEntrypoint { async resolveAccess() { return { allowed: true, roles: [], permissions: [] }; } }\n' +
        'export default { fetch() { return new Response(null, { status: 404 }); } };'
    }]
  });
  db = await mf.getD1Database("SESSIONS", "gateway");
  await migrateGateway(db);
});
after(() => mf?.dispose());

async function startLogin(sub, sid, iat = Math.floor(Date.now() / 1000), afterIssue) {
  const begin = await mf.dispatchFetch(ORIGIN + "/__nathan/login?returnTo=/reports", { redirect: "manual" });
  assert.equal(begin.status, 302, "login must redirect to the IdP, got " + begin.status + " " + await begin.clone().text());
  const flow = cookiesOf(begin)["__Host-nathan-flow"];
  assert.ok(flow?.value, "login must set the encrypted flow cookie");
  assert.match(flow.raw, /HttpOnly/);
  const authorize = new URL(begin.headers.get("Location"));
  assert.equal(authorize.origin + authorize.pathname, ISSUER + "/oauth2/authorize");
  const code = "code-" + crypto.randomUUID();
  issued.set(code, { nonce: authorize.searchParams.get("nonce"), sub, sid, iat, afterIssue });
  return () => mf.dispatchFetch(
    ORIGIN + "/__nathan/callback?code=" + code + "&state=" + authorize.searchParams.get("state"),
    { redirect: "manual", headers: { Cookie: "__Host-nathan-flow=" + flow.value } });
}
async function login(sub, sid, iat) {
  const complete = await startLogin(sub, sid, iat);
  const callback = await complete();
  assert.equal(callback.status, 303, "callback must complete, got " + callback.status + " " + await callback.clone().text());
  assert.equal(callback.headers.get("Location"), ORIGIN + "/reports");
  const jar = cookiesOf(callback);
  assert.ok(jar["__Host-nathan-session"]?.value, "callback must set the session cookie");
  assert.match(jar["__Host-nathan-flow"].raw, /Max-Age=0/, "callback must clear the flow cookie");
  return jar["__Host-nathan-session"].value;
}

test("gateway login round trip sets flow and session cookies and proxies upstream", async () => {
  const session = await login("user-1", "sid-1");
  const page = await mf.dispatchFetch(ORIGIN + "/reports", { headers: { Cookie: "__Host-nathan-session=" + session } });
  assert.equal(page.status, 200, await page.clone().text());
  assert.equal(await page.text(), "upstream ok");
  // no-referrer would make browsers send Origin: null on the app's own same-origin POSTs,
  // which the gateway's unsafe-request check then refuses.
  assert.equal(page.headers.get("Referrer-Policy"), "same-origin");
});

async function logoutToken(claims, iat = Math.floor(Date.now() / 1000), jti = crypto.randomUUID()) {
  return new SignJWT({ events: { "http://schemas.openid.net/event/backchannel-logout": {} }, ...claims })
    .setProtectedHeader({ alg: "ES256", kid: "k1", typ: "logout+jwt" })
    .setIssuer(ISSUER).setAudience(CLIENT).setIssuedAt(iat).setJti(jti)
    .setExpirationTime("2m").sign(privateKey);
}
const postLogout = token => mf.dispatchFetch(ORIGIN + "/__nathan/backchannel", {
  method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ logout_token: token }).toString()
});
const sessionCount = async sid =>
  (await db.prepare("SELECT count(*) AS n FROM nathan_gateway_sessions WHERE sid=?").bind(sid).first()).n;

async function assertLoginEnded(complete, sid) {
  const response = await complete();
  assert.equal(response.status, 401);
  assert.equal(cookiesOf(response)["__Host-nathan-session"], undefined);
  assert.match(cookiesOf(response)["__Host-nathan-flow"].raw, /Max-Age=0/);
  assert.equal(await sessionCount(sid), 0);
}

test("a signed SID logout received during an in-flight token exchange applies at callback", async () => {
  const sub = "sid-cutoff-user", sid = "sid-before-callback";
  const signed = Promise.withResolvers(), deliver = Promise.withResolvers();
  const complete = await startLogin(sub, sid, undefined, async () => {
    signed.resolve();
    await deliver.promise;
  });
  const callback = complete();
  try {
    await Promise.race([signed.promise, callback.then(() => assert.fail("callback ended before token exchange"))]);
    assert.equal((await postLogout(await logoutToken({ sub, sid }))).status, 204);
  } finally { deliver.resolve(); }
  await assertLoginEnded(() => callback, sid);
  await login(sub, "sid-after-logout");
});

test("an issuer omitting ID-token iat uses the encrypted flow start for subject cutoffs", async () => {
  const sub = "no-iat-person", sid = "no-iat-sid";
  const complete = await startLogin(sub, sid, null);
  assert.equal((await postLogout(await logoutToken({ sub, toe: Math.floor(Date.now() / 1000) }))).status, 204);
  await assertLoginEnded(complete, sid);
  await login("other-no-iat-person", "allowed-no-iat", null);
});

test("a subject receipt compares the signed ID-token time to the original event second at callback", async () => {
  const sub = "subject-cutoff-user", toe = Math.floor(Date.now() / 1000) - 30;
  const complete = await startLogin(sub, "at-subject-cutoff", toe);
  const later = await startLogin(sub, "after-subject-cutoff", toe + 1);
  assert.equal((await postLogout(await logoutToken({ sub, toe }))).status, 204);
  assert.equal((await postLogout(await logoutToken({ sub, toe: toe - 10 }))).status, 204);
  await assertLoginEnded(complete, "at-subject-cutoff");
  assert.equal((await later()).status, 303);
  await login("other-subject", "other-subject-sid", toe);
});

test("a retained pre-upgrade JTI acknowledges a replay without revoking a fresh session", async () => {
  const jti = crypto.randomUUID(), now = Math.floor(Date.now() / 1000);
  await db.prepare("INSERT INTO nathan_gateway_logout_jti(jti,exp) VALUES (?,?)").bind(jti,now + 120).run();
  await login("legacy-jti-person", "legacy-jti-fresh");
  assert.equal((await postLogout(await logoutToken({ sub: "legacy-jti-person" }, now, jti))).status, 204);
  assert.equal(await sessionCount("legacy-jti-fresh"), 1);
});

test("receipts and event IDs belong to the verified issuer and client", async () => {
  const jti = crypto.randomUUID(), sid = "scoped-sid", sub = "scoped-person";
  for (const [iss, client] of [[ISSUER, "other-client"], ["https://other.example.test/api/auth", CLIENT]])
    await db.prepare("INSERT INTO nathan_gateway_logout_receipts(issuer,client_id,jti,sid,exp) VALUES (?,?,?,?,unixepoch()+3600)")
      .bind(iss,client,jti,sid).run();
  await login(sub, sid);
  assert.equal((await postLogout(await logoutToken({ sid }, Math.floor(Date.now() / 1000), jti))).status, 204);
  assert.equal(await sessionCount(sid), 0);
  assert.equal((await db.prepare("SELECT count(*) AS n FROM nathan_gateway_logout_receipts WHERE jti=?").bind(jti).first()).n, 3);
});

test("a subject logout without toe ends an in-flight login and admits an immediate new one", async () => {
  const sub = "legacy-cutoff-user", issuedAt = Math.floor(Date.now() / 1000);
  const complete = await startLogin(sub, "pending-legacy", issuedAt), jti = crypto.randomUUID();
  assert.equal((await postLogout(await logoutToken({ sub }, issuedAt, jti))).status, 204);
  await assertLoginEnded(complete, "pending-legacy");
  await login(sub, "fresh-legacy", issuedAt);
  assert.equal((await postLogout(await logoutToken({ sub }, issuedAt + 1, jti))).status, 204);
  assert.equal(await sessionCount("fresh-legacy"), 1);
});

test("back-channel logout deletes the matching session", async () => {
  await login("user-2", "sid-2");
  assert.equal(await sessionCount("sid-2"), 1);
  const response = await postLogout(await logoutToken({ sid: "sid-2" }));
  assert.equal(response.status, 204);
  assert.equal(await sessionCount("sid-2"), 0);
});

test("back-channel logout that fails mid-way can be retried with the same token", async () => {
  await login("user-3", "sid-3");
  const token = await logoutToken({ sid: "sid-3" });
  // Make session deletion fail once by hiding the sessions table.
  await db.prepare("ALTER TABLE nathan_gateway_sessions RENAME TO hidden_sessions").run();
  const failed = await postLogout(token);
  await db.prepare("ALTER TABLE hidden_sessions RENAME TO nathan_gateway_sessions").run();
  assert.notEqual(failed.status, 204, "a failed revocation must not report success");
  assert.ok(failed.status >= 500, "a storage failure must be retryable (5xx), got " + failed.status);
  assert.equal(await sessionCount("sid-3"), 1);
  const retried = await postLogout(token);
  assert.equal(retried.status, 204);
  assert.equal(await sessionCount("sid-3"), 0, "the IdP's retry must revoke the session");
});

test("replayed logout token does not revoke a newer session", async () => {
  await login("user-4", "sid-4");
  const token = await logoutToken({ sub: "user-4" });
  assert.equal((await postLogout(token)).status, 204);
  await login("user-4", "sid-4b");
  assert.equal((await postLogout(token)).status, 204);
  assert.equal(await sessionCount("sid-4b"), 1);
});

test("revocation rolls back when the replay record cannot be written, so the retry still revokes", async () => {
  await login("user-5", "sid-5");
  const token = await logoutToken({ sid: "sid-5" });
  await db.prepare("ALTER TABLE nathan_gateway_logout_receipts RENAME TO hidden_receipts").run();
  const failed = await postLogout(token);
  await db.prepare("ALTER TABLE hidden_receipts RENAME TO nathan_gateway_logout_receipts").run();
  assert.equal(failed.status, 503);
  assert.equal(await sessionCount("sid-5"), 1, "the batch must be all-or-nothing");
  assert.equal((await postLogout(token)).status, 204);
  assert.equal(await sessionCount("sid-5"), 0);
});

test("concurrent deliveries of one logout token both succeed and revoke once", async () => {
  await login("user-6", "sid-6");
  const token = await logoutToken({ sid: "sid-6" });
  const responses = await Promise.all([postLogout(token), postLogout(token)]);
  assert.deepEqual(responses.map(r => r.status), [204, 204]);
  assert.equal(await sessionCount("sid-6"), 0);
  const rows = await db.prepare("SELECT count(*) AS n FROM nathan_gateway_logout_receipts WHERE sid=?").bind("sid-6").first();
  assert.equal(rows.n, 1);
});

test("replay receipts cover the sender retry schedule and the gateway prunes expired receipts", async () => {
  await login("user-7", "sid-7");
  const iat = Math.floor(Date.now() / 1000) + 170;
  const token = await logoutToken({ sid: "sid-7" }, iat);
  assert.equal((await postLogout(token)).status, 204);
  const jti = JSON.parse(Buffer.from(token.split(".")[1], "base64url")).jti;
  const row = await db.prepare("SELECT exp FROM nathan_gateway_logout_receipts WHERE jti=?").bind(jti).first();
  assert.ok(row.exp >= iat + 48 * 3600, "receipt must span retries as well as the signed token's lifetime");
  const expired = "expired-" + crypto.randomUUID();
  await db.prepare("INSERT INTO nathan_gateway_logout_receipts(issuer,client_id,jti,subject,exp) VALUES (?,?,?,?,unixepoch()-1)")
    .bind(ISSUER,CLIENT,expired,"stale-subject").run();
  const gateway = await mf.getWorker("gateway");
  await gateway.scheduled({ cron: "*/5 * * * *" });
  const receipts = await db.prepare("SELECT jti FROM nathan_gateway_logout_receipts WHERE jti IN (?,?)").bind(expired,jti).all();
  assert.deepEqual(receipts.results, [{ jti }]);
});

test("discovery or JWKS outages are retryable; bad tokens are not", async () => {
  await login("user-8", "sid-8");
  const token = await logoutToken({ sid: "sid-8" });
  outage.discovery = true;
  assert.equal((await postLogout(token)).status, 503);
  outage.discovery = false;
  outage.jwks = true;
  assert.equal((await postLogout(token)).status, 503);
  outage.jwks = false;
  assert.equal(await sessionCount("sid-8"), 1);
  const forged = token.slice(0, -4) + (token.endsWith("AAAA") ? "BBBB" : "AAAA");
  assert.equal((await postLogout(forged)).status, 400);
  assert.equal((await postLogout(token)).status, 204);
  assert.equal(await sessionCount("sid-8"), 0);
});

test("a delayed subject logout ends only sessions established by the signed event time", async () => {
  const sub = "delayed-logout-user", occurred = Math.floor(Date.now() / 1000) - 300;
  await login(sub, "older-sid", occurred);
  await login(sub, "newer-sid");
  assert.equal((await postLogout(await logoutToken({ sub, toe: "invalid" }))).status, 400);
  assert.equal((await postLogout(await logoutToken({ sub, toe: occurred }))).status, 204);
  assert.equal(await sessionCount("older-sid"), 0);
  assert.equal(await sessionCount("newer-sid"), 1);
});
