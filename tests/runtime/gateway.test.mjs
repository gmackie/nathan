import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { bundle, migrate, randomKey, cookiesOf, start } from "./helpers.mjs";

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
    const idToken = await new SignJWT({ nonce: grant.nonce, email: "user@example.test", email_verified: true, sid: grant.sid })
      .setProtectedHeader({ alg: "ES256", kid: "k1" })
      .setIssuer(ISSUER).setAudience(CLIENT).setSubject(grant.sub)
      .setIssuedAt().setExpirationTime("5m").sign(privateKey);
    return Response.json({ id_token: idToken, access_token: "x", token_type: "Bearer" });
  }
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

let mf, db;
before(async () => {
  mf = await start({
    scriptPath: bundle("gateway"),
    d1Databases: { SESSIONS: "gateway-sessions" },
    serviceBindings: { UPSTREAM: () => new Response("upstream ok") },
    outboundService: idp,
    bindings: {
      NATHAN_ISSUER: ISSUER, PUBLIC_ORIGIN: ORIGIN, APPLICATION_ID: "dashboard",
      OIDC_CLIENT_ID: CLIENT, OIDC_CLIENT_SECRET: "s".repeat(40),
      SESSION_ENCRYPTION_KEY: randomKey(), SESSION_TTL_SECONDS: "3600", REQUIRE_AAL2: "false"
    }
  });
  db = await mf.getD1Database("SESSIONS");
  await migrate(db, "migrations/gateway/0001_sessions.sql");
});
after(() => mf?.dispose());

async function login(sub, sid) {
  const begin = await mf.dispatchFetch(ORIGIN + "/__nathan/login?returnTo=/reports", { redirect: "manual" });
  assert.equal(begin.status, 302, "login must redirect to the IdP, got " + begin.status + " " + await begin.clone().text());
  const flow = cookiesOf(begin)["__Host-nathan-flow"];
  assert.ok(flow?.value, "login must set the encrypted flow cookie");
  assert.match(flow.raw, /HttpOnly/);
  const authorize = new URL(begin.headers.get("Location"));
  assert.equal(authorize.origin + authorize.pathname, ISSUER + "/oauth2/authorize");
  const code = "code-" + crypto.randomUUID();
  issued.set(code, { nonce: authorize.searchParams.get("nonce"), sub, sid });
  const callback = await mf.dispatchFetch(
    ORIGIN + "/__nathan/callback?code=" + code + "&state=" + authorize.searchParams.get("state"),
    { redirect: "manual", headers: { Cookie: "__Host-nathan-flow=" + flow.value } });
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
  assert.equal(page.status, 200);
  assert.equal(await page.text(), "upstream ok");
});

async function logoutToken(claims, iat = Math.floor(Date.now() / 1000)) {
  return new SignJWT({ events: { "http://schemas.openid.net/event/backchannel-logout": {} }, ...claims })
    .setProtectedHeader({ alg: "ES256", kid: "k1", typ: "logout+jwt" })
    .setIssuer(ISSUER).setAudience(CLIENT).setIssuedAt(iat).setJti(crypto.randomUUID())
    .setExpirationTime("2m").sign(privateKey);
}
const postLogout = token => mf.dispatchFetch(ORIGIN + "/__nathan/backchannel", {
  method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ logout_token: token }).toString()
});
const sessionCount = async sid =>
  (await db.prepare("SELECT count(*) AS n FROM nathan_gateway_sessions WHERE sid=?").bind(sid).first()).n;

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
  // Fail the batch's second statement: the delete must not commit on its own.
  await db.prepare("ALTER TABLE nathan_gateway_logout_jti RENAME TO hidden_jti").run();
  const failed = await postLogout(token);
  await db.prepare("ALTER TABLE hidden_jti RENAME TO nathan_gateway_logout_jti").run();
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
  const rows = await db.prepare("SELECT count(*) AS n FROM nathan_gateway_logout_jti").first();
  assert.ok(rows.n >= 1);
});

test("a future-dated token's replay record outlives its acceptance window", async () => {
  await login("user-7", "sid-7");
  const iat = Math.floor(Date.now() / 1000) + 170;
  const token = await logoutToken({ sid: "sid-7" }, iat);
  assert.equal((await postLogout(token)).status, 204);
  const jti = JSON.parse(Buffer.from(token.split(".")[1], "base64url")).jti;
  const row = await db.prepare("SELECT exp FROM nathan_gateway_logout_jti WHERE jti=?").bind(jti).first();
  assert.ok(row.exp >= iat + 180 + 30, "replay record must last until iat + skew + tolerance, got exp-iat=" + (row.exp - iat));
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
