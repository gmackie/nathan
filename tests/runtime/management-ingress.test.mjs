import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { authWorker, bundle, enrollAdmin, randomKey, start } from "./helpers.mjs";
import { passkeySignIn, softwarePasskey } from "./passkey-authenticator.mjs";

const host = "id.management.test";
const origin = "https://" + host;
const team = "team.cloudflareaccess.com";
const audience = "a".repeat(64);
const secret = randomKey();
const vars = { NATHAN_APP_ORIGIN: "https://management.test", NATHAN_APP_ID: "customer", NATHAN_ACCESS_TEAM_DOMAIN: team, NATHAN_ACCESS_AUD: audience, BETTER_AUTH_SECRET: secret };
const { publicKey, privateKey } = await generateKeyPair("RS256");
const jwk = { ...await exportJWK(publicKey), kid: "test-key", alg: "RS256", use: "sig" };
const accessJwt = (overrides = {}) => new SignJWT({
  iss: "https://" + team, aud: [audience], sub: "owner", email: "admin@example.test", type: "app",
  exp: Math.floor(Date.now() / 1000) + 300, ...overrides
}).setProtectedHeader({ alg: "RS256", kid: jwk.kid }).sign(privateKey);
const ownerJwt = await accessJwt();
const assertion = token => ({ "Cf-Access-Jwt-Assertion": token });
let mf, admin, db, passkey;
before(async () => {
  mf = await authWorker(host, vars, { outboundService(request) {
    assert.equal(request.url, "https://" + team + "/cdn-cgi/access/certs");
    return Response.json({ keys: [jwk] });
  } });
  db = await mf.getD1Database("DB");
  admin = await enrollAdmin(db, secret);
  passkey = softwarePasskey();
  await db.prepare('UPDATE passkey SET publicKey=?, credentialID=? WHERE userId=?')
    .bind(passkey.publicKey, passkey.credentialId, "admin-1").run();
});
after(() => mf?.dispose());

test("standalone management checks Access before serving any route, including assets and health", async () => {
  for (const path of ["/healthz", "/__nathan/ui/missing.css", "/sign-in", "/studio", "/api/auth/get-session"]) {
    assert.equal((await mf.dispatchFetch(origin + path)).status, 403, path);
  }
  const verified = await mf.dispatchFetch(origin + "/healthz", { headers: assertion(ownerJwt) });
  assert.equal(verified.status, 200);
  assert.equal((await verified.json()).system, "nathan");
  for (const other of [vars.NATHAN_APP_ORIGIN, "https://management-preview.example.test"]) {
    assert.equal((await mf.dispatchFetch(other + "/healthz", { headers: assertion(ownerJwt) })).status, 421);
  }
  for (const claims of [{ iss: "https://other.cloudflareaccess.com" }, { aud: "other-application" }, { exp: 10 },
    { exp: undefined }, { sub: "" }, { type: "service_token" }, { email: undefined }]) {
    assert.equal((await mf.dispatchFetch(origin + "/healthz", { headers: assertion(await accessJwt(claims)) })).status, 403);
  }
  for (const path of ["/api/auth/oauth2/authorize", "/sign-in/email", "/consent"]) {
    assert.equal((await mf.dispatchFetch(origin + path, { headers: assertion(ownerJwt) })).status, 404, path);
  }
});

test("management accepts its own Access-bound passkey session and keeps ordinary signed sessions outside Studio", async () => {
  const status = (token, cookie) => mf.dispatchFetch(origin + "/studio/api/status", { headers: { ...assertion(token), Cookie: cookie } });
  assert.equal((await status(ownerJwt, admin.cookie)).status, 403);
  const asOperator = token => ({ dispatchFetch(url, init) {
    return mf.dispatchFetch(url, { ...init, headers: { ...init.headers, ...assertion(token) } });
  } });
  const fetcher = asOperator(ownerJwt);
  const management = await passkeySignIn(fetcher, origin, passkey, "admin-1");
  assert.match(management.cookie, /^__Host-/);
  const studio = await status(ownerJwt, management.cookie);
  assert.equal(studio.status, 200);
  assert.equal((await studio.json()).issuer, vars.NATHAN_APP_ORIGIN + "/api/auth");
  assert.equal((await status(await accessJwt({ sub: "another-person" }), management.cookie)).status, 403);
  assert.equal((await status(await accessJwt({ email: "other@example.test" }), management.cookie)).status, 403);
  await assert.rejects(passkeySignIn(asOperator(await accessJwt({ email: "other@example.test" })), origin, passkey, "admin-1"),
    /verify-authentication: 403/);
  await db.prepare("DELETE FROM nathan_admin_assurance WHERE session_id=?").bind(management.id).run();
  assert.equal((await status(ownerJwt, management.cookie)).status, 403);
  const newKey = await fetcher.dispatchFetch(origin + "/api/auth/passkey/generate-register-options",
    { headers: { Cookie: management.cookie, Origin: origin } });
  assert.equal(newKey.status, 403, "adding a passkey to an enrolled administrator requires a recent passkey sign-in");
});

test("only the invited bootstrap owner can choose a management password and verify the real mailbox link", async () => {
  let verification;
  const install = await authWorker(host, { ...vars, ENABLE_PASSWORD: "true", EMAIL_FROM: "operator@example.test", RESEND_API_KEY: randomKey() },
    { async outboundService(request) {
      if (request.url === "https://" + team + "/cdn-cgi/access/certs") return Response.json({ keys: [jwk] });
      assert.equal(request.url, "https://api.resend.com/emails");
      const message = await request.json();
      assert.equal([message.to].flat()[0], "admin@example.test");
      verification = message.text.match(/https:\/\/[^\s]+/)[0];
      return Response.json({ id: "sent" });
    } });
  const setup = "/security/setup-owner";
  const password = randomKey();
  const get = (path, token = ownerJwt) => install.dispatchFetch(new URL(path, origin).href, { redirect: "manual", headers: assertion(token) });
  const submit = (source, token, supplied = password) => install.dispatchFetch(origin + setup, { method: "POST", redirect: "manual",
    headers: { ...assertion(token), Origin: source, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ password: supplied }).toString() });
  try {
    const database = await install.getD1Database("DB");
    await database.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary','cli:account','admin@example.test','pending')").run();
    assert.equal((await get(setup)).status, 404);
    await database.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('initial','admin@example.test','cli:account',unixepoch()+3600)").run();
    assert.equal((await get("/")).headers.get("Location"), origin + setup);
    const form = await get(setup);
    assert.equal(form.status, 200);
    assert.match(await form.text(), /autocomplete="new-password"/i);
    assert.equal((await get(setup, await accessJwt({ email: "wrong@example.test" }))).status, 404);
    assert.equal((await submit("https://management.test", ownerJwt)).status, 403);
    assert.equal((await submit(origin, ownerJwt)).status, 303);
    assert.ok(verification);
    assert.equal(new URL(verification).origin, origin);
    assert.equal((await submit(origin, ownerJwt, randomKey())).status, 401);
    assert.equal((await submit(origin, ownerJwt)).status, 303);
    await database.prepare("UPDATE nathan_invitations SET revoked_at=unixepoch() WHERE id='initial'").run();
    await get(verification);
    assert.equal(await database.prepare('SELECT emailVerified FROM "user" WHERE email=?').bind("admin@example.test").first("emailVerified"), 0);
    await database.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('reissued','admin@example.test','cli:account',unixepoch()+3600)").run();
    assert.equal((await get(verification)).status, 302);
    assert.match(await (await get(setup)).text(), /email is verified/i);
    const owner = await database.prepare('SELECT u.emailVerified, u.role, b.state, i.uses FROM "user" u JOIN nathan_bootstrap_status b ON b.admin_email=u.email JOIN nathan_invitations i ON i.email=u.email WHERE i.id=?').bind("reissued").first();
    assert.equal(owner.emailVerified, 1);
    assert.notEqual(owner.role, "admin");
    assert.equal(owner.state, "pending");
    assert.equal(owner.uses, 1);
  } finally { await install.dispose(); }
});

test("incomplete standalone setup fails closed; an existing hosted deployment keeps its sign-in route", async () => {
  for (const overrides of [
    { NATHAN_APP_ID: "customer" },
    { NATHAN_APP_ORIGIN: vars.NATHAN_APP_ORIGIN },
    { NATHAN_ACCESS_AUD: audience },
    { ...vars, NATHAN_APP_ORIGIN: origin },
    { ...vars, NATHAN_ACCESS_TEAM_DOMAIN: "invalid.example.test" }
  ]) {
    // Fail before accessing D1, bootstrapping Better Auth, or fetching keys.
    const invalid = await start({ scriptPath: bundle("auth"), bindings: { NATHAN_ISSUER: origin,
      NATHAN_CONFIG_KEY: randomKey(), NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_STEPUP_REQUIRED: "true", ...overrides } });
    try { assert.equal((await invalid.dispatchFetch(origin + "/healthz", { headers: assertion(ownerJwt) })).status, 503); }
    finally { await invalid.dispose(); }
  }
  const legacy = await authWorker(host);
  try { assert.equal((await legacy.dispatchFetch(origin + "/sign-in")).status, 200); }
  finally { await legacy.dispose(); }
});
