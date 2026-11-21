/**
 * NATH-17 in workerd: one social provider whose stored credentials cannot be decrypted must not take
 * down every sign-in. The broken provider is skipped and marked unavailable (audited once per window,
 * shown in Studio and in /healthz without secrets); the other providers, Identity Studio and the
 * repair and disable paths keep working; Nathan never falls back to an older credential source.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, randomKey, enrollAdmin, studioPost, cookiesOf } from "./helpers.mjs";
import { sealProviderCredentials } from "../../src/auth/config-crypto.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST;
const KEY = randomKey(), SECRET = randomKey() + randomKey();
const CREDS = {
  github: { clientId: "Ov23liIsolationTest01", clientSecret: "0123456789abcdef0123456789abcdef01234567" },
  discord: { clientId: "123456789012345678", clientSecret: "AbCdEfGhIjKlMnOpQrStUvWxYz012345" },
  twitter: { clientId: "M1M5R3BMVy13QmpScXkzTUt5OE46MTpjaQ", clientSecret: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDeFgHiJ" }
};
// Legacy GitHub Worker secrets exist too: a broken D1 row must never fall back to them.
const LEGACY = { GITHUB_CLIENT_ID: "Iv1legacyGithubApp00", GITHUB_CLIENT_SECRET: "legacy-secret-legacy-secret-legacy-00000" };

const codes = new Map();
async function outbound(request) {
  const url = new URL(request.url);
  if (url.href === "https://discord.com/api/oauth2/token") {
    const code = new URLSearchParams(await request.text()).get("code");
    return codes.has(code) ? Response.json({ access_token: "at-" + code, token_type: "Bearer", expires_in: 3600 }) : Response.json({ error: "invalid_grant" }, { status: 400 });
  }
  const grant = codes.get((request.headers.get("authorization") || "").replace(/^Bearer at-/, ""));
  if (grant && url.origin + decodeURIComponent(url.pathname) === "https://discord.com/api/users/@me")
    return Response.json({ id: grant.id, username: "u" + grant.id, global_name: null, avatar: null, discriminator: "0", email: grant.email, verified: true });
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

let mf, db, admin;
const worker = { fetch: (url, init) => mf.dispatchFetch(url, init) };
before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, NATHAN_CONFIG_KEY: KEY, ...LEGACY }, { outboundService: outbound });
  db = await mf.getD1Database("DB");
  await db.prepare("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','test')").run();
  for (const [id, values] of Object.entries(CREDS)) await store(id, values);
  admin = await enrollAdmin(db, SECRET);
});
after(() => mf?.dispose());

async function store(id, values) {
  const sealed = await sealProviderCredentials(id, values, KEY);
  await db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,config,secret_fields,updated_by) VALUES (?,?,?,?,'test') " +
    "ON CONFLICT(id) DO UPDATE SET client_id=excluded.client_id,config=excluded.config,secret_fields=excluded.secret_fields,secret_cipher=NULL")
    .bind(id, sealed.clientId, sealed.config, sealed.secretFields).run();
}
/** Damages the stored ciphertext the way a bad restore or a rotated NATHAN_CONFIG_KEY would. */
async function corrupt(id) {
  const row = await db.prepare("SELECT secret_fields FROM nathan_oauth_providers WHERE id=?").bind(id).first();
  const fields = JSON.parse(row.secret_fields);
  for (const name of Object.keys(fields)) fields[name] = fields[name].slice(0, -8) + "AAAAAAAA";
  await db.prepare("UPDATE nathan_oauth_providers SET secret_fields=? WHERE id=?").bind(JSON.stringify(fields), id).run();
}
const get = (path, cookie) => mf.dispatchFetch(ORIGIN + path, { headers: cookie ? { Cookie: cookie } : {} });
const unavailableAudits = async id => (await db.prepare("SELECT outcome FROM nathan_security_audit WHERE action='oauth_provider_unavailable' AND target=?").bind(id).all()).results;
let clients = 0;
async function discordSignIn(code, id, email) {
  const started = await mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/social", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": "203.0.113." + (++clients) },
    body: JSON.stringify({ provider: "discord", callbackURL: "/" })
  });
  assert.equal(started.status, 200, await started.clone().text());
  const state = new URL((await started.json()).url).searchParams.get("state");
  const cookie = Object.entries(cookiesOf(started)).map(([k, v]) => k + "=" + v.value).join("; ");
  codes.set(code, { id, email });
  return mf.dispatchFetch(ORIGIN + "/api/auth/callback/discord?code=" + code + "&state=" + encodeURIComponent(state), { redirect: "manual", headers: { Cookie: cookie } });
}

test("a corrupted GitHub row leaves sign-in, Discord sign-in and Studio working", async () => {
  await corrupt("github");
  const page = await get("/sign-in");
  assert.equal(page.status, 200, "the sign-in page still renders");
  const html = await page.text();
  assert.ok(html.includes("Continue with Discord") && html.includes("Continue with X"), "other providers stay available");
  assert.ok(!html.includes("Continue with GitHub"), "the broken provider is skipped");
  const back = await discordSignIn("dc-1", "400000000000000001", "member@example.test");
  assert.equal(back.status, 302, await back.clone().text());
  assert.equal(back.headers.get("Location"), "/");
  assert.ok(cookiesOf(back)["__Secure-nathan.session_token"], "Discord sign-in completed");
  assert.equal((await get("/studio", admin.cookie)).status, 200, "Identity Studio still opens");
});

test("the broken provider never falls back to the legacy Worker secrets", async () => {
  const response = await mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/social", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": "203.0.113.200" },
    body: JSON.stringify({ provider: "github", callbackURL: "/" })
  });
  assert.notEqual(response.status, 200, "no GitHub sign-in at all");
  assert.ok(!(await response.text()).includes(LEGACY.GITHUB_CLIENT_ID), "the legacy client is never used");
});

test("Studio and /healthz show the provider as unavailable, without secrets; the audit has one row per window", async () => {
  for (let i = 0; i < 3; i++) await get("/sign-in");
  const providers = (await (await get("/studio/api/providers", admin.cookie)).json()).providers;
  const github = providers.find(p => p.id === "github");
  assert.equal(github.enabled, false);
  assert.equal(github.available, false);
  assert.equal(github.unavailable.reason, "decrypt_failed");
  assert.match(github.error, /cannot be decrypted/);
  assert.equal(providers.find(p => p.id === "discord").available, true);
  const text = JSON.stringify(providers);
  for (const secret of [CREDS.github.clientSecret, LEGACY.GITHUB_CLIENT_SECRET, KEY]) assert.ok(!text.includes(secret), "no secret in Studio");
  const health = await get("/healthz");
  assert.equal(health.status, 200);
  const body = await health.json();
  assert.equal(body.ok, true, "the identity Worker itself is healthy");
  assert.deepEqual(body.detail.socialProviders.unavailable, [{ id: "github", reason: "decrypt_failed" }]);
  const healthText = JSON.stringify(body);
  for (const secret of [CREDS.github.clientSecret, CREDS.discord.clientSecret, KEY, CREDS.github.clientId]) assert.ok(!healthText.includes(secret), "no credential in /healthz");
  assert.deepEqual((await unavailableAudits("github")).map(a => a.outcome), ["skipped_decrypt_failed"], "audited once per window");
  // After the window, a still-broken provider is audited again.
  await db.prepare("UPDATE nathan_provider_health SET audited_at=unixepoch()-3601 WHERE id='github'").run();
  await get("/sign-in");
  assert.equal((await unavailableAudits("github")).length, 2);
});

test("Studio repairs the broken provider by saving new credentials", async () => {
  const saved = await studioPost(worker, ORIGIN, "/studio/api/providers", { id: "github", ...CREDS.github }, admin.cookie);
  assert.equal(saved.status, 200, await saved.clone().text());
  assert.ok((await (await get("/sign-in")).text()).includes("Continue with GitHub"), "GitHub is back");
  assert.deepEqual((await (await get("/healthz")).json()).detail.socialProviders.unavailable, []);
  assert.equal(await db.prepare("SELECT 1 FROM nathan_provider_health WHERE id='github'").first(), null, "the mark is cleared");
});

test("Studio can disable a broken provider even when it is the only one left", async () => {
  await corrupt("twitter");
  await get("/sign-in");
  const disabled = await studioPost(worker, ORIGIN, "/studio/api/providers/status",
    { id: "twitter", enabled: false, confirm: "CONFIRM DISABLE twitter" }, admin.cookie);
  assert.equal(disabled.status, 200, await disabled.clone().text());
  assert.equal((await db.prepare("SELECT enabled FROM nathan_provider_state WHERE id='twitter'").first()).enabled, 0);
  const audit = await db.prepare("SELECT outcome FROM nathan_security_audit WHERE action='oauth_provider_disable' AND target='twitter'").first();
  assert.equal(audit.outcome, "succeeded");
  // A disabled broken provider is no longer reported as unavailable (an administrator turned it off).
  assert.deepEqual((await (await get("/healthz")).json()).detail.socialProviders.unavailable, []);
  // Enabling it again is refused until its credentials can be used.
  const enable = await studioPost(worker, ORIGIN, "/studio/api/providers/status",
    { id: "twitter", enabled: true, confirm: "CONFIRM ENABLE twitter" }, admin.cookie);
  assert.equal(enable.status, 409);
});
