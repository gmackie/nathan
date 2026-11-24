import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { jwtVerify, decodeProtectedHeader } from "jose";
import {
  PROVIDER_IDS, PROVIDERS, callbackUrl, providerGuide, providerGuides, installerRegistry,
  validateProviderCredentials, buildSocialProviders, placeholderEmail, ACCOUNT_LINKING
} from "../src/shared/providers.mjs";
import { providerGuide as cliGuide, cliSecretNotice } from "../scripts/lib/provider-wizard.mjs";
import {
  generateConfigKey, encryptProviderSecret, encryptProviderField, decryptProviderField
} from "../src/auth/config-crypto.mjs";
import { mintAppleClientSecret, clearAppleSecretCache } from "../src/auth/apple-secret.mjs";
import {
  providerStatus, loadSocialProviderCredentials, loadSocialProviderState, upsertSocialProvider, setSocialProviderEnabled,
  beginProviderTest, completeProviderTest, recordProviderSignIn, credentialVersion
} from "../src/auth/provider-config.mjs";

const HOST = "login.example.com";
/** The six social providers; the Nathan upstream (NATH-51) is tested in nathan-upstream.test.mjs. */
const SOCIAL_IDS = PROVIDER_IDS.filter(id => id !== "nathan");

/** A P-256 PKCS#8 key in Apple's .p8 PEM format, plus its public key. */
async function appleKey() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const der = Buffer.from(await crypto.subtle.exportKey("pkcs8", pair.privateKey)).toString("base64");
  const pem = "-----BEGIN PRIVATE KEY-----\n" + der.match(/.{1,64}/g).join("\n") + "\n-----END PRIVATE KEY-----\n";
  return { pem, publicKey: pair.publicKey };
}
const apple = await appleKey();

// Shape-valid fake Google credentials, assembled at runtime so secret scanners (GitHub push
// protection) do not mistake test fixtures for real OAuth credentials.
const FAKE_GOOGLE_CLIENT_ID = ["123456789012", "abcdefghijklmnop0123456789abcdef"].join("-") + ".apps." + "googleusercontent.com";
const FAKE_GOOGLE_CLIENT_SECRET = "GOC" + "SPX-" + "abcdefghijklmnopqrstuvwxyz12";
const VALID = {
  google: { clientId: FAKE_GOOGLE_CLIENT_ID, clientSecret: FAKE_GOOGLE_CLIENT_SECRET },
  github: { clientId: "Ov23liAbCdEfGhIjKlMn", clientSecret: "0123456789abcdef0123456789abcdef01234567" },
  apple: { clientId: "com.example.login", teamId: "ABCDE12345", keyId: "KEY1234567", privateKey: apple.pem },
  discord: { clientId: "123456789012345678", clientSecret: "AbCdEfGhIjKlMnOpQrStUvWxYz012345" },
  twitch: { clientId: "abcdefghijklmnopqrstuvwxyz0123", clientSecret: "0123456789abcdefghijklmnopqrst" },
  twitter: { clientId: "M1M5R3BMVy13QmpScXkzTUt5OE46MTpjaQ", clientSecret: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDeFgHiJ" },
  nathan: { issuer: "https://id.example.com/api/auth", clientId: "parentClient123", clientSecret: "pArEnTsEcReT0123456789abcdefXYZ",
    displayName: "Example ID", trustEmailVerified: "true" }
};

test("the registry covers exactly the six guided providers and the Nathan upstream, with complete setup guides", () => {
  assert.deepEqual(PROVIDER_IDS, ["google", "github", "apple", "discord", "twitch", "twitter", "nathan"]);
  for (const id of SOCIAL_IDS) {
    const p = PROVIDERS[id];
    assert.equal(p.id, id);
    assert.match(p.consoleUrl, /^https:\/\//, id + " console deep link");
    assert.ok(p.steps.length >= 3, id + " has ordered setup steps");
    assert.ok(p.scopes.length >= 1, id + " lists its scopes");
    assert.ok(p.fields.some(f => f.secret), id + " has at least one secret field");
    assert.ok(p.emailTrust.length > 20, id + " documents its email trust rule");
  }
  assert.equal(PROVIDERS.twitter.name, "X");
  assert.equal(PROVIDERS.apple.responseMode, "form_post");
  assert.deepEqual(PROVIDERS.apple.fields.map(f => f.name), ["clientId", "teamId", "keyId", "privateKey"]);
  // NATH-51: no fixed console (the client is registered in the parent's own Studio), same guide shape otherwise.
  const n = PROVIDERS.nathan;
  assert.equal(n.consoleUrl, null);
  assert.match(n.consoleHint, /Identity Studio/);
  assert.ok(n.steps.length >= 3 && n.fields.some(f => f.secret) && n.emailTrust.length > 20);
  assert.deepEqual(n.fields.map(f => f.name), ["issuer", "clientId", "clientSecret", "displayName", "trustEmailVerified"]);
  assert.deepEqual(n.scopes, ["openid", "email", "profile"]);
});

test("callback URLs are exact and identical in the registry, Studio guide, installer and CLI", () => {
  const expected = Object.fromEntries(PROVIDER_IDS.map(id => [id, "https://" + HOST + "/api/auth/callback/" + id]));
  const fromRegistry = Object.fromEntries(PROVIDER_IDS.map(id => [id, callbackUrl(HOST, id)]));
  const fromStudio = Object.fromEntries(providerGuides("https://" + HOST).map(g => [g.id, g.callbackUrl]));
  const fromCli = Object.fromEntries(PROVIDER_IDS.map(id => [id, cliGuide(id, HOST).callback]));
  // The hosted installer embeds the registry function source and data; evaluate it exactly as the page does.
  const registry = installerRegistry();
  const installerFn = new Function("return (" + registry.callbackUrlSource + ")")();
  const fromInstaller = Object.fromEntries(registry.providers.map(p => [p.id, installerFn(HOST, p.id)]));
  assert.deepEqual(fromRegistry, expected);
  assert.deepEqual(fromStudio, expected);
  assert.deepEqual(fromCli, expected);
  assert.deepEqual(fromInstaller, expected);
  assert.equal(callbackUrl("https://LOGIN.example.com/", "discord"), expected.discord);
  for (const bad of ["", "login.example.com/evil", "a b.com", "login.example.com?x", "user@login.example.com", "-x.example.com"])
    assert.throws(() => callbackUrl(bad, "google"), "rejects host " + JSON.stringify(bad));
  assert.throws(() => callbackUrl(HOST, "facebook"));
  assert.throws(() => cliGuide("fake", HOST));
});

test("credential validation accepts each provider's real formats and rejects malformed input", () => {
  for (const id of PROVIDER_IDS) {
    const v = validateProviderCredentials(id, { ...VALID[id], unrelated: "ignored" });
    assert.deepEqual(Object.keys(v).sort(), PROVIDERS[id].fields.map(f => f.name).sort(), id);
    assert.ok(!("unrelated" in v));
    for (const field of PROVIDERS[id].fields) {
      if (field.optional) assert.ok(!(field.name in validateProviderCredentials(id, { ...VALID[id], [field.name]: "" })), id + "." + field.name + " optional");
      else assert.throws(() => validateProviderCredentials(id, { ...VALID[id], [field.name]: "" }), id + "." + field.name + " empty");
      assert.throws(() => validateProviderCredentials(id, { ...VALID[id], [field.name]: "x".repeat(20000) }), id + "." + field.name + " huge");
      assert.throws(() => validateProviderCredentials(id, { ...VALID[id], [field.name]: 42 }), id + "." + field.name + " type");
    }
  }
  // Provider-specific formats.
  const bad = {
    google: { clientId: "my-client-id" },
    github: { clientSecret: "not-hex-not-hex-not-hex-not-hex-not-hex!" },
    apple: { teamId: "abcde12345", keyId: "SHORT", clientId: "nodots", privateKey: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----" },
    discord: { clientId: "not-a-snowflake" },
    twitch: { clientId: "UPPERCASEUPPERCASEUPPERCASE123" },
    twitter: { clientSecret: "short" },
    nathan: { issuer: "http://id.example.com/api/auth", trustEmailVerified: "false", displayName: "<script>" }
  };
  for (const issuer of ["https://id.example.com/api/auth/", "https://id.example.com/api/auth?x=1", "https://id.example.com#f",
    "https://user@id.example.com", "javascript:alert(1)", "https://ID.example.com"])
    assert.throws(() => validateProviderCredentials("nathan", { ...VALID.nathan, issuer }), "nathan issuer " + issuer);
  for (const [id, fields] of Object.entries(bad))
    for (const [name, value] of Object.entries(fields))
      assert.throws(() => validateProviderCredentials(id, { ...VALID[id], [name]: value }), id + "." + name + " format");
  for (const id of ["evil", "oauth", "google;DELETE", "", "__proto__", "constructor"])
    assert.throws(() => validateProviderCredentials(id, VALID.google));
  // Trimming and PEM line-ending normalisation.
  assert.equal(validateProviderCredentials("discord", { ...VALID.discord, clientId: "  123456789012345678 " }).clientId, "123456789012345678");
  assert.equal(validateProviderCredentials("apple", { ...VALID.apple, privateKey: apple.pem.replace(/\n/g, "\r\n") }).privateKey, apple.pem.trim());
  // Legacy installer/Studio input shape keeps working.
  assert.equal(validateProviderCredentials("google", { id: "google", ...VALID.google }).clientSecret, VALID.google.clientSecret);
});

test("validation errors never echo a submitted secret", () => {
  const secret = "SECRET-VALUE-THAT-MUST-NOT-LEAK!!";
  for (const id of PROVIDER_IDS) {
    for (const field of PROVIDERS[id].fields.filter(f => f.secret)) {
      try { validateProviderCredentials(id, { ...VALID[id], [field.name]: secret }); assert.fail("accepted"); }
      catch (e) { assert.ok(!String(e.message).includes(secret), id + " message leaks secret"); }
    }
  }
});

test("the Better Auth config builder emits only enabled providers with trust-preserving profile mapping", async () => {
  const resolved = Object.fromEntries(SOCIAL_IDS.map(id => [id, { clientId: "cid-" + id, clientSecret: "secret-" + id }]));
  const built = buildSocialProviders(resolved);
  assert.deepEqual(Object.keys(built), SOCIAL_IDS);
  for (const id of SOCIAL_IDS) {
    assert.equal(built[id].clientId, "cid-" + id);
    assert.equal(built[id].clientSecret, "secret-" + id);
    // Admission stays uniform: no provider may bypass or alter sign-up policy.
    for (const key of ["disableSignUp", "disableImplicitSignUp", "redirectURI", "overrideUserInfoOnSignIn"])
      assert.ok(!(key in built[id]), id + " must not set " + key);
  }
  assert.deepEqual(Object.keys(buildSocialProviders({ discord: resolved.discord })), ["discord"]);
  assert.deepEqual(buildSocialProviders({}), {});
  assert.ok(built.twitch.claims.includes("email_verified"));
  assert.deepEqual(built.discord.scope ?? [], []);

  // Discord: only `verified` emails are kept.
  assert.deepEqual(await built.discord.mapProfileToUser({ id: "42", email: "v@example.com", verified: true }), { emailVerified: true });
  assert.deepEqual(await built.discord.mapProfileToUser({ id: "42", email: "v@example.com", verified: false }),
    { email: "42@discord.placeholder.invalid", emailVerified: false });
  // Twitch: email_verified claim.
  assert.deepEqual(await built.twitch.mapProfileToUser({ sub: "7", email: "t@example.com", email_verified: true }), { emailVerified: true });
  assert.deepEqual((await built.twitch.mapProfileToUser({ sub: "7", email: "t@example.com" })).email, "7@twitch.placeholder.invalid");
  // Apple: boolean or "true".
  assert.deepEqual(await built.apple.mapProfileToUser({ sub: "001.a", email: "a@privaterelay.appleid.com", email_verified: "true" }), { emailVerified: true });
  assert.equal((await built.apple.mapProfileToUser({ sub: "001.a", email: "a@example.com", email_verified: "false" })).emailVerified, false);
  // Google: email_verified claim.
  assert.equal((await built.google.mapProfileToUser({ sub: "g1", email: "g@example.com", email_verified: false })).email, "g1@google.placeholder.invalid");
  // X: only a confirmed email; otherwise a non-routable placeholder.
  assert.deepEqual(await built.twitter.mapProfileToUser({ data: { id: "99", email: "x@example.com" } }), { emailVerified: true });
  assert.deepEqual(await built.twitter.mapProfileToUser({ data: { id: "99" } }), { email: "99@twitter.placeholder.invalid", emailVerified: false });
});

test("GitHub identity uses only the primary verified email", async () => {
  const cases = [
    { emails: [{ email: "pub@example.com", primary: false, verified: true }, { email: "main@example.com", primary: true, verified: true }],
      profileEmail: "pub@example.com", expect: { email: "main@example.com", emailVerified: true } },
    { emails: [{ email: "main@example.com", primary: true, verified: false }, { email: "other@example.com", primary: false, verified: true }],
      profileEmail: null, expect: { email: "5@github.placeholder.invalid", emailVerified: false } },
    { emails: null, profileEmail: "pub@example.com", expect: { email: "5@github.placeholder.invalid", emailVerified: false } }
  ];
  for (const c of cases) {
    const calls = [];
    const fetcher = async (url, init) => {
      calls.push({ url: String(url), auth: init.headers.Authorization });
      if (String(url) === "https://api.github.com/user")
        return Response.json({ id: 5, login: "octo", name: "Octo", email: c.profileEmail, avatar_url: "https://avatars/x" });
      if (String(url) === "https://api.github.com/user/emails")
        return c.emails ? Response.json(c.emails) : new Response("forbidden", { status: 403 });
      return new Response("unexpected", { status: 599 });
    };
    const built = buildSocialProviders({ github: { clientId: "cid", clientSecret: "sec" } }, { fetch: fetcher });
    const info = await built.github.getUserInfo({ accessToken: "gho_token" });
    assert.equal(info.user.email, c.expect.email);
    assert.equal(info.user.emailVerified, c.expect.emailVerified);
    assert.equal(info.user.name, "Octo");
    assert.equal(info.data.id, 5, "account subject stays the GitHub numeric id");
    assert.ok(calls.every(x => x.auth === "Bearer gho_token"));
  }
  const failing = buildSocialProviders({ github: { clientId: "c", clientSecret: "s" } }, { fetch: async () => new Response("x", { status: 500 }) });
  assert.equal(await failing.github.getUserInfo({ accessToken: "t" }), null);
});

test("account linking trusts no provider by name and needs verified emails on both sides", () => {
  assert.deepEqual(ACCOUNT_LINKING, {
    enabled: true, trustedProviders: [], requireLocalEmailVerified: true,
    allowDifferentEmails: false, updateUserInfoOnLink: false
  });
  assert.equal(placeholderEmail("twitter", "123"), "123@twitter.placeholder.invalid");
  assert.match(placeholderEmail("apple", "001234.abc/../def"), /^[A-Za-z0-9._-]+@apple\.placeholder\.invalid$/);
});

test("provider secret fields are encrypted with provider- and field-bound AAD", async () => {
  const master = generateConfigKey();
  const a = await encryptProviderField("apple", "privateKey", apple.pem, master);
  assert.ok(a.startsWith("v2.") && !a.includes("PRIVATE"));
  assert.notEqual(a, await encryptProviderField("apple", "privateKey", apple.pem, master));
  assert.equal(await decryptProviderField("apple", "privateKey", a, master), apple.pem);
  await assert.rejects(() => decryptProviderField("apple", "clientSecret", a, master), "field-bound");
  await assert.rejects(() => decryptProviderField("discord", "privateKey", a, master), "provider-bound");
  await assert.rejects(() => decryptProviderField("apple", "privateKey", a, generateConfigKey()), "key-bound");
  await assert.rejects(() => encryptProviderField("apple", "teamId", "ABCDE12345", master), "non-secret fields are not sealed");
  await assert.rejects(() => encryptProviderField("facebook", "clientSecret", "x".repeat(20), master));
  // v1 ciphertext from before migration 0012 is not a v2 field cipher.
  const legacy = await encryptProviderSecret("google", "legacy-google-secret", master);
  await assert.rejects(() => decryptProviderField("google", "clientSecret", legacy, master));
});

test("Apple client secret is a short-lived ES256 JWT minted from the .p8 key and cached per isolate", async () => {
  clearAppleSecretCache();
  const creds = { clientId: "com.example.login", teamId: "ABCDE12345", keyId: "KEY1234567", privateKey: apple.pem };
  const now = 1_800_000_000;
  const jwt = await mintAppleClientSecret(creds, now);
  const header = decodeProtectedHeader(jwt);
  assert.deepEqual(header, { alg: "ES256", kid: "KEY1234567" });
  const { payload } = await jwtVerify(jwt, apple.publicKey, {
    issuer: "ABCDE12345", subject: "com.example.login", audience: "https://appleid.apple.com",
    algorithms: ["ES256"], currentDate: new Date(now * 1000)
  });
  assert.equal(payload.iat, now);
  assert.ok(payload.exp > now && payload.exp - payload.iat <= 3600, "lifetime at most one hour");
  assert.equal(await mintAppleClientSecret(creds, now + 60), jwt, "cached within its lifetime");
  assert.notEqual(await mintAppleClientSecret(creds, now + 3300), jwt, "re-minted well before expiry");
  assert.notEqual(await mintAppleClientSecret({ ...creds, keyId: "KEY7654321" }, now + 3300), jwt);
  await assert.rejects(() => mintAppleClientSecret({ ...creds, privateKey: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" }, now));
  const other = await appleKey();
  await assert.rejects(async () => jwtVerify(await mintAppleClientSecret({ ...creds, privateKey: other.pem }, now), apple.publicKey,
    { currentDate: new Date(now * 1000) }));
});

test("migration 0012 keeps existing provider rows, moves their state, and admits the six providers", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync("migrations/0006_control_plane.sql", "utf8"));
  db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,enabled,updated_at,updated_by) VALUES (?,?,?,?,?,?)")
    .run("google", "gid-12345", "v1.iv.cipher", 1, 1700000000, "admin-1");
  db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,enabled,updated_at,updated_by) VALUES (?,?,?,?,?,?)")
    .run("github", "ghid-1234", "v1.iv.cipher2", 0, 1700000001, "admin-2");
  db.exec(readFileSync("migrations/0012_social_providers.sql", "utf8"));
  const rows = db.prepare("SELECT * FROM nathan_oauth_providers ORDER BY id").all().map(r => ({ ...r }));
  assert.deepEqual(rows, [
    { id: "github", client_id: "ghid-1234", secret_cipher: "v1.iv.cipher2", config: "{}", secret_fields: "{}", updated_at: 1700000001, updated_by: "admin-2" },
    { id: "google", client_id: "gid-12345", secret_cipher: "v1.iv.cipher", config: "{}", secret_fields: "{}", updated_at: 1700000000, updated_by: "admin-1" }
  ], "the credential table holds credentials only");
  const state = db.prepare("SELECT * FROM nathan_provider_state ORDER BY id").all().map(r => ({ ...r }));
  assert.deepEqual(state, [
    { id: "github", enabled: 0, updated_at: 1700000001, updated_by: "admin-2", tested_at: null, tested_by: null, tested_user: null, tested_version: null },
    { id: "google", enabled: 1, updated_at: 1700000000, updated_by: "admin-1", tested_at: null, tested_by: null, tested_user: null, tested_version: null }
  ], "enabled flags move to the per-provider state table");
  const cols = db.prepare("PRAGMA table_info(nathan_oauth_providers)").all().map(x => x.name);
  for (const forbidden of ["client_secret", "private_key", "refresh_token"]) assert.ok(!cols.includes(forbidden));
  for (const id of ["apple", "discord", "twitch", "twitter"])
    db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_fields,updated_by) VALUES (?,?,?,?)").run(id, "c-" + id, '{"clientSecret":"v2.x.y"}', "a");
  assert.throws(() => db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_fields,updated_by) VALUES ('facebook','c','{\"a\":1}','a')").run(), /CHECK/);
  assert.throws(() => db.prepare("INSERT INTO nathan_provider_state(id,updated_by) VALUES ('facebook','a')").run(), /CHECK/);
  assert.throws(() => db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,updated_by) VALUES ('discord','c','a')").run(), /UNIQUE|CHECK/);
  assert.throws(() => db.prepare("UPDATE nathan_oauth_providers SET secret_cipher=NULL,secret_fields='{}' WHERE id='google'").run(), /CHECK/,
    "a row always carries an encrypted secret");
  assert.throws(() => db.prepare("UPDATE nathan_provider_state SET tested_at=1 WHERE id='google'").run(), /CHECK/,
    "a test record is always bound to a credential version");
  for (const [table, column] of [["nathan_provider_test_tickets", "credential_version"], ["nathan_provider_signins", "credential_version"]])
    assert.ok(db.prepare("PRAGMA table_info(" + table + ")").all().some(c => c.name === column), table + "." + column);
  db.close();
});

// ---- Provider store rules over a D1-shaped adapter on node:sqlite ----
function d1(db) {
  return {
    prepare(sql) {
      let args = [];
      const statement = {
        bind(...values) { args = values; return statement; },
        async all() { return { results: db.prepare(sql).all(...args).map(r => ({ ...r })) }; },
        async first() { const r = db.prepare(sql).get(...args); return r ? { ...r } : null; },
        async run() { const r = db.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; },
        runSync() { const r = db.prepare(sql).run(...args); return { meta: { changes: Number(r.changes) } }; }
      };
      return statement;
    },
    /** D1 batches run as one transaction. */
    async batch(statements) {
      db.exec("BEGIN");
      try { const out = statements.map(s => s.runSync()); db.exec("COMMIT"); return out; }
      catch (e) { db.exec("ROLLBACK"); throw e; }
    }
  };
}
function storeEnv(vars = {}) {
  const db = new DatabaseSync(":memory:");
  for (const f of ["0002_better_auth.sql", "0003_security_audit.sql", "0006_control_plane.sql", "0012_social_providers.sql", "0019_nathan_upstream.sql"])
    db.exec(readFileSync("migrations/" + f, "utf8"));
  const events = [];
  const audit = async (_env, actor, action, target, outcome) => { events.push({ actor, action, target, outcome }); };
  // Stand-in for isAdminPrincipal: a verified admin-role user with a live grant.
  const grants = new Set();
  const isAdmin = async u => u.role === "admin" && u.emailVerified === true && grants.has(u.id);
  const deps = { audit, isAdmin };
  const env = { DB: d1(db), NATHAN_ISSUER: "https://" + HOST, NATHAN_CONFIG_KEY: generateConfigKey(),
    BETTER_AUTH_SECRET: "x".repeat(40), ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false", ...vars };
  const addUser = (id, email, { admin = false, password = false } = {}) => {
    db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,1,0,0,?)')
      .run(id, id, email, admin ? "admin" : "user");
    if (admin) grants.add(id);
    if (password) db.prepare('INSERT INTO "account"("id","accountId","providerId","userId","password","createdAt","updatedAt") VALUES (?,?,?,?,?,0,0)')
      .run("acct-" + id, id, "credential", id, "scrypt-hash");
  };
  return { db, env, audit, deps, events, grants, addUser };
}
const state = (db, id) => db.prepare("SELECT * FROM nathan_provider_state WHERE id=?").get(id);
const credentialRow = (db, id) => db.prepare("SELECT * FROM nathan_oauth_providers WHERE id=?").get(id);
/** Runs a Studio test sign-in for `id`, with the provider callback signing in `userId`. */
async function provenTest(env, deps, id, userId, admin = "admin") {
  const { ticket } = await beginProviderTest(env, { id }, admin, deps);
  const sessionId = "s-" + id + "-" + userId + "-" + Math.random();
  await recordProviderSignIn(env, { providerId: id, sessionId, userId });
  return completeProviderTest(env, ticket, { sessionId, userId }, deps);
}

test("stored credentials round-trip, never return secrets, and rotation clears the test record", async () => {
  const { db, env, deps, events, addUser } = storeEnv();
  addUser("admin", "admin@example.com", { admin: true });
  await assert.rejects(() => upsertSocialProvider(env, { id: "apple", ...VALID.apple, privateKey: apple.pem.replace("A", "!") }, "admin", deps));
  await upsertSocialProvider(env, { id: "apple", fields: VALID.apple }, "admin", deps);
  await upsertSocialProvider(env, { id: "discord", ...VALID.discord }, "admin", deps);
  const raw = JSON.stringify(db.prepare("SELECT * FROM nathan_oauth_providers").all());
  for (const secret of [VALID.discord.clientSecret, "PRIVATE KEY", apple.pem.split("\n")[1]]) assert.ok(!raw.includes(secret));
  const status = await providerStatus(env, deps);
  assert.deepEqual(status.map(s => s.id), PROVIDER_IDS);
  const text = JSON.stringify(status);
  for (const secret of [VALID.discord.clientSecret, VALID.apple.privateKey.split("\n")[1]]) assert.ok(!text.includes(secret), "status leaks a secret");
  const appleStatus = status.find(s => s.id === "apple");
  assert.deepEqual(appleStatus.values, { clientId: "com.example.login", teamId: "ABCDE12345", keyId: "KEY1234567" });
  assert.deepEqual(appleStatus.secretsSet, ["privateKey"]);
  assert.equal(appleStatus.callbackUrl, "https://" + HOST + "/api/auth/callback/apple");
  assert.equal(appleStatus.enabled, true);
  assert.equal(appleStatus.source, "encrypted-d1");

  const creds = await loadSocialProviderCredentials(env);
  assert.deepEqual(Object.keys(creds), ["apple", "discord"]);
  assert.equal(creds.discord.clientSecret, VALID.discord.clientSecret);
  const { payload } = await jwtVerify(creds.apple.clientSecret, apple.publicKey, { audience: "https://appleid.apple.com" });
  assert.equal(payload.sub, "com.example.login");

  await provenTest(env, deps, "discord", "admin");
  assert.ok(state(db, "discord").tested_at > 0);
  await upsertSocialProvider(env, { id: "discord", ...VALID.discord, clientSecret: "ZyXwVuTsRqPoNmLkJiHgFeDcBa987654" }, "admin2", deps);
  const cleared = state(db, "discord");
  assert.deepEqual([cleared.tested_at, cleared.tested_by, cleared.tested_user, cleared.tested_version], [null, null, null, null]);
  assert.equal((await loadSocialProviderCredentials(env)).discord.clientSecret, "ZyXwVuTsRqPoNmLkJiHgFeDcBa987654");
  assert.ok(events.some(e => e.action === "oauth_provider_update" && e.target === "apple" && e.outcome === "succeeded"));
  assert.ok(!JSON.stringify(events).includes(VALID.discord.clientSecret));
  await assert.rejects(() => upsertSocialProvider({ ...env, NATHAN_CONFIG_KEY: undefined }, { id: "discord", ...VALID.discord }, "a", deps));
});

test("a CLI rotation after a Studio test or toggle takes effect and voids the old test", async () => {
  const { db, env, deps, addUser } = storeEnv({ NATHAN_PROVIDER_TWITCH: JSON.stringify(VALID.twitch) });
  addUser("admin", "admin@example.com", { admin: true });
  // Configure Twitch through the CLI, then toggle and test it in Studio.
  await setSocialProviderEnabled(env, { id: "twitch", enabled: true, confirm: "CONFIRM ENABLE twitch" }, "admin", deps);
  const done = await provenTest(env, deps, "twitch", "admin");
  assert.equal(done.id, "twitch");
  assert.equal(credentialRow(db, "twitch"), undefined, "Studio never copies Worker-secret credentials into D1");
  assert.ok((await providerStatus(env, deps)).find(s => s.id === "twitch").testedAt > 0);

  // `nathan providers add twitch --apply` with a new secret.
  const rotated = { ...VALID.twitch, clientSecret: "zyxwvutsrqponmlkjihgfedcba9876" };
  env.NATHAN_PROVIDER_TWITCH = JSON.stringify(rotated);
  assert.deepEqual((await loadSocialProviderCredentials(env)).twitch, rotated, "the rotated CLI secret is used");
  const status = (await providerStatus(env, deps)).find(s => s.id === "twitch");
  assert.equal(status.source, "worker-secret");
  assert.equal(status.secretName, "NATHAN_PROVIDER_TWITCH");
  assert.equal(status.testedAt, null, "a credential change voids the previous test");
  assert.equal(status.testStale, true);
  assert.equal(status.canSaveInStudio, false);
  // The CLI says exactly that, instead of claiming Studio credentials take precedence.
  const notice = cliSecretNotice("twitch");
  for (const claim of [/NATHAN_PROVIDER_TWITCH/, /overrides credentials saved in Identity Studio/, /voids the previous test/,
    /wrangler secret delete NATHAN_PROVIDER_TWITCH/, /stays disabled/]) assert.match(notice, claim);
  assert.doesNotMatch(notice, /Studio take precedence/);
});

test("each provider has one source of truth and a shadowed credential is never silent", async () => {
  const { db, env, deps, events, addUser } = storeEnv({ GITHUB_CLIENT_ID: "Ov23liLegacyClient00", GITHUB_CLIENT_SECRET: "legacy-github-secret" });
  addUser("admin", "admin@example.com", { admin: true });
  const cipher = await encryptProviderSecret("google", "legacy-google-secret", env.NATHAN_CONFIG_KEY);
  db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,updated_by) VALUES ('google','gid-legacy',?,'old')").run(cipher);
  env.NATHAN_PROVIDER_TWITCH = JSON.stringify(VALID.twitch);
  env.NATHAN_PROVIDER_DISCORD = "{not json";
  await upsertSocialProvider(env, { id: "discord", ...VALID.discord }, "admin", deps).catch(() => {});
  const creds = await loadSocialProviderCredentials(env);
  assert.deepEqual(creds.google, { clientId: "gid-legacy", clientSecret: "legacy-google-secret" }, "pre-0012 v1 row");
  assert.deepEqual(creds.github, { clientId: "Ov23liLegacyClient00", clientSecret: "legacy-github-secret" });
  assert.deepEqual(creds.twitch, VALID.twitch);
  assert.ok(!creds.discord, "a malformed CLI secret fails closed for that provider only");
  let status = await providerStatus(env, deps);
  const by = id => status.find(s => s.id === id);
  assert.equal(by("github").source, "legacy-worker-secret");
  assert.equal(by("google").source, "encrypted-d1");
  assert.equal(by("discord").source, "worker-secret");
  assert.match(by("discord").error, /NATHAN_PROVIDER_DISCORD/);
  assert.equal(credentialRow(db, "discord"), undefined, "Studio refuses to save over a CLI-managed provider");

  // Studio save while the CLI secret exists is refused loudly, with exact instructions, and audited.
  await assert.rejects(() => upsertSocialProvider(env, { id: "twitch", ...VALID.twitch }, "admin", deps),
    e => /NATHAN_PROVIDER_TWITCH/.test(e.publicMessage) && /wrangler secret delete NATHAN_PROVIDER_TWITCH/.test(e.publicMessage) &&
      /providers add twitch --apply/.test(e.publicMessage));
  assert.ok(events.some(e => e.action === "oauth_provider_update" && e.target === "twitch" && e.outcome === "denied_worker_secret"));

  // Toggling a legacy-secret provider does not copy it into D1, so changing the legacy secret still takes effect.
  await provenTest(env, deps, "google", "admin");
  await setSocialProviderEnabled(env, { id: "github", enabled: false, confirm: "CONFIRM DISABLE github" }, "admin", deps);
  assert.equal(credentialRow(db, "github"), undefined);
  assert.ok(!(await loadSocialProviderCredentials(env)).github, "disabled");
  await setSocialProviderEnabled(env, { id: "github", enabled: true, confirm: "CONFIRM ENABLE github" }, "admin", deps);
  env.GITHUB_CLIENT_SECRET = "legacy-github-secret-rotated";
  assert.deepEqual((await loadSocialProviderCredentials(env)).github, { clientId: "Ov23liLegacyClient00", clientSecret: "legacy-github-secret-rotated" });

  // A CLI secret added after Studio credentials wins, and Studio says the D1 row is unused.
  env.NATHAN_PROVIDER_GOOGLE = JSON.stringify(VALID.google);
  assert.deepEqual((await loadSocialProviderCredentials(env)).google, VALID.google);
  status = await providerStatus(env, deps);
  assert.equal(by("google").source, "worker-secret");
  assert.deepEqual(by("google").shadowed.map(s => s.source), ["encrypted-d1"]);
  assert.ok(by("google").notices.some(n => /not used/.test(n) && /NATHAN_PROVIDER_GOOGLE/.test(n)));
  // Studio credentials override legacy Worker secrets, and Studio says the legacy secrets are unused.
  await upsertSocialProvider(env, { id: "github", ...VALID.github }, "admin", deps);
  status = await providerStatus(env, deps);
  assert.equal(by("github").source, "encrypted-d1");
  assert.ok(by("github").notices.some(n => /GITHUB_CLIENT_SECRET/.test(n) && /not used/.test(n)));
  // NATH-17: a stored provider that cannot be decrypted turns off only that provider, never falls back
  // to the legacy secrets it overrides, and is reported unavailable (it used to fail every request).
  const keyless = { ...env, NATHAN_CONFIG_KEY: undefined };
  const isolated = await loadSocialProviderState(keyless);
  assert.ok(!isolated.credentials.github, "the undecryptable D1 provider is off");
  assert.deepEqual(isolated.credentials.twitch, VALID.twitch, "other providers keep working");
  assert.deepEqual(isolated.credentials.google, VALID.google, "including the CLI-managed one");
  assert.deepEqual(isolated.unavailable, [{ id: "github", reason: "decrypt_failed" }, { id: "discord", reason: "invalid_worker_secret" }]);
  assert.ok(!JSON.stringify(await loadSocialProviderCredentials(keyless)).includes("legacy-github-secret"), "no fallback to the legacy secrets");
});

test("test tickets are bound to the credential version they were issued for", async () => {
  const { db, env, deps, events, addUser } = storeEnv({ NATHAN_PROVIDER_TWITCH: JSON.stringify(VALID.twitch) });
  addUser("admin", "admin@example.com", { admin: true });
  await upsertSocialProvider(env, { id: "discord", ...VALID.discord }, "admin", deps);
  const v1 = await credentialVersion(env, "discord", VALID.discord);
  assert.match(v1, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(!v1.includes(VALID.discord.clientSecret));
  assert.notEqual(await credentialVersion(env, "discord", { ...VALID.discord, clientSecret: "other-secret-other-secret-1234" }), v1);
  const issued = await beginProviderTest(env, { id: "discord" }, "admin", deps);
  assert.equal(db.prepare("SELECT credential_version FROM nathan_provider_test_tickets").get().credential_version, v1);

  // Rotating in Studio between start and finish invalidates the open ticket.
  await recordProviderSignIn(env, { providerId: "discord", sessionId: "s1", userId: "admin" });
  await upsertSocialProvider(env, { id: "discord", ...VALID.discord, clientSecret: "ZyXwVuTsRqPoNmLkJiHgFeDcBa987654" }, "admin", deps);
  await assert.rejects(() => completeProviderTest(env, issued.ticket, { sessionId: "s1", userId: "admin" }, deps), /ticket/);
  assert.equal(state(db, "discord").tested_at, null);

  // Evidence recorded under the old credentials does not prove the new ones.
  const afterRotation = await beginProviderTest(env, { id: "discord" }, "admin", deps);
  db.prepare("UPDATE nathan_provider_signins SET created_at=unixepoch()+1 WHERE session_id='s1'").run();
  await assert.rejects(() => completeProviderTest(env, afterRotation.ticket, { sessionId: "s1", userId: "admin" }, deps), /evidence|changed/);

  // A CLI rotation between start and finish (no D1 write to hook) fails on the version check.
  const cli = await beginProviderTest(env, { id: "twitch" }, "admin", deps);
  await recordProviderSignIn(env, { providerId: "twitch", sessionId: "s2", userId: "admin" });
  env.NATHAN_PROVIDER_TWITCH = JSON.stringify({ ...VALID.twitch, clientSecret: "zyxwvutsrqponmlkjihgfedcba9876" });
  await assert.rejects(() => completeProviderTest(env, cli.ticket, { sessionId: "s2", userId: "admin" }, deps), /changed/);
  assert.equal(state(db, "twitch")?.tested_at ?? null, null);
  assert.ok(events.some(e => e.action === "oauth_provider_test" && e.target === "twitch" && e.outcome === "failed_credentials_changed"));

  // Same credentials end to end: recorded against that version.
  const ok = await provenTest(env, deps, "twitch", "admin");
  assert.equal(ok.adminVerified, true);
  assert.equal(state(db, "twitch").tested_version, await credentialVersion(env, "twitch", JSON.parse(env.NATHAN_PROVIDER_TWITCH)));
});

test("ticket mechanics: single use, unexpired, digest only, evidence after issue, same provider and user", async () => {
  const { db, env, deps, events, addUser } = storeEnv();
  addUser("admin", "admin@example.com", { admin: true });
  await upsertSocialProvider(env, { id: "discord", ...VALID.discord }, "admin", deps);
  await assert.rejects(() => beginProviderTest(env, { id: "apple" }, "admin", deps), /enabled/);
  const { ticket, callbackURL } = await beginProviderTest(env, { id: "discord" }, "admin", deps);
  assert.match(ticket, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(callbackURL, "/studio/providers/test-complete?ticket=" + ticket);
  assert.ok(!JSON.stringify(db.prepare("SELECT * FROM nathan_provider_test_tickets").all()).includes(ticket), "only a digest is stored");
  // A failed attempt consumes the ticket.
  await assert.rejects(() => completeProviderTest(env, ticket, { sessionId: "s-none", userId: "admin" }, deps), /evidence/);
  await assert.rejects(() => completeProviderTest(env, ticket, { sessionId: "s-none", userId: "admin" }, deps), /ticket/);
  await recordProviderSignIn(env, { providerId: "discord", sessionId: "s-discord", userId: "admin" });
  const wrongUser = await beginProviderTest(env, { id: "discord" }, "admin", deps);
  await assert.rejects(() => completeProviderTest(env, wrongUser.ticket, { sessionId: "s-discord", userId: "u3" }, deps), /evidence/);
  const second = await beginProviderTest(env, { id: "discord" }, "admin", deps);
  db.prepare("UPDATE nathan_provider_test_tickets SET expires_at=unixepoch()-1").run();
  await assert.rejects(() => completeProviderTest(env, second.ticket, { sessionId: "s-discord", userId: "admin" }, deps), /ticket/);
  const third = await beginProviderTest(env, { id: "discord" }, "admin", deps);
  db.prepare("UPDATE nathan_provider_signins SET created_at=created_at-3600").run();
  await assert.rejects(() => completeProviderTest(env, third.ticket, { sessionId: "s-discord", userId: "admin" }, deps), /evidence/);
  await assert.rejects(() => completeProviderTest(env, "x".repeat(43), { sessionId: "s-discord", userId: "admin" }, deps), /ticket/);
  assert.equal(state(db, "discord").tested_at, null);
  const fresh = await provenTest(env, deps, "discord", "admin");
  assert.equal(fresh.id, "discord");
  const row = state(db, "discord");
  assert.ok(row.tested_at > 0);
  assert.equal(row.tested_by, "admin");
  assert.equal(row.tested_user, "admin");
  assert.ok(events.some(e => e.action === "oauth_provider_test" && e.outcome === "succeeded" && e.actor === "admin"));
});

test("the last login method rule protects administrator access, atomically", async () => {
  const { db, env, deps, events, grants, addUser } = storeEnv();
  addUser("admin", "admin@example.com", { admin: true });
  addUser("member", "tester@example.com");
  for (const id of ["discord", "twitch", "github"]) await upsertSocialProvider(env, { id, ...VALID[id] }, "admin", deps);
  await assert.rejects(() => setSocialProviderEnabled(env, { id: "discord", enabled: false, confirm: "confirm disable discord" }, "admin", deps), /confirmation/);
  assert.ok(events.some(e => e.action === "oauth_provider_disable" && e.target === "discord" && e.outcome === "denied_confirmation"));
  await assert.rejects(() => setSocialProviderEnabled(env, { id: "discord", enabled: false, confirm: "CONFIRM DISABLE discord" }, "admin", deps),
    /last/, "an untested provider cannot become the only login method");
  assert.ok(events.some(e => e.action === "oauth_provider_disable" && e.target === "discord" && e.outcome === "denied_last_method"));

  // A test sign-in with a non-admin test account proves the provider works, not that admins can use it.
  const byTester = await provenTest(env, deps, "twitch", "member");
  assert.equal(byTester.adminVerified, false);
  assert.equal((await providerStatus(env, deps)).find(s => s.id === "twitch").testedByAdmin, false);
  await assert.rejects(() => setSocialProviderEnabled(env, { id: "discord", enabled: false, confirm: "CONFIRM DISABLE discord" }, "admin", deps), /last/);

  // Tested by a current admin: the other provider may now be disabled.
  await provenTest(env, deps, "twitch", "admin");
  assert.deepEqual(await setSocialProviderEnabled(env, { id: "discord", enabled: false, confirm: "CONFIRM DISABLE discord" }, "admin", deps),
    { id: "discord", enabled: false });
  await assert.rejects(() => setSocialProviderEnabled(env, { id: "twitch", enabled: false, confirm: "CONFIRM DISABLE twitch" }, "admin", deps), /last/);

  // Revoking that admin removes the protection.
  await provenTest(env, deps, "github", "admin");
  grants.delete("admin");
  addUser("admin2", "admin2@example.com", { admin: true });
  await assert.rejects(() => setSocialProviderEnabled(env, { id: "twitch", enabled: false, confirm: "CONFIRM DISABLE twitch" }, "admin2", deps), /last/);
  grants.add("admin");

  // Password sign-in counts only when an admin has a password; enterprise SSO only for an admin's verified domain.
  await assert.rejects(() => setSocialProviderEnabled({ ...env, ENABLE_PASSWORD: "true" },
    { id: "github", enabled: false, confirm: "CONFIRM DISABLE github" }, "admin", deps).then(() =>
    setSocialProviderEnabled({ ...env, ENABLE_PASSWORD: "true" }, { id: "twitch", enabled: false, confirm: "CONFIRM DISABLE twitch" }, "admin", deps)), /last/);
  addUser("admin3", "admin3@corp.example", { admin: true, password: true });
  assert.ok(await setSocialProviderEnabled({ ...env, ENABLE_PASSWORD: "true" }, { id: "twitch", enabled: false, confirm: "CONFIRM DISABLE twitch" }, "admin", deps));
  db.prepare('DELETE FROM "account" WHERE "providerId"=\'credential\'').run();
  await setSocialProviderEnabled(env, { id: "twitch", enabled: true, confirm: "CONFIRM ENABLE twitch" }, "admin", deps);
  await provenTest(env, deps, "twitch", "admin");
  db.prepare('INSERT INTO "ssoProvider"("id","issuer","userId","providerId","domain","domainVerified") VALUES (\'sso1\',\'https://idp.corp.example\',\'admin3\',\'corp\',\'corp.example\',0)').run();
  await assert.rejects(() => setSocialProviderEnabled({ ...env, ENTERPRISE_SSO: "true" }, { id: "twitch", enabled: false, confirm: "CONFIRM DISABLE twitch" }, "admin", deps), /last/,
    "an unverified SSO domain is not a recovery path");
  db.prepare('UPDATE "ssoProvider" SET "domainVerified"=1').run();
  assert.ok(await setSocialProviderEnabled({ ...env, ENTERPRISE_SSO: "true" }, { id: "twitch", enabled: false, confirm: "CONFIRM DISABLE twitch" }, "admin", deps));

  assert.ok(await setSocialProviderEnabled(env, { id: "discord", enabled: true, confirm: "CONFIRM ENABLE discord" }, "admin", deps));
  await assert.rejects(() => setSocialProviderEnabled(env, { id: "apple", enabled: true, confirm: "CONFIRM ENABLE apple" }, "admin", deps), /configure/);
  assert.ok(events.some(e => e.action === "oauth_provider_disable" && e.target === "discord" && e.outcome === "succeeded"));
});

test("two concurrent disables cannot both pass the last-method check", async () => {
  const { db, env, deps, addUser } = storeEnv();
  addUser("admin", "admin@example.com", { admin: true });
  for (const id of ["discord", "twitch"]) {
    await upsertSocialProvider(env, { id, ...VALID[id] }, "admin", deps);
    await provenTest(env, deps, id, "admin");
  }
  const results = await Promise.allSettled(["discord", "twitch"].map(id =>
    setSocialProviderEnabled(env, { id, enabled: false, confirm: "CONFIRM DISABLE " + id }, "admin", deps)));
  assert.deepEqual(results.map(r => r.status).sort(), ["fulfilled", "rejected"]);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_provider_state WHERE enabled=1").get().n, 1, "one tested method remains");
});

test("provider updates audit attempts, validation failures and denials without secret values", async () => {
  const { env, deps, events, addUser } = storeEnv();
  addUser("admin", "admin@example.com", { admin: true });
  await assert.rejects(() => upsertSocialProvider(env, { id: "twitch", fields: { clientId: "abc", clientSecret: "SECRET-SHOULD-NOT-ECHO-123456" } }, "admin", deps), /wrong format/);
  await assert.rejects(() => upsertSocialProvider(env, { id: "facebook", clientId: "abc", clientSecret: "SECRET-SHOULD-NOT-ECHO-123456" }, "admin", deps), /Unsupported/);
  await assert.rejects(() => upsertSocialProvider({ ...env, NATHAN_CONFIG_KEY: undefined }, { id: "twitch", ...VALID.twitch }, "admin", deps), /NATHAN_CONFIG_KEY/);
  const updates = events.filter(e => e.action === "oauth_provider_update").map(e => [e.target, e.outcome]);
  assert.deepEqual(updates, [
    ["twitch", "attempted"], ["twitch", "failed_validation"],
    ["unsupported", "attempted"], ["unsupported", "failed_validation"],
    ["twitch", "attempted"], ["twitch", "failed_config_key"]
  ]);
  const text = JSON.stringify(events);
  for (const secret of ["SECRET-SHOULD-NOT-ECHO", VALID.twitch.clientSecret, "facebook"]) assert.ok(!text.includes(secret));
});
