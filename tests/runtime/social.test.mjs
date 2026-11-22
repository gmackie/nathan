/**
 * NATH-9 social login in workerd: sign-in redirects (state, PKCE, exact redirect_uri),
 * callback round trips against mocked provider endpoints, verified-email-only linking, the
 * Studio provider API and test sign-in through the real Better Auth after-hook, credential
 * rotation during a test, and identical callback URLs on all three surfaces.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { SignJWT, jwtVerify, generateKeyPair, exportJWK } from "jose";
import { authWorker, bundle, migrate, start, randomKey } from "./helpers.mjs";
import { sealProviderCredentials } from "../../src/auth/config-crypto.mjs";
import { PROVIDER_IDS } from "../../src/shared/providers.mjs";
import { providerGuide as cliGuide } from "../../scripts/lib/provider-wizard.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST;
const KEY = randomKey();
const CREDS = {
  discord: { clientId: "123456789012345678", clientSecret: "AbCdEfGhIjKlMnOpQrStUvWxYz012345" },
  twitter: { clientId: "M1M5R3BMVy13QmpScXkzTUt5OE46MTpjaQ", clientSecret: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDeFgHiJ" }
};
const appleKeys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const applePem = "-----BEGIN PRIVATE KEY-----\n" +
  Buffer.from(await crypto.subtle.exportKey("pkcs8", appleKeys.privateKey)).toString("base64").match(/.{1,64}/g).join("\n") +
  "\n-----END PRIVATE KEY-----";
CREDS.apple = { clientId: "com.example.login", teamId: "ABCDE12345", keyId: "KEY1234567", privateKey: applePem };
// The mocked Apple signs ID tokens with an RS256 key it publishes at /auth/keys, like Apple.
const APPLE_KID = "apple-test-kid";
const appleIdp = await generateKeyPair("RS256", { extractable: true });
const appleJwks = { keys: [{ ...await exportJWK(appleIdp.publicKey), kid: APPLE_KID, alg: "RS256", use: "sig" }] };
const appleIdToken = (claims, key = appleIdp.privateKey) => new SignJWT({ email_verified: "true", ...claims })
  .setProtectedHeader({ alg: "RS256", kid: APPLE_KID }).setIssuer("https://appleid.apple.com").setAudience("com.example.login")
  .setIssuedAt().setExpirationTime("5m").sign(key);

/** Mocked provider behaviour, keyed by the authorization code the test sends back. */
const codes = new Map();
const seen = [];
async function outbound(request) {
  const url = new URL(request.url);
  const body = request.method === "POST" ? new URLSearchParams(await request.text()) : null;
  seen.push({ url: url.href, method: request.method, body, authorization: request.headers.get("authorization") });
  if (url.href === "https://appleid.apple.com/auth/keys") return Response.json(appleJwks);
  if (url.href === "https://discord.com/api/oauth2/token" || url.href === "https://api.x.com/2/oauth2/token" ||
      url.href === "https://appleid.apple.com/auth/token") {
    const grant = codes.get(body.get("code"));
    if (!grant) return Response.json({ error: "invalid_grant" }, { status: 400 });
    grant.tokenRequest = { body, authorization: request.headers.get("authorization") };
    const token = { access_token: "at-" + body.get("code"), token_type: "Bearer", expires_in: 3600 };
    if (grant.idToken) token.id_token = await grant.idToken();
    return Response.json(token);
  }
  const bearer = (request.headers.get("authorization") || "").replace(/^Bearer at-/, "");
  const grant = codes.get(bearer);
  if (url.origin + decodeURIComponent(url.pathname) === "https://discord.com/api/users/@me" && grant)
    return Response.json({ id: grant.id, username: "user" + grant.id, global_name: null, avatar: null, discriminator: "0",
      email: grant.email, verified: grant.verified });
  if (url.origin + url.pathname === "https://api.x.com/2/users/me" && grant) {
    if (url.searchParams.get("user.fields") === "confirmed_email")
      return grant.email ? Response.json({ data: { id: grant.id, confirmed_email: grant.email } }) : Response.json({ data: { id: grant.id } });
    return Response.json({ data: { id: grant.id, name: "X user", username: "x" + grant.id } });
  }
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

let mf, db;
const instances = [];
before(async () => {
  mf = await authWorker(HOST, {
    NATHAN_CONFIG_KEY: KEY, NATHAN_BOOTSTRAP_REQUIRED: "false", NATHAN_ADMIN_STEPUP_REQUIRED: "false",
    NATHAN_SECURITY_PROFILE: "standard"
  }, { outboundService: outbound });
  instances.push(mf);
  db = await mf.getD1Database("DB");
  // NATH-16: these tests cover provider sign-in and linking in a self-service installation;
  // invitation-only admission is tested in admission.test.mjs.
  await db.prepare("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','test')").run();
  for (const [id, values] of Object.entries(CREDS)) {
    const sealed = await sealProviderCredentials(id, values, KEY);
    await db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,config,secret_fields,updated_by) VALUES (?,?,?,?,'test')")
      .bind(id, sealed.clientId, sealed.config, sealed.secretFields).run();
  }
});
after(() => Promise.all(instances.map(m => m.dispose())));

/**
 * A browser cookie jar that keeps each cookie's SameSite attribute and applies it the way
 * browsers do: Strict cookies only on same-site requests, Lax (and unmarked) cookies also on
 * cross-site top-level GET navigations, never on cross-site POSTs; None cookies always.
 */
function jarOf(init = {}) { return { ...init }; }
function merge(jar, response) {
  for (const line of response.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(";");
    const name = pair.slice(0, pair.indexOf("=")), value = pair.slice(pair.indexOf("=") + 1);
    const sameSite = (attrs.map(a => a.trim().split("=")).find(([k]) => k.toLowerCase() === "samesite")?.[1] || "lax").toLowerCase();
    const expired = !value || attrs.some(a => /^max-age=0$/i.test(a.trim()));
    if (expired) delete jar[name]; else jar[name] = { value, sameSite, raw: line };
  }
  return jar;
}
function cookieHeader(jar, context = "same-site") {
  return Object.entries(jar).filter(([, c]) => c.sameSite === "none" || context === "same-site" ||
    (context === "cross-site-get" && c.sameSite === "lax")).map(([k, c]) => k + "=" + c.value).join("; ");
}

let clients = 0;
/** Starts a social sign-in exactly like the sign-in page does (a same-origin fetch). */
async function begin(provider, jar = jarOf(), callbackURL = "/", extra = {}) {
  const response = await mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/social", {
    method: "POST", redirect: "manual",
    // Each simulated browser gets its own client IP, as Better Auth rate-limits sign-in per IP.
    headers: { "Content-Type": "application/json", Origin: ORIGIN, Cookie: cookieHeader(jar), "cf-connecting-ip": "198.51.100." + (++clients) },
    body: JSON.stringify({ provider, callbackURL, ...extra })
  });
  assert.equal(response.status, 200, "sign-in/social: " + response.status + " " + await response.clone().text());
  merge(jar, response);
  const { url } = await response.json();
  return { authorize: new URL(url), jar };
}
/** The provider redirects the browser back: a cross-site top-level GET navigation. */
async function callback(provider, code, state, jar, headers = {}) {
  const response = await mf.dispatchFetch(ORIGIN + "/api/auth/callback/" + provider + "?code=" + code + "&state=" + encodeURIComponent(state),
    { redirect: "manual", headers: { Cookie: cookieHeader(jar, "cross-site-get"), ...headers } });
  merge(jar, response);
  return response;
}
/** Follows a same-site redirect (or opens a same-origin page) in the given browser. */
async function visit(path, jar) {
  const response = await mf.dispatchFetch(new URL(path, ORIGIN).href, { redirect: "manual", headers: { Cookie: cookieHeader(jar) } });
  merge(jar, response);
  return response;
}
/** A full sign-in round trip through a mocked provider, landing on `callbackURL`. */
async function signIn(provider, code, grant, jar = jarOf(), callbackURL = "/") {
  const started = await begin(provider, jar, callbackURL);
  codes.set(code, grant);
  const back = await callback(provider, code, started.authorize.searchParams.get("state"), jar);
  assert.equal(back.status, 302, await back.clone().text());
  assert.equal(back.headers.get("Location"), callbackURL);
  return jar;
}
async function userFor(provider, accountId) {
  return db.prepare('SELECT u."id" AS id,u."email" AS email,u."emailVerified" AS verified FROM "account" a JOIN "user" u ON u."id"=a."userId" WHERE a."providerId"=? AND a."accountId"=?')
    .bind(provider, accountId).first();
}
const providerState = id => db.prepare("SELECT * FROM nathan_provider_state WHERE id=?").bind(id).first();
const auditRows = async () => (await db.prepare("SELECT actor,action,target,outcome FROM nathan_security_audit WHERE action LIKE 'oauth_provider_%' ORDER BY rowid").all()).results;
const post = (path, body, jar) => mf.dispatchFetch(ORIGIN + path, { method: "POST",
  headers: { "Content-Type": "application/json", Origin: ORIGIN, Cookie: cookieHeader(jar) }, body: JSON.stringify(body) });

test("sign-in page shows every enabled provider by display name", async () => {
  const html = await (await mf.dispatchFetch(ORIGIN + "/sign-in")).text();
  for (const name of ["Discord", "X", "Apple"]) assert.ok(html.includes("Continue with " + name), name);
  assert.ok(!html.includes("Continue with Google") && !html.includes("Continue with Twitch"), "unconfigured providers are hidden");
});

let adminJar, memberJar;
test("Discord redirect carries state and the exact redirect_uri; only verified emails are trusted", async () => {
  const { authorize, jar } = await begin("discord");
  assert.equal(authorize.origin + authorize.pathname, "https://discord.com/api/oauth2/authorize");
  assert.equal(authorize.searchParams.get("client_id"), CREDS.discord.clientId);
  assert.equal(authorize.searchParams.get("redirect_uri"), ORIGIN + "/api/auth/callback/discord");
  assert.equal(authorize.searchParams.get("response_type"), "code");
  assert.equal(authorize.searchParams.get("scope"), "identify email");
  // Better Auth 1.7.14 sends no PKCE to Discord; state plus the confidential secret protect the flow.
  assert.ok(!authorize.searchParams.has("code_challenge"));
  const state = authorize.searchParams.get("state");
  assert.ok(state && state.length >= 32, "unguessable state");

  // A forged or replayed state is refused before any token request.
  const forged = await callback("discord", "dc-forged", "x".repeat(32), jarOf(jar));
  assert.equal(forged.status, 302);
  assert.match(forged.headers.get("Location"), /error=/);
  assert.ok(!seen.some(s => s.body?.get("code") === "dc-forged"), "no token exchange for a forged state");

  codes.set("dc-admin", { id: "100000000000000001", email: "admin@example.test", verified: true });
  const ok = await callback("discord", "dc-admin", state, jar);
  assert.equal(ok.status, 302, await ok.clone().text());
  assert.equal(ok.headers.get("Location"), "/");
  const exchange = codes.get("dc-admin").tokenRequest;
  assert.equal(exchange.body.get("redirect_uri"), ORIGIN + "/api/auth/callback/discord");
  assert.ok(jar["__Secure-nathan.session_token"], "session cookie issued");
  const admin = await userFor("discord", "100000000000000001");
  assert.equal(admin.email, "admin@example.test");
  assert.equal(admin.verified, 1);
  const replay = await callback("discord", "dc-admin", state, jarOf());
  assert.match(replay.headers.get("Location") || "", /error=/, "state is single use");
  adminJar = jar;

  // An unverified Discord email for the same address never links and never squats the address.
  const second = await begin("discord");
  codes.set("dc-squat", { id: "100000000000000002", email: "admin@example.test", verified: false });
  const squat = await callback("discord", "dc-squat", second.authorize.searchParams.get("state"), second.jar);
  assert.equal(squat.status, 302);
  const squatter = await userFor("discord", "100000000000000002");
  assert.equal(squatter.email, "100000000000000002@discord.placeholder.invalid");
  assert.equal(squatter.verified, 0);
  assert.notEqual(squatter.id, admin.id);

  // A verified ordinary member: signed in, but not a Nathan administrator.
  memberJar = await signIn("discord", "dc-member", { id: "100000000000000003", email: "member@example.test", verified: true });
  assert.equal((await userFor("discord", "100000000000000003")).verified, 1);
});

test("X redirect uses S256 PKCE; the token exchange proves the verifier; only a confirmed email links", async () => {
  const { authorize, jar } = await begin("twitter");
  assert.equal(authorize.origin + authorize.pathname, "https://x.com/i/oauth2/authorize");
  assert.equal(authorize.searchParams.get("redirect_uri"), ORIGIN + "/api/auth/callback/twitter");
  assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
  const challenge = authorize.searchParams.get("code_challenge");
  assert.match(challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(authorize.searchParams.get("state"));

  codes.set("x-none", { id: "777" });
  const response = await callback("twitter", "x-none", authorize.searchParams.get("state"), jar);
  assert.equal(response.status, 302, await response.clone().text());
  assert.equal(response.headers.get("Location"), "/");
  const { body, authorization } = codes.get("x-none").tokenRequest;
  const verifier = body.get("code_verifier");
  assert.ok(verifier, "PKCE verifier sent");
  assert.equal(createHash("sha256").update(verifier).digest("base64url"), challenge);
  assert.equal(body.get("redirect_uri"), ORIGIN + "/api/auth/callback/twitter");
  assert.equal(authorization, "Basic " + Buffer.from(CREDS.twitter.clientId + ":" + CREDS.twitter.clientSecret).toString("base64"));
  const noEmail = await userFor("twitter", "777");
  assert.equal(noEmail.email, "777@twitter.placeholder.invalid");
  assert.equal(noEmail.verified, 0);

  await signIn("twitter", "x-confirmed", { id: "778", email: "admin@example.test" });
  assert.equal((await userFor("twitter", "778")).id, (await userFor("discord", "100000000000000001")).id,
    "a provider-confirmed email links to the verified Nathan user");
});

test("Apple form_post: the cross-site POST carries no Lax cookies, the GET redirect completes the state check", async () => {
  const { authorize, jar } = await begin("apple");
  assert.equal(authorize.origin + authorize.pathname, "https://appleid.apple.com/auth/authorize");
  assert.equal(authorize.searchParams.get("response_mode"), "form_post");
  assert.equal(authorize.searchParams.get("redirect_uri"), ORIGIN + "/api/auth/callback/apple");
  const state = authorize.searchParams.get("state");
  // Better Auth keeps OAuth state in D1 and binds it to this browser with a signed SameSite=Lax cookie.
  const stateCookie = Object.entries(jar).find(([name]) => /state$/.test(name));
  assert.ok(stateCookie, "a state cookie is set");
  assert.equal(stateCookie[1].sameSite, "lax");
  assert.match(stateCookie[1].raw, /HttpOnly/i);
  assert.match(stateCookie[1].raw, /Secure/i);

  codes.set("ap-1", { idToken: () => appleIdToken({ sub: "001234.apple", email: "apple-user@privaterelay.appleid.com" }) });
  // Apple's page auto-submits a cross-site form POST. A browser sends no Lax cookies with it,
  // so the POST leg must work without the state cookie. The form also carries Apple's id_token;
  // an attacker-supplied one here must not influence the identity.
  assert.equal(cookieHeader(jar, "cross-site-post"), "", "no cookie would accompany Apple's POST");
  const forgedFormToken = await appleIdToken({ sub: "attacker.apple", email: "admin@example.test", email_verified: true },
    (await generateKeyPair("RS256")).privateKey);
  const posted = await mf.dispatchFetch(ORIGIN + "/api/auth/callback/apple", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://appleid.apple.com",
      Cookie: cookieHeader(jar, "cross-site-post") },
    body: new URLSearchParams({ code: "ap-1", state, id_token: forgedFormToken }).toString()
  });
  assert.equal(posted.status, 302, await posted.clone().text());
  assert.ok(!posted.headers.getSetCookie().some(c => /session_token=[^;]/.test(c)), "the POST leg creates no session");
  const next = new URL(posted.headers.get("Location"));
  assert.equal(next.origin + next.pathname, ORIGIN + "/api/auth/callback/apple");
  assert.equal(next.searchParams.get("state"), state);
  assert.ok(!next.searchParams.has("id_token"), "the form-posted id_token is dropped");
  assert.ok(!seen.some(s => s.body?.get("code") === "ap-1"), "no token exchange on the cookieless POST leg");

  // The redirect is a top-level GET navigation, which does carry Lax cookies. Without the
  // state cookie (another browser) the state check fails and no code is exchanged.
  const otherBrowser = await mf.dispatchFetch(next.href, { redirect: "manual" });
  assert.match(otherBrowser.headers.get("Location") || "", /error=/);
  assert.ok(!seen.some(s => s.body?.get("code") === "ap-1"), "no token exchange without the state cookie");
  const done = await mf.dispatchFetch(next.href, { redirect: "manual", headers: { Cookie: cookieHeader(jar, "cross-site-get") } });
  merge(jar, done);
  assert.equal(done.status, 302);
  assert.equal(done.headers.get("Location"), "/", await done.clone().text());
  assert.ok(jar["__Secure-nathan.session_token"], "session issued on the GET leg");

  const secret = codes.get("ap-1").tokenRequest.body.get("client_secret");
  const { payload, protectedHeader } = await jwtVerify(secret, appleKeys.publicKey, {
    issuer: "ABCDE12345", subject: "com.example.login", audience: "https://appleid.apple.com", algorithms: ["ES256"] });
  assert.equal(protectedHeader.kid, "KEY1234567");
  assert.ok(payload.exp - payload.iat <= 3600);
  assert.equal((await userFor("apple", "001234.apple")).email, "apple-user@privaterelay.appleid.com", "identity from the token-endpoint ID token");
  assert.equal(await userFor("apple", "attacker.apple"), null, "identity never from the form-posted id_token");
  const stored = await db.prepare("SELECT secret_fields FROM nathan_oauth_providers WHERE id='apple'").first();
  assert.ok(!stored.secret_fields.includes(secret) && !stored.secret_fields.includes("PRIVATE"), "minted secret and key never stored in clear");

  // What is and is not verified (Better Auth 1.7.14): in the code flow the ID token comes from
  // Apple's token endpoint over TLS, in exchange for the code plus Nathan's signed client
  // secret, and Better Auth decodes it WITHOUT checking its signature against Apple's JWKS
  // (OIDC Core 3.1.3.7 step 6 allows TLS server validation instead). The JWKS is fetched only
  // for ID tokens a client submits directly to /sign-in/social, which are signature-checked.
  assert.ok(!seen.some(s => s.url === "https://appleid.apple.com/auth/keys"), "code flow does not fetch Apple's JWKS");
  const direct = token => mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/social", { method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": "198.51.100." + (++clients) },
    body: JSON.stringify({ provider: "apple", idToken: { token } }) });
  const unsigned = await direct(await appleIdToken({ sub: "001999.forged", email: "forged@example.test" }, (await generateKeyPair("RS256")).privateKey));
  assert.ok(unsigned.status >= 400, "a submitted ID token with a foreign signature is refused: " + unsigned.status);
  assert.ok(!unsigned.headers.getSetCookie().some(c => /session_token=[^;]/.test(c)));
  // Direct ID-token sign-in is disabled for every provider: Nathan's sign-in page only uses the
  // redirect flow, and a leaked provider ID token for Nathan's client id must not be replayable
  // (no state, PKCE or nonce binds it). Even a correctly signed token is refused.
  const signed = await direct(await appleIdToken({ sub: "001998.native", email: "native@privaterelay.appleid.com" }));
  assert.ok(signed.status >= 400, "direct ID-token sign-in is disabled: " + signed.status);
  assert.ok(!signed.headers.getSetCookie().some(c => /session_token=[^;]/.test(c)));
  assert.equal(await userFor("apple", "001999.forged"), null);
  assert.equal(await userFor("apple", "001998.native"), null, "no account from a directly submitted ID token");
});

let studioCallbacks;
test("Studio provider API is admin-only: anonymous and signed-in non-admin sessions get 403 on every route", async () => {
  assert.equal((await mf.dispatchFetch(ORIGIN + "/studio/api/providers")).status, 403);
  const memberUser = await userFor("discord", "100000000000000003");
  assert.ok(memberJar["__Secure-nathan.session_token"], "the member has a real session");
  const session = await (await visit("/api/auth/get-session", memberJar)).json();
  assert.equal(session.user.id, memberUser.id, "the member session is live");
  const before = await auditRows();
  assert.equal((await visit("/studio/api/providers", memberJar)).status, 403, "GET /studio/api/providers");
  for (const [path, body] of [
    ["/studio/api/providers", { id: "twitch", fields: { clientId: "abcdefghijklmnopqrstuvwxyz0123", clientSecret: "0123456789abcdefghijklmnopqrst" } }],
    ["/studio/api/providers/status", { id: "discord", enabled: false, confirm: "CONFIRM DISABLE discord" }],
    ["/studio/api/providers/test", { id: "twitter" }]
  ]) assert.equal((await post(path, body, memberJar)).status, 403, "POST " + path);
  assert.deepEqual(await auditRows(), before, "nothing ran for the non-admin");
  assert.equal(await db.prepare("SELECT id FROM nathan_oauth_providers WHERE id='twitch'").first(), null);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM nathan_provider_test_tickets").first("n"), 0);

  await db.prepare("UPDATE \"user\" SET \"role\"='admin' WHERE \"email\"='admin@example.test'").run();
  const listed = await visit("/studio/api/providers", adminJar);
  assert.equal(listed.status, 200, await listed.clone().text());
  const text = await listed.clone().text();
  // The field schema documents the PEM header; the key material itself must never appear.
  for (const secret of [CREDS.discord.clientSecret, CREDS.twitter.clientSecret, ...applePem.split("\n").slice(1, -1)])
    assert.ok(!text.includes(secret), "provider API leaks a secret");
  const { providers } = JSON.parse(text);
  assert.deepEqual(providers.map(p => p.id), PROVIDER_IDS);
  studioCallbacks = Object.fromEntries(providers.map(p => [p.id, p.callbackUrl]));
  assert.deepEqual(providers.find(p => p.id === "apple").values, { clientId: "com.example.login", teamId: "ABCDE12345", keyId: "KEY1234567" });
  assert.equal(providers.find(p => p.id === "discord").source, "encrypted-d1");

  const rejected = await post("/studio/api/providers", { id: "twitch", fields: { clientId: "abc", clientSecret: "SECRET-SHOULD-NOT-ECHO-123456" } }, adminJar);
  assert.equal(rejected.status, 409);
  const reason = (await rejected.json()).error;
  assert.match(reason, /Twitch Client ID has the wrong format/);
  assert.ok(!reason.includes("SECRET-SHOULD-NOT-ECHO"));
  const lastMethod = await post("/studio/api/providers/status", { id: "discord", enabled: false, confirm: "CONFIRM DISABLE discord" }, adminJar);
  assert.equal(lastMethod.status, 409, "no other tested provider yet");
  assert.match((await lastMethod.json()).error, /administrator/);
  const audit = await auditRows();
  assert.ok(!JSON.stringify(audit).includes("SECRET-SHOULD-NOT-ECHO"));
  for (const outcome of ["attempted", "failed_validation"])
    assert.ok(audit.some(a => a.action === "oauth_provider_update" && a.target === "twitch" && a.outcome === outcome), outcome);
  assert.ok(audit.some(a => a.action === "oauth_provider_disable" && a.target === "discord" && a.outcome === "denied_last_method"));
});

test("a test sign-in is recorded only from that provider's real callback, and only an admin's test protects access", async () => {
  const adminId = (await userFor("discord", "100000000000000001")).id;
  const start = async id => {
    const r = await post("/studio/api/providers/test", { id }, adminJar);
    assert.equal(r.status, 200, await r.clone().text());
    return (await r.json()).callbackURL;
  };

  // 1. A real session created by a different provider (Discord) for an X test is not evidence.
  const viaDiscord = await start("twitter");
  const discordBrowser = await signIn("discord", "dc-wrong-provider", { id: "100000000000000001", email: "admin@example.test", verified: true },
    jarOf(), viaDiscord);
  const wrong = await visit(viaDiscord, discordBrowser);
  assert.equal(wrong.status, 400);
  assert.match(await wrong.text(), /not recorded/);
  // 2. An existing session that no callback created after the ticket is not evidence either.
  const stale = await start("twitter");
  assert.equal((await visit(stale, adminJar)).status, 400);
  assert.equal((await providerState("twitter"))?.tested_at ?? null, null);

  // 3. Test-account path, end to end: a fresh browser signs in to X as an account that is not an
  // administrator. The test is recorded, but it does not protect administrator access.
  const forTester = await start("twitter");
  const testerBrowser = await signIn("twitter", "x-tester", { id: "779" }, jarOf(), forTester);
  const testerResult = await visit(forTester, testerBrowser);
  assert.equal(testerResult.status, 200, await testerResult.clone().text());
  const testerPage = await testerResult.text();
  assert.match(testerPage, /Test sign-in succeeded/);
  assert.match(testerPage, /not a Nathan administrator/);
  const tester = await userFor("twitter", "779");
  let row = await providerState("twitter");
  assert.equal(row.tested_user, tester.id);
  assert.equal(row.tested_by, adminId);
  const status = (await (await visit("/studio/api/providers", adminJar)).json()).providers.find(p => p.id === "twitter");
  assert.ok(status.testedAt > 0);
  assert.equal(status.testedByAdmin, false);
  assert.equal((await post("/studio/api/providers/status", { id: "discord", enabled: false, confirm: "CONFIRM DISABLE discord" }, adminJar)).status, 409,
    "a non-admin test does not let the admin's other method be disabled");

  // 4. The administrator's own X sign-in (account 778 is linked to the admin) does.
  const forAdmin = await start("twitter");
  const adminBrowser = await signIn("twitter", "x-admin-test", { id: "778", email: "admin@example.test" }, jarOf(adminJar), forAdmin);
  const result = await visit(forAdmin, adminBrowser);
  assert.equal(result.status, 200, await result.clone().text());
  assert.match(await result.text(), /You signed in as a Nathan administrator/);
  assert.equal((await visit(forAdmin, adminBrowser)).status, 400, "ticket is single use");
  row = await providerState("twitter");
  assert.equal(row.tested_user, adminId);
  assert.ok(row.tested_version, "the test is bound to a credential version");

  const disabled = await post("/studio/api/providers/status", { id: "discord", enabled: false, confirm: "CONFIRM DISABLE discord" }, adminBrowser);
  assert.equal(disabled.status, 200, await disabled.clone().text());
  assert.ok(!(await (await mf.dispatchFetch(ORIGIN + "/sign-in")).text()).includes("Continue with Discord"), "disable takes effect immediately");
  const reenabled = await post("/studio/api/providers/status", { id: "discord", enabled: true, confirm: "CONFIRM ENABLE discord" }, adminBrowser);
  assert.equal(reenabled.status, 200);
  const audit = await auditRows();
  assert.ok(audit.some(a => a.action === "oauth_provider_test" && a.target === "twitter" && a.outcome === "failed"));
  for (const [action, target] of [["oauth_provider_test", "twitter"], ["oauth_provider_disable", "discord"], ["oauth_provider_enable", "discord"]])
    assert.ok(audit.some(a => a.action === action && a.target === target && a.outcome === "succeeded"), action);
  adminJar = adminBrowser;
});

test("rotating credentials between test start and finish voids the test; the new secret is used at once", async () => {
  const rotate = async secret => {
    const r = await post("/studio/api/providers", { id: "discord", fields: { clientId: CREDS.discord.clientId, clientSecret: secret } }, adminJar);
    assert.equal(r.status, 200, await r.clone().text());
  };
  const start = async () => (await (await post("/studio/api/providers/test", { id: "discord" }, adminJar)).json()).callbackURL;
  const adminGrant = { id: "100000000000000001", email: "admin@example.test", verified: true };

  // Rotated after the provider callback, before the test completes.
  const first = await start();
  const browser = await signIn("discord", "dc-rotate-1", adminGrant, jarOf(), first);
  await rotate("RotatedSecretOne0123456789abcdef");
  assert.equal((await visit(first, browser)).status, 400);
  // Rotated after the test started, before the provider callback.
  const second = await start();
  await rotate("RotatedSecretTwo0123456789abcdef");
  const browser2 = await signIn("discord", "dc-rotate-2", adminGrant, jarOf(), second);
  assert.equal(codes.get("dc-rotate-2").tokenRequest.body.get("client_secret"), "RotatedSecretTwo0123456789abcdef",
    "the rotated secret is used for the very next token exchange");
  assert.equal((await visit(second, browser2)).status, 400);
  assert.equal((await providerState("discord")).tested_at, null, "nothing recorded against superseded credentials");

  // Unchanged credentials from start to finish: recorded.
  const third = await start();
  const browser3 = await signIn("discord", "dc-rotate-3", adminGrant, jarOf(), third);
  assert.equal((await visit(third, browser3)).status, 200);
  assert.ok((await providerState("discord")).tested_at > 0);
});

test("callback URLs are identical in the hosted installer page, Studio API and CLI", async () => {
  assert.ok(studioCallbacks, "Studio test ran first");
  const installer = await start({
    scriptPath: bundle("installer"),
    d1Databases: { INSTALLER_DB: "installer-db-" + crypto.randomUUID() },
    serviceBindings: { ASSETS: () => new Response("asset") },
    bindings: { PUBLIC_ORIGIN: "https://install.example.test", CF_OAUTH_CLIENT_ID: "cf", CF_OAUTH_CLIENT_SECRET: "cf-secret",
      CF_OAUTH_SCOPES: "user-details.read", INSTALLER_ENCRYPTION_KEY: randomKey() }
  });
  instances.push(installer);
  const idb = await installer.getD1Database("INSTALLER_DB");
  for (const file of readdirSync("migrations/installer").filter(f => f.endsWith(".sql")).sort())
    await migrate(idb, "migrations/installer/" + file);
  const html = await (await installer.dispatchFetch("https://install.example.test/")).text();
  const start_ = html.indexOf("const providerRegistry="), end = html.indexOf("const $=");
  assert.ok(start_ > 0 && end > start_, "installer embeds the registry");
  const { providerRegistry, providerCallbackUrl } = new Function(html.slice(start_, end) + "return {providerRegistry,providerCallbackUrl};")();
  assert.deepEqual(providerRegistry.map(p => p.id), PROVIDER_IDS);
  const fromInstaller = Object.fromEntries(providerRegistry.map(p => [p.id, providerCallbackUrl(HOST, p.id)]));
  const fromCli = Object.fromEntries(PROVIDER_IDS.map(id => [id, cliGuide(id, HOST).callback]));
  assert.deepEqual(fromInstaller, studioCallbacks);
  assert.deepEqual(fromCli, studioCallbacks);
  assert.equal(studioCallbacks.twitter, ORIGIN + "/api/auth/callback/twitter");
});

// Staging 2026-11-22: a successful sign-in landed on "/", which always redirected to /sign-in, which
// never looked at the session, so the browser looped back to the sign-in page.
test("a signed-in browser landing on / or /sign-in goes to its account page, not back to sign-in", async () => {
  const jar = await signIn("discord", "dc-landing", { id: "100000000000000009", email: "landing@example.test", verified: true });
  const root = await visit("/", jar);
  assert.equal(root.status, 302);
  assert.equal(root.headers.get("Location"), ORIGIN + "/security");
  const signInAgain = await visit("/sign-in", jar);
  assert.equal(signInAgain.status, 302);
  assert.equal(signInAgain.headers.get("Location"), ORIGIN + "/security");
  assert.equal((await visit("/security", jar)).status, 200);
  // Signed out, both still lead to the sign-in page.
  const anonymous = await visit("/", jarOf());
  assert.equal(anonymous.headers.get("Location"), ORIGIN + "/sign-in");
  assert.equal((await visit("/sign-in", jarOf())).status, 200);
});

// "Sign in with gmacko": an app sends the browser to /oauth2/authorize; Nathan sends it to /sign-in with a
// signed query; after the social round trip Better Auth must resume that authorization, not land on "/".
// NATH-44: the signed query reaches the OAuth state (serverContext), but the callback still lands on "/";
// Better Auth's post-login authorize hook does not resume yet. Tracked until fixed; blocks the app pilot.
test("an app's authorization resumes after a social sign-in that carries the signed oauth_query", { todo: "NATH-44" }, async () => {
  const CLIENT = "app-" + randomKey().slice(0, 8), REDIRECT = "https://app.example.test/api/auth/callback/nathan";
  await db.prepare('INSERT INTO "oauthClient"("id","clientId","redirectUris","disabled","skipConsent","tokenEndpointAuthMethod","requirePKCE","subjectType","createdAt","updatedAt") VALUES (?,?,?,0,1,\'none\',1,\'public\',?,?)')
    .bind("oc-" + CLIENT, CLIENT, JSON.stringify([REDIRECT]), Date.now(), Date.now()).run();
  const state = randomKey();
  const query = new URLSearchParams({ response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT, scope: "openid profile email",
    state, code_challenge: createHash("sha256").update(randomKey()).digest("base64url"), code_challenge_method: "S256" });
  const jar = jarOf();
  const authorize = await mf.dispatchFetch(ORIGIN + "/api/auth/oauth2/authorize?" + query, { redirect: "manual",
    headers: { Accept: "text/html", "Sec-Fetch-Mode": "navigate", Cookie: cookieHeader(jar) } });
  merge(jar, authorize);
  const login = new URL(authorize.headers.get("Location") ?? (await authorize.json()).url, ORIGIN);
  assert.equal(login.pathname, "/sign-in");
  assert.ok(login.searchParams.has("sig"), "Nathan signs the query it hands the sign-in page");

  // The sign-in page sends what signedOAuthQuery derives from its own URL.
  const { signedOAuthQuery } = await import("../../src/auth/oauth-query.mjs");
  const oauthQuery = signedOAuthQuery(login.search);
  assert.ok(oauthQuery, "the page URL carries a signed query");
  const started = await begin("discord", jar, "/", { oauth_query: oauthQuery });
  codes.set("dc-app", { id: "100000000000000010", email: "app-user@example.test", verified: true });
  // A real browser follows the provider's redirect as a top-level navigation.
  const back = await callback("discord", "dc-app", started.authorize.searchParams.get("state"), jar,
    { Accept: "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "cross-site" });
  assert.equal(back.status, 302, await back.clone().text());
  const resumed = new URL(back.headers.get("Location"), ORIGIN);
  assert.equal(resumed.origin + resumed.pathname, REDIRECT, "the browser returns to the app, not to Nathan's /: " + resumed.href);
  assert.ok(resumed.searchParams.get("code"), "with an authorization code");
  assert.equal(resumed.searchParams.get("state"), state);
});
