/**
 * NATH-51 "Sign in with Nathan": discovery validation, ID token verification, the trust and
 * email-verified rules, the genericOAuth registration, encrypted storage and the Studio lifecycle of
 * the `nathan` provider. The end-to-end federation between two Nathan Workers is in
 * tests/runtime/nathan-upstream.test.mjs.
 */
import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet } from "jose";
import {
  validateDiscovery, discoverUpstream, resolveUpstream, upstreamProfile, idTokenVerifier, nathanUpstreamPlugin,
  accountSubject, discoveryUrl, clearUpstreamCaches, DiscoveryError
} from "../src/auth/nathan-upstream.mjs";
import { buildSocialProviders, signInLabel, validateProviderCredentials, PROVIDERS } from "../src/shared/providers.mjs";
import { generateConfigKey, decryptProviderField } from "../src/auth/config-crypto.mjs";
import {
  providerStatus, loadSocialProviderState, upsertSocialProvider, setSocialProviderEnabled, beginProviderTest,
  completeProviderTest, recordProviderSignIn
} from "../src/auth/provider-config.mjs";

const ISSUER = "https://id.example.com/api/auth";
const CLIENT = "parentClient123";
const SECRET = "pArEnTsEcReT0123456789abcdefXYZ";
const CHILD = "https://child.example.com";
const VALUES = { issuer: ISSUER, clientId: CLIENT, clientSecret: SECRET, displayName: "Example ID", trustEmailVerified: "true" };
/** The discovery document a Nathan parent (Better Auth oauth-provider) publishes, abridged. */
const DOC = {
  issuer: ISSUER,
  authorization_endpoint: ISSUER + "/oauth2/authorize",
  token_endpoint: ISSUER + "/oauth2/token",
  userinfo_endpoint: ISSUER + "/oauth2/userinfo",
  jwks_uri: ISSUER + "/jwks",
  response_types_supported: ["code"],
  id_token_signing_alg_values_supported: ["EdDSA"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]
};

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; clearUpstreamCaches(); });
/** Serves DOC (or `doc`) at the discovery URL; counts requests. */
function parentFetch(doc = DOC, { status = 200 } = {}) {
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url) !== discoveryUrl(ISSUER)) return new Response("not found", { status: 404 });
    return status === 200 ? Response.json(doc) : new Response("down", { status, headers: status === 302 ? { Location: "https://evil.example/" } : {} });
  };
  return { fetcher, calls };
}

test("discovery is validated against the exact configured issuer and its own origin", () => {
  const ok = validateDiscovery(ISSUER, DOC);
  assert.deepEqual(ok, { issuer: ISSUER, authorizationEndpoint: DOC.authorization_endpoint, tokenEndpoint: DOC.token_endpoint,
    userinfoEndpoint: DOC.userinfo_endpoint, jwksUri: DOC.jwks_uri, algorithms: ["EdDSA"] });
  const code = (doc) => { try { validateDiscovery(ISSUER, doc); return "accepted"; } catch (e) { assert.ok(e instanceof DiscoveryError); return e.code; } };
  assert.equal(code({ ...DOC, issuer: ISSUER + "/" }), "issuer_mismatch");
  assert.equal(code({ ...DOC, issuer: "https://evil.example.com/api/auth" }), "issuer_mismatch");
  assert.equal(code({ ...DOC, token_endpoint: "https://evil.example.com/oauth2/token" }), "endpoint_not_on_issuer_origin",
    "a discovery document cannot send the client secret elsewhere");
  assert.equal(code({ ...DOC, authorization_endpoint: "http://id.example.com/api/auth/oauth2/authorize" }), "endpoint_not_on_issuer_origin");
  assert.equal(code({ ...DOC, jwks_uri: "https://id.example.com.evil.example/jwks" }), "endpoint_not_on_issuer_origin");
  assert.equal(code({ ...DOC, jwks_uri: undefined }), "endpoint_not_on_issuer_origin");
  assert.equal(code({ ...DOC, userinfo_endpoint: "https://evil.example.com/userinfo" }), "endpoint_not_on_issuer_origin",
    "the access token is never sent elsewhere");
  assert.equal(code({ ...DOC, id_token_signing_alg_values_supported: ["HS256", "none"] }), "no_supported_id_token_algorithm",
    "symmetric and unsigned ID tokens are never accepted");
  assert.deepEqual(validateDiscovery(ISSUER, { ...DOC, id_token_signing_alg_values_supported: ["none", "RS256", "EdDSA"] }).algorithms, ["EdDSA", "RS256"]);
  assert.equal(code({ ...DOC, code_challenge_methods_supported: ["plain"] }), "pkce_s256_unsupported");
  assert.equal(code({ ...DOC, token_endpoint_auth_methods_supported: ["private_key_jwt"] }), "client_secret_basic_unsupported");
  assert.equal(code({ ...DOC, response_types_supported: ["token"] }), "code_flow_unsupported");
  assert.equal(code(null), "discovery_invalid");
  assert.equal(code([]), "discovery_invalid");
});

test("discovery is fetched only from the issuer, without redirects, and cached per isolate", async () => {
  const { fetcher, calls } = parentFetch();
  const first = await discoverUpstream(ISSUER, { fetch: fetcher });
  assert.equal(first.tokenEndpoint, DOC.token_endpoint);
  assert.equal(calls[0].url, "https://id.example.com/api/auth/.well-known/openid-configuration");
  assert.equal(calls[0].init.redirect, "manual");
  await discoverUpstream(ISSUER, { fetch: fetcher });
  assert.equal(calls.length, 1, "cached");
  await discoverUpstream(ISSUER, { fetch: fetcher, fresh: true });
  assert.equal(calls.length, 2, "a Studio save re-reads it");
  await discoverUpstream(ISSUER, { fetch: fetcher, now: Date.now() + 11 * 60 * 1000 });
  assert.equal(calls.length, 3, "expires after ten minutes");

  clearUpstreamCaches();
  const redirect = parentFetch(DOC, { status: 302 });
  await assert.rejects(discoverUpstream(ISSUER, { fetch: redirect.fetcher }), e => e.code === "discovery_status_302");
  await assert.rejects(discoverUpstream(ISSUER, { fetch: redirect.fetcher }), e => e.code === "discovery_status_302");
  assert.equal(redirect.calls.length, 1, "a failure is cached briefly too");
  clearUpstreamCaches();
  await assert.rejects(discoverUpstream(ISSUER, { fetch: async () => new Response("<html>") }), e => e.code === "discovery_invalid");
  clearUpstreamCaches();
  await assert.rejects(discoverUpstream(ISSUER, { fetch: async () => { throw new TypeError("network"); } }), e => e.code === "discovery_unreachable");
  clearUpstreamCaches();
  await assert.rejects(discoverUpstream(ISSUER, { fetch: async () => new Response("x".repeat(70_000)) }), e => e.code === "discovery_too_large");
  const message = new DiscoveryError("issuer_mismatch", ISSUER).publicMessage;
  assert.match(message, /issuer_mismatch/);
  assert.ok(!message.includes(SECRET));
});

test("an upstream is resolved only when trusted for email verification and not this instance itself", async () => {
  const { fetcher } = parentFetch();
  const resolved = await resolveUpstream(VALUES, { fetch: fetcher, selfIssuer: CHILD });
  assert.equal(resolved.discovery.authorizationEndpoint, DOC.authorization_endpoint);
  assert.equal(resolved.trustEmailVerified, "true");
  await assert.rejects(resolveUpstream({ ...VALUES, trustEmailVerified: "" }, { fetch: fetcher }), /trusted for email verification/);
  await assert.rejects(resolveUpstream({ ...VALUES, trustEmailVerified: "false" }, { fetch: fetcher }), /trusted for email verification/);
  await assert.rejects(resolveUpstream(VALUES, { fetch: fetcher, selfIssuer: "https://id.example.com" }), /this instance itself/);
});

const claims = (extra = {}) => ({ iss: ISSUER, aud: CLIENT, sub: "user-1", email: "Alice@Example.com", email_verified: true,
  name: "Alice", picture: "https://id.example.com/a.png", iat: 1, exp: 2, ...extra });
test("only a trusted parent's email_verified === true address is used; MFA claims are dropped", () => {
  const ok = upstreamProfile(claims({ amr: ["mfa", "hwk"], acr: "urn:aal2", nathan_amr: ["pop"], nathan_acr: "urn:nathan:acr:passkey",
    nathan_auth_time: 5, role: "admin" }), { issuer: ISSUER, clientId: CLIENT, trusted: true });
  assert.deepEqual(ok, { ok: true, profile: { id: ISSUER + "#user-1", sub: "user-1", email: "alice@example.com", emailVerified: true,
    name: "Alice", image: "https://id.example.com/a.png" } }, "no amr, acr, evidence or role claim survives");
  assert.equal(accountSubject(ISSUER, "user-1"), "https://id.example.com/api/auth#user-1", "issuer-qualified account id");
  const reason = (c, trusted = true) => upstreamProfile(c, { issuer: ISSUER, clientId: CLIENT, trusted }).reason;
  assert.equal(reason(claims(), false), "untrusted_upstream");
  assert.equal(reason(claims({ email_verified: false })), "email_unverified");
  assert.equal(reason(claims({ email_verified: "true" })), "email_unverified", "only the boolean true counts");
  assert.equal(reason(claims({ email_verified: undefined })), "email_unverified");
  assert.equal(reason(claims({ email: "not-an-address" })), "email_unverified");
  assert.equal(reason(claims({ email: undefined })), "email_unverified");
  assert.equal(reason(claims({ iss: "https://evil.example.com/api/auth" })), "invalid_claims");
  assert.equal(reason(claims({ aud: "other-client" })), "invalid_claims");
  assert.equal(reason(claims({ aud: [CLIENT, "other"] })), "invalid_claims", "several audiences need azp");
  assert.equal(upstreamProfile(claims({ aud: [CLIENT, "other"], azp: CLIENT }), { issuer: ISSUER, clientId: CLIENT, trusted: true }).ok, true);
  assert.equal(reason(claims({ sub: "" })), "invalid_claims");
  assert.equal(reason(claims({ sub: "a\nb" })), "invalid_claims");
  assert.equal(upstreamProfile(claims({ picture: "http://id.example.com/a.png" }), { issuer: ISSUER, clientId: CLIENT, trusted: true }).profile.image,
    undefined, "only https pictures");
});

// ---- ID token verification (signature, iss, aud, exp, nonce) --------------------------------------
const parentKeys = await generateKeyPair("EdDSA", { crv: "Ed25519" });
const otherKeys = await generateKeyPair("EdDSA", { crv: "Ed25519" });
const jwks = createLocalJWKSet({ keys: [{ ...await exportJWK(parentKeys.publicKey), kid: "k1", alg: "EdDSA" }] });
function idToken({ key = parentKeys.privateKey, kid = "k1", iss = ISSUER, aud = CLIENT, nonce = "n-1", exp = "5m", extra = {} } = {}) {
  return new SignJWT({ email: "alice@example.com", email_verified: true, ...(nonce ? { nonce } : {}), ...extra })
    .setProtectedHeader({ alg: "EdDSA", kid }).setIssuer(iss).setSubject("user-1").setAudience(aud).setIssuedAt()
    .setExpirationTime(exp).sign(key);
}
test("ID tokens are verified: signature, algorithm, issuer, audience, expiry and the authorization's nonce", async () => {
  const refused = [];
  const verify = idTokenVerifier({ issuer: ISSUER, clientId: CLIENT, algorithms: ["EdDSA"], jwks, onRefused: r => { refused.push(r); } });
  assert.equal(await verify(await idToken(), "n-1"), true);
  const cases = [
    ["wrong issuer", await idToken({ iss: "https://evil.example.com/api/auth" }), "n-1", "id_token_invalid"],
    ["wrong audience", await idToken({ aud: "someone-else" }), "n-1", "id_token_invalid"],
    ["expired", await idToken({ exp: Math.floor(Date.now() / 1000) - 120 }), "n-1", "id_token_invalid"],
    ["other key", await idToken({ key: otherKeys.privateKey }), "n-1", "id_token_invalid"],
    ["wrong nonce", await idToken({ nonce: "n-2" }), "n-1", "id_token_nonce"],
    ["no nonce in token", await idToken({ nonce: null }), "n-1", "id_token_nonce"],
    ["no expected nonce", await idToken(), undefined, "id_token_nonce"],
    ["several audiences without azp", await idToken({ aud: [CLIENT, "other"] }), "n-1", "id_token_invalid"],
    ["not a JWT", "opaque-token", "n-1", "id_token_invalid"]
  ];
  for (const [name, token, nonce, reason] of cases) {
    refused.length = 0;
    assert.equal(await verify(token, nonce), false, name);
    assert.deepEqual(refused, [reason], name);
  }
  // HS256 (algorithm confusion) is refused: only the discovered asymmetric algorithms are accepted.
  const hs = await new SignJWT({ nonce: "n-1" }).setProtectedHeader({ alg: "HS256", kid: "k1" }).setIssuer(ISSUER).setSubject("u")
    .setAudience(CLIENT).setIssuedAt().setExpirationTime("5m").sign(new TextEncoder().encode("x".repeat(32)));
  assert.equal(await verify(hs, "n-1"), false);
  // A client-submitted ID token (Better Auth passes the request context) is never accepted.
  refused.length = 0;
  assert.equal(await verify(await idToken(), "n-1", { path: "/sign-in/social" }), false);
  assert.deepEqual(refused, ["client_id_token"]);
});

test("the genericOAuth registration uses discovered endpoints, PKCE S256, a nonce, the iss check and client_secret_basic", async () => {
  const refused = [], verified = [];
  const plugin = nathanUpstreamPlugin({ ...VALUES, discovery: validateDiscovery(ISSUER, DOC) },
    { jwks, onRefused: r => { refused.push(r); }, onVerified: e => { verified.push(e); } });
  assert.equal(plugin.id, "generic-oauth");
  const logger = { error() {}, warn() {}, info() {}, debug() {} };
  const { context } = await plugin.init({ socialProviders: [], logger, baseURL: CHILD + "/api/auth" });
  const provider = context.socialProviders.find(p => p.id === "nathan");
  assert.equal(provider.name, "Sign in with Example ID");
  assert.equal(provider.issuer, ISSUER, "RFC 9207 iss check");
  assert.equal(provider.requiresIdTokenNonce, true);
  assert.equal(typeof provider.idToken.verify, "function");
  const url = await provider.createAuthorizationURL({ state: "st-1", codeVerifier: "v".repeat(64), idTokenNonce: "n-1",
    redirectURI: CHILD + "/api/auth/callback/nathan" });
  assert.equal(url.origin + url.pathname, DOC.authorization_endpoint);
  assert.equal(url.searchParams.get("client_id"), CLIENT);
  assert.equal(url.searchParams.get("redirect_uri"), CHILD + "/api/auth/callback/nathan");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.ok(url.searchParams.get("code_challenge"));
  assert.equal(url.searchParams.get("nonce"), "n-1");
  assert.equal(url.searchParams.get("state"), "st-1");
  assert.deepEqual(url.searchParams.get("scope").split(" ").sort(), ["email", "openid", "profile"]);

  // The token request authenticates with HTTP Basic at the discovered token endpoint, with the PKCE verifier.
  const seen = [];
  // A Nathan parent's ID token carries no email claims; UserInfo does (OIDC Core 5.4).
  let userinfo = { sub: "user-1", email: "Alice@example.com", email_verified: true, name: "Alice" };
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    seen.push({ url: request.url, auth: request.headers.get("authorization"), body: new URLSearchParams(await request.text()) });
    if (request.url === DOC.userinfo_endpoint) return request.headers.get("authorization") === "Bearer at" ? Response.json(userinfo) : new Response("", { status: 401 });
    return Response.json({ access_token: "at", token_type: "Bearer", expires_in: 60, id_token: await idToken({ extra: { email: undefined, email_verified: undefined } }) });
  };
  const tokens = await provider.validateAuthorizationCode({ code: "c-1", codeVerifier: "v".repeat(64), redirectURI: CHILD + "/api/auth/callback/nathan" });
  assert.equal(seen[0].url, DOC.token_endpoint);
  assert.equal(seen[0].auth, "Basic " + btoa(CLIENT + ":" + SECRET));
  assert.equal(seen[0].body.get("code_verifier"), "v".repeat(64));
  assert.ok(!seen[0].body.has("client_secret"), "secret only in the Authorization header");

  // getUserInfo: verified ID token → profile; the account key is issuer-qualified.
  const info = await provider.getUserInfo({ ...tokens, expectedIdTokenNonce: "n-1" });
  assert.equal(info.user.email, "alice@example.com");
  assert.equal(info.user.emailVerified, true);
  assert.equal(await provider.accountSubject({ tokens, profile: info.data }), ISSUER + "#user-1");
  assert.deepEqual(verified, ["alice@example.com"]);
  assert.equal(seen.at(-1).url, DOC.userinfo_endpoint);
  // A nonce from another authorization, an unverified address, UserInfo about someone else, or no ID token: refused.
  assert.equal(await provider.getUserInfo({ ...tokens, expectedIdTokenNonce: "n-other" }), null);
  userinfo = { ...userinfo, email_verified: false };
  assert.equal(await provider.getUserInfo({ ...tokens, expectedIdTokenNonce: "n-1" }), null);
  userinfo = { ...userinfo, email_verified: true, sub: "user-2" };
  assert.equal(await provider.getUserInfo({ ...tokens, expectedIdTokenNonce: "n-1" }), null);
  assert.equal(await provider.getUserInfo({ ...tokens, accessToken: "wrong", expectedIdTokenNonce: "n-1" }), null);
  assert.equal(await provider.getUserInfo({ accessToken: "at", expectedIdTokenNonce: "n-1" }), null, "an ID token is required");
  assert.deepEqual(refused, ["id_token_nonce", "email_unverified", "userinfo_subject_mismatch", "userinfo_unavailable", "id_token_missing"]);
  userinfo = { ...userinfo, sub: "user-1" };

  // An untrusted configuration is refused even if it reached the plugin.
  const untrusted = nathanUpstreamPlugin({ ...VALUES, trustEmailVerified: "false", discovery: validateDiscovery(ISSUER, DOC) }, { jwks });
  const p2 = (await untrusted.init({ socialProviders: [], logger })).context.socialProviders[0];
  assert.equal(await p2.getUserInfo({ ...tokens, expectedIdTokenNonce: "n-1" }), null);
});

test("Better Auth config: the upstream is built only when trusted and discovered; button labels", () => {
  const discovery = validateDiscovery(ISSUER, DOC);
  const built = buildSocialProviders({ nathan: { ...VALUES, discovery } });
  assert.deepEqual(Object.keys(built), ["nathan"]);
  assert.equal(built.nathan.upstream, true);
  assert.equal(built.nathan.issuer, ISSUER);
  assert.deepEqual(buildSocialProviders({ nathan: { ...VALUES, trustEmailVerified: "false", discovery } }), {});
  assert.deepEqual(buildSocialProviders({ nathan: { ...VALUES } }), {}, "no discovery, no provider");
  assert.equal(signInLabel("nathan"), "Sign in with Nathan");
  assert.equal(signInLabel("nathan", "gmacko ID"), "Sign in with gmacko ID");
  assert.equal(signInLabel("nathan", "<img src=x>"), "Sign in with Nathan", "an invalid name falls back");
  assert.equal(signInLabel("github"), "Continue with GitHub");
  assert.throws(() => validateProviderCredentials("nathan", { ...VALUES, displayName: "<b>x</b>" }));
  assert.equal(PROVIDERS.nathan.fields.find(f => f.name === "trustEmailVerified").checkbox, true);
});

// ---- Storage and Studio lifecycle ------------------------------------------------------------------
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
    async batch(statements) {
      db.exec("BEGIN");
      try { const out = statements.map(s => s.runSync()); db.exec("COMMIT"); return out; }
      catch (e) { db.exec("ROLLBACK"); throw e; }
    }
  };
}
function storeEnv() {
  const db = new DatabaseSync(":memory:");
  for (const f of ["0002_better_auth.sql", "0003_security_audit.sql", "0006_control_plane.sql", "0012_social_providers.sql",
    "0017_admission_provider_health.sql", "0019_nathan_upstream.sql"])
    db.exec(readFileSync("migrations/" + f, "utf8"));
  const events = [];
  const grants = new Set(["admin"]);
  const deps = { audit: async (_env, actor, action, target, outcome) => { events.push({ actor, action, target, outcome }); },
    isAdmin: async u => u.role === "admin" && u.emailVerified === true && grants.has(u.id) };
  const env = { DB: d1(db), NATHAN_ISSUER: CHILD, NATHAN_CONFIG_KEY: generateConfigKey(), BETTER_AUTH_SECRET: "x".repeat(40),
    ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false" };
  db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (\'admin\',\'a\',\'admin@example.com\',1,0,0,\'admin\')').run();
  return { db, env, deps, events };
}

test("Studio saves the upstream with its secret encrypted, refuses untrusted or unusable parents, and audits every attempt", async () => {
  const { db, env, deps, events } = storeEnv();
  globalThis.fetch = parentFetch().fetcher;
  const fail = async (input, outcome) => {
    events.length = 0;
    await assert.rejects(upsertSocialProvider(env, { id: "nathan", fields: input }, "admin", deps));
    assert.deepEqual(events.map(e => e.outcome), ["attempted", outcome]);
  };
  await fail({ ...VALUES, trustEmailVerified: "" }, "failed_validation");
  await fail({ ...VALUES, trustEmailVerified: "false" }, "failed_validation");
  await fail({ ...VALUES, issuer: "https://child.example.com/api/auth" }, "failed_validation");
  globalThis.fetch = parentFetch({ ...DOC, issuer: "https://elsewhere.example.com/api/auth" }).fetcher;
  await fail(VALUES, "failed_validation");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_oauth_providers").get().n, 0, "nothing stored");

  globalThis.fetch = parentFetch().fetcher;
  events.length = 0;
  const saved = await upsertSocialProvider(env, { id: "nathan", fields: VALUES }, "admin", deps);
  assert.equal(saved.callbackUrl, CHILD + "/api/auth/callback/nathan");
  assert.deepEqual(events.map(e => [e.action, e.target, e.outcome]), [["oauth_provider_update", "nathan", "attempted"], ["oauth_provider_update", "nathan", "succeeded"]]);
  const row = db.prepare("SELECT * FROM nathan_oauth_providers WHERE id='nathan'").get();
  assert.ok(!JSON.stringify(row).includes(SECRET), "the client secret is never stored in clear");
  assert.deepEqual(JSON.parse(row.config), { issuer: ISSUER, displayName: "Example ID", trustEmailVerified: "true" });
  const sealed = JSON.parse(row.secret_fields).clientSecret;
  assert.equal(await decryptProviderField("nathan", "clientSecret", sealed, env.NATHAN_CONFIG_KEY), SECRET);
  await assert.rejects(decryptProviderField("github", "clientSecret", sealed, env.NATHAN_CONFIG_KEY), "bound to the nathan provider");

  const status = (await providerStatus(env, deps)).find(p => p.id === "nathan");
  assert.equal(status.enabled, true);
  assert.equal(status.available, true);
  assert.equal(status.callbackUrl, CHILD + "/api/auth/callback/nathan");
  assert.equal(status.consoleUrl, "https://id.example.com/studio", "links the parent's Studio");
  assert.deepEqual(status.values, { issuer: ISSUER, clientId: CLIENT, displayName: "Example ID", trustEmailVerified: "true" });
  assert.deepEqual(status.secretsSet, ["clientSecret"]);
  assert.ok(!JSON.stringify(status).includes(SECRET));

  const { credentials, unavailable } = await loadSocialProviderState(env);
  assert.deepEqual(unavailable, []);
  assert.equal(credentials.nathan.discovery.tokenEndpoint, DOC.token_endpoint);
  assert.equal(credentials.nathan.clientSecret, SECRET);

  // Test sign-in: a ticket bound to the credential version, completed by a nathan callback session.
  const { ticket } = await beginProviderTest(env, { id: "nathan" }, "admin", deps);
  await recordProviderSignIn(env, { providerId: "nathan", sessionId: "s-1", userId: "admin" });
  const tested = await completeProviderTest(env, ticket, { sessionId: "s-1", userId: "admin" }, deps);
  assert.deepEqual(tested, { id: "nathan", tested: true, adminVerified: true });

  // Disable needs the exact confirmation, and the upstream is the only tested method, so it is the last one administrators have.
  await assert.rejects(setSocialProviderEnabled(env, { id: "nathan", enabled: false, confirm: "yes" }, "admin", deps), /confirmation/);
  await assert.rejects(setSocialProviderEnabled(env, { id: "nathan", enabled: false, confirm: "CONFIRM DISABLE nathan" }, "admin", deps),
    /last login method/);
  // Rotation stores new credentials and voids the test record.
  await upsertSocialProvider(env, { id: "nathan", fields: { ...VALUES, clientSecret: SECRET + "rotated" } }, "admin", deps);
  assert.equal(db.prepare("SELECT tested_version FROM nathan_provider_state WHERE id='nathan'").get().tested_version, null);
  assert.equal((await loadSocialProviderState(env)).credentials.nathan.clientSecret, SECRET + "rotated");
});

test("isolation: an undecryptable or undiscoverable upstream is turned off alone", async () => {
  const { db, env, deps } = storeEnv();
  globalThis.fetch = parentFetch().fetcher;
  await upsertSocialProvider(env, { id: "nathan", fields: VALUES }, "admin", deps);
  // The parent's discovery fails: the provider is unavailable (no button, no sign-in), nothing else is affected.
  clearUpstreamCaches();
  globalThis.fetch = async () => new Response("down", { status: 503 });
  let state = await loadSocialProviderState(env);
  assert.deepEqual(state.unavailable, [{ id: "nathan", reason: "unusable_credentials" }]);
  assert.ok(!state.credentials.nathan);
  assert.equal(db.prepare("SELECT reason FROM nathan_provider_health WHERE id='nathan'").get().reason, "unusable_credentials");
  // NATHAN_CONFIG_KEY changed without re-saving: decrypt_failed, never a fallback.
  clearUpstreamCaches();
  globalThis.fetch = parentFetch().fetcher;
  state = await loadSocialProviderState({ ...env, NATHAN_CONFIG_KEY: generateConfigKey() });
  assert.deepEqual(state.unavailable, [{ id: "nathan", reason: "decrypt_failed" }]);
  // Recovery clears the health row.
  state = await loadSocialProviderState(env);
  assert.deepEqual(state.unavailable, []);
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_provider_health").get().n, 0);
  // A disabled upstream is not loaded at all.
  db.prepare("UPDATE nathan_provider_state SET enabled=0 WHERE id='nathan'").run();
  assert.ok(!(await loadSocialProviderState(env)).credentials.nathan);
});

test("migration 0019 keeps provider rows and state, and admits only the nathan id", () => {
  const db = new DatabaseSync(":memory:");
  for (const f of ["0006_control_plane.sql", "0012_social_providers.sql"]) db.exec(readFileSync("migrations/" + f, "utf8"));
  db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,config,secret_fields,updated_at,updated_by) VALUES ('discord','c1','{}','{\"clientSecret\":\"v2.a.b\"}',5,'a')").run();
  db.prepare("INSERT INTO nathan_provider_state(id,enabled,updated_at,updated_by,tested_at,tested_by,tested_user,tested_version) VALUES ('discord',0,6,'a',7,'a','u','ver')").run();
  assert.throws(() => db.prepare("INSERT INTO nathan_provider_state(id,updated_by) VALUES ('nathan','a')").run(), /CHECK/);
  db.exec(readFileSync("migrations/0019_nathan_upstream.sql", "utf8"));
  assert.deepEqual({ ...db.prepare("SELECT * FROM nathan_oauth_providers").get() },
    { id: "discord", client_id: "c1", secret_cipher: null, config: "{}", secret_fields: '{"clientSecret":"v2.a.b"}', updated_at: 5, updated_by: "a" });
  assert.deepEqual({ ...db.prepare("SELECT * FROM nathan_provider_state").get() },
    { id: "discord", enabled: 0, updated_at: 6, updated_by: "a", tested_at: 7, tested_by: "a", tested_user: "u", tested_version: "ver" });
  db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_fields,updated_by) VALUES ('nathan','c','{\"clientSecret\":\"v2.x.y\"}','a')").run();
  db.prepare("INSERT INTO nathan_provider_state(id,updated_by) VALUES ('nathan','a')").run();
  assert.throws(() => db.prepare("INSERT INTO nathan_oauth_providers(id,client_id,secret_fields,updated_by) VALUES ('okta','c','{\"a\":1}','a')").run(), /CHECK/);
  assert.throws(() => db.prepare("INSERT INTO nathan_provider_state(id,updated_by) VALUES ('okta','a')").run(), /CHECK/);
  assert.throws(() => db.prepare("UPDATE nathan_oauth_providers SET secret_fields='{}' WHERE id='nathan'").run(), /CHECK/, "a row always carries an encrypted secret");
});
