import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { hashPassword } from "better-auth/crypto";
import { createLocalJWKSet, jwtVerify } from "jose";
import { signedOAuthQuery } from "../../src/auth/oauth-query.mjs";
import { authWorker, browserRedirect, cookiesOf, enrollAdmin, randomKey, studioPost } from "./helpers.mjs";

const HOST = "login.example.test";
const ORIGIN = "https://" + HOST;
const ISSUER = ORIGIN + "/api/auth";

function authorization(client, endpoint, extra = {}) {
  const verifier = randomKey(), state = randomKey(), nonce = randomKey();
  const url = new URL(endpoint);
  url.search = new URLSearchParams({
    response_type: "code", scope: "openid profile email", client_id: client.client_id,
    redirect_uri: client.redirect_uris[0], nonce, state,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256", ...extra
  }).toString();
  return { url, verifier, state, nonce };
}

function callback(location, client, flow) {
  const url = new URL(location);
  assert.equal(url.origin + url.pathname, client.redirect_uris[0]);
  assert.equal(url.searchParams.get("state"), flow.state);
  assert.equal(url.searchParams.get("iss"), ISSUER);
  return url.searchParams;
}

test("one issuer supports independent realm and external OIDC clients across sign-in, consent and token exchange", async t => {
  const secret = randomKey() + randomKey(), password = randomKey();
  const mf = await authWorker(HOST, { BETTER_AUTH_SECRET: secret, ENABLE_PASSWORD: "true", NATHAN_REALM_APEX: "example.test" });
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("DB");
  const admin = await enrollAdmin(db, secret);
  const worker = { fetch: (url, init) => mf.dispatchFetch(url, init) };
  const studio = async (path, body) => {
    const response = await studioPost(worker, ORIGIN, "/studio/api/v1/" + path, body, admin.cookie);
    const result = await response.json();
    assert.equal(response.status, 200, path + " " + (result.error?.code ?? ""));
    return result.data;
  };
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"(id, name, email, emailVerified, createdAt, updatedAt) VALUES (\'member\', \'Member\', \'member@example.test\', 1, ?, ?)').bind(now, now).run();
  await db.prepare('INSERT INTO account(id, accountId, providerId, userId, password, createdAt, updatedAt) VALUES (\'account\', \'member\', \'credential\', \'member\', ?, ?, ?)').bind(await hashPassword(password), now, now).run();
  await db.prepare("INSERT INTO nathan_domain_realms(apex, issuer_hostname, account_id, zone_id, registered_by) VALUES ('example.test', ?, 'account', 'zone', 'installer')").bind(HOST).run();

  const first = await studio("realm/clients", { hostname: "books.example.test", kind: "web", callbackPath: "/auth/callback" });
  const audit = await db.prepare("SELECT outcome FROM nathan_security_audit WHERE action='realm_client_create' AND target=? ORDER BY rowid").bind("books.example.test").all();
  assert.deepEqual(audit.results.map(row => row.outcome), ["attempted", "succeeded"]);
  const other = await studio("clients", { name: "Courses", kind: "external", redirectUri: "https://courses.example.org/oidc/callback" });
  assert.equal(first.enabled, false);
  assert.ok(first.client_id && other.client_id && first.client_id !== other.client_id);
  assert.ok(first.client_secret && other.client_secret && first.client_secret !== other.client_secret);
  assert.equal(first.oidcConfig.issuer, ISSUER);
  const document = await mf.dispatchFetch(first.oidcConfig.discovery);
  assert.equal(document.status, 200, "a new app must be able to use the discovery URL returned by Studio");
  const metadata = await document.json();
  assert.equal(metadata.issuer, ISSUER);
  assert.ok(metadata.code_challenge_methods_supported.includes("S256"));
  for (const key of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) assert.equal(new URL(metadata[key]).origin, ORIGIN);

  let cookie = "";
  const navigate = flow => browserRedirect(mf, flow.url, cookie);
  const disabled = await navigate(authorization(first, metadata.authorization_endpoint));
  assert.equal(disabled.searchParams.get("error"), "client_disabled");
  await studio("clients/status", { clientId: first.client_id, disabled: false });
  const crossed = await navigate(authorization(first, metadata.authorization_endpoint, { redirect_uri: other.redirect_uris[0] }));
  assert.equal(crossed.origin, ORIGIN);
  assert.equal(crossed.searchParams.get("error"), "invalid_redirect");

  // Start the first RP in a signed-out browser. Submit the same signed query as Nathan's hosted page.
  const start = authorization(first, metadata.authorization_endpoint);
  const login = await navigate(start);
  assert.equal(login.origin + login.pathname, ORIGIN + "/sign-in");
  const signIn = await mf.dispatchFetch(ISSUER + "/sign-in/email", { method: "POST",
    headers: { Origin: ORIGIN, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ email: "member@example.test", password, oauth_query: signedOAuthQuery(login.search) }) });
  assert.equal(signIn.status, 200);
  const session = cookiesOf(signIn)["__Secure-nathan.session_token"];
  assert.ok(session);
  assert.match(session.raw, /; Secure(?:;|$)/i);
  assert.match(session.raw, /; HttpOnly(?:;|$)/i);
  assert.doesNotMatch(session.raw, /; Domain=/i);
  cookie = "__Secure-nathan.session_token=" + session.value;
  const firstConsent = new URL((await signIn.json()).url, ORIGIN);

  const accept = async (consent, client, flow) => {
    assert.equal(consent.origin + consent.pathname, ORIGIN + "/consent");
    assert.equal(consent.searchParams.get("client_id"), client.client_id);
    assert.equal((await mf.dispatchFetch(consent.href, { headers: { Cookie: cookie } })).status, 200);
    const response = await mf.dispatchFetch(ISSUER + "/oauth2/consent", { method: "POST",
      headers: { Cookie: cookie, Origin: ORIGIN, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ accept: true, oauth_query: signedOAuthQuery(consent.search) }) });
    assert.equal(response.status, 200);
    const params = callback((await response.json()).url, client, flow);
    assert.ok(params.has("code"));
    return params.get("code");
  };
  const exchange = (client, code, verifier) => mf.dispatchFetch(metadata.token_endpoint, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(client.client_id + ":" + client.client_secret).toString("base64") },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: client.redirect_uris[0], code_verifier: verifier }).toString() });
  const idToken = async (client, flow, consent) => {
    const response = await exchange(client, await accept(consent, client, flow), flow.verifier);
    assert.equal(response.status, 200);
    return (await response.json()).id_token;
  };
  const firstToken = await idToken(first, start, firstConsent);

  // The second RP reuses the issuer session but still needs its own consent.
  const silent = authorization(other, metadata.authorization_endpoint, { prompt: "none" });
  const denied = callback(await navigate(silent), other, silent);
  assert.equal(denied.get("error"), "consent_required");
  assert.equal(denied.has("code"), false);
  const second = authorization(other, metadata.authorization_endpoint);
  const otherToken = await idToken(other, second, await navigate(second));

  const jwks = await mf.dispatchFetch(metadata.jwks_uri);
  assert.equal(jwks.status, 200);
  const keys = createLocalJWKSet(await jwks.json());
  const verify = (token, audience) => jwtVerify(token, keys, { algorithms: ["EdDSA", "ES256", "RS256"],
    issuer: ISSUER, audience, requiredClaims: ["exp", "iat", "sub", "nonce"] });
  for (const [token, client, flow, wrongClient] of [[firstToken, first, start, other], [otherToken, other, second, first]]) {
    const { payload } = await verify(token, client.client_id);
    assert.equal(payload.sub, "member");
    assert.equal(payload.nonce, flow.nonce);
    await assert.rejects(() => verify(token, wrongClient.client_id), { code: "ERR_JWT_CLAIM_VALIDATION_FAILED", claim: "aud" });
  }

  const returning = authorization(first, metadata.authorization_endpoint, { prompt: "none" });
  const granted = callback(await navigate(returning), first, returning);
  assert.ok(granted.has("code"), "returning to the first RP requires no new login or consent");
  const wrongVerifier = await exchange(first, granted.get("code"), randomKey());
  assert.equal(wrongVerifier.status, 400);
  assert.equal((await wrongVerifier.json()).error, "invalid_grant");
});
