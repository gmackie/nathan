import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test, { before, after } from "node:test";
import { createLocalJWKSet, jwtVerify } from "jose";
import { authWorker, enrollAdmin, randomKey, studioPost } from "./helpers.mjs";

const origin = "https://id.native.test", issuer = origin + "/api/auth";
const parent = "io.classcheck.parent:/oauth", driver = "io.classcheck.driver:/oauth";
const claimed = "https://mobile.example.test/oidc/callback";
const secret = randomKey();
let mf, admin;
const fetcher = { fetch(...args) { return mf.dispatchFetch(...args); } };
before(async () => {
  mf = await authWorker(new URL(origin).hostname, { BETTER_AUTH_SECRET: secret });
  admin = await enrollAdmin(await mf.getD1Database("DB"), secret);
});
after(() => mf?.dispose());
const register = (redirectUri, extra = {}) => studioPost(fetcher, origin, "/studio/api/clients",
  { name: "ClassCheck mobile", kind: "native", redirectUri, ...extra }, admin.cookie);
async function location(response) {
  return response.headers.get("Location") ?? (await response.json()).url;
}
function authorization(clientId, redirect, verifier, nonce, state) {
  return new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirect, scope: "openid email",
    nonce, state, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" });
}
const authorize = query => mf.dispatchFetch(issuer + "/oauth2/authorize?" + query, { redirect: "manual", headers: { Cookie: admin.cookie } });
async function finish(query) {
  let next = new URL(await location(await authorize(query)), origin);
  if (next.pathname === "/consent") {
    const consent = await studioPost(fetcher, origin, "/api/auth/oauth2/consent", { accept: true, oauth_query: next.search.slice(1) }, admin.cookie);
    assert.equal(consent.status, 200);
    next = new URL(await location(consent));
  }
  assert.equal(next.href.split("?")[0], query.get("redirect_uri"));
  assert.equal(next.searchParams.get("state"), query.get("state"));
  assert.ok(next.searchParams.get("code"));
  return next.searchParams.get("code");
}
const exchange = (clientId, redirect, code, verifier) => mf.dispatchFetch(issuer + "/oauth2/token", {
  method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, redirect_uri: redirect,
    code, ...(verifier ? { code_verifier: verifier } : {}) }).toString()
});

for (const redirect of [parent, driver, claimed]) test("public native S256 round trip with " + redirect, async () => {
  const created = await register(redirect);
  assert.equal(created.status, 200, await created.clone().text());
  const client = await created.json();
  assert.equal(client.application_type, "native");
  assert.equal(client.token_endpoint_auth_method, "none");
  assert.ok(!client.client_secret);
  assert.equal(client.require_pkce, true);
  assert.deepEqual(client.redirect_uris, [redirect]);
  const verifier = randomKey(), nonce = randomKey(), state = randomKey();
  const query = authorization(client.client_id, redirect, verifier, nonce, state);
  const code = await finish(query);
  const exchanged = await exchange(client.client_id, redirect, code, verifier);
  assert.equal(exchanged.status, 200);
  const tokens = await exchanged.json();
  const keys = createLocalJWKSet(await (await mf.dispatchFetch(issuer + "/jwks")).json());
  assert.equal((await jwtVerify(tokens.id_token, keys, { issuer, audience: client.client_id })).payload.nonce, nonce);
  assert.ok(tokens.access_token);
});

test("native registration and authorization pin the mobile redirect and require S256", async () => {
  for (const redirect of ["http://mobile.example.test/cb", "school:/oauth", "io.classcheck.parent://authority/oauth", "io.classcheck.parent:/o*",
    "io.classcheck.parent:/oauth#", "https://*.example.test/oauth", "https://user@mobile.example.test/oauth"]) {
    assert.equal((await register(redirect)).status, 400, redirect);
  }
  assert.equal((await register(parent, { publicClient: false })).status, 400);
  assert.equal((await register(parent, { kind: "external", publicClient: true })).status, 400);
  const created = await register(parent);
  assert.equal(created.status, 200);
  const { client_id } = await created.json();
  const query = authorization(client_id, parent, randomKey(), randomKey(), randomKey());
  for (const other of [driver, parent + "/"]) {
    const wrong = new URLSearchParams(query);
    wrong.set("redirect_uri", other);
    const failure = new URL(await location(await authorize(wrong)), origin);
    assert.equal(failure.origin, origin);
    assert.equal(failure.searchParams.has("code"), false);
  }
  for (const method of ["", "plain"]) {
    const wrong = new URLSearchParams(query);
    wrong.set("code_challenge_method", method);
    if (!method) { wrong.delete("code_challenge"); wrong.delete("code_challenge_method"); }
    const response = await authorize(wrong);
    if (response.status < 400) {
      const error = new URL(await location(response), origin);
      assert.ok(error.searchParams.get("error"));
      assert.equal(error.searchParams.has("code"), false);
    }
  }
  const code = await finish(query);
  assert.ok((await exchange(client_id, parent, code)).status >= 400);
  const differentCode = await finish(authorization(client_id, parent, randomKey(), randomKey(), randomKey()));
  assert.ok((await exchange(client_id, parent, differentCode, randomKey())).status >= 400);
});
