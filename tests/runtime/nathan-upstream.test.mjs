/**
 * NATH-51 in workerd: "Sign in with Nathan" end to end between two built identity Workers. The
 * parent is a real Nathan instance (its own discovery, authorization, token and JWKS endpoints,
 * EdDSA ID tokens); the child reaches it through Miniflare's outbound service. Covers Studio
 * configuration through the parent's real discovery, the hosted button, PKCE S256 + state + nonce,
 * issuer-qualified accounts, admission (invitation-only and self-service), email_verified false,
 * linking rules, refused client-submitted ID tokens, no local MFA evidence from the parent, and the
 * Studio test sign-in.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, randomKey, enrollAdmin, insertSession, studioPost } from "./helpers.mjs";

const PARENT_HOST = "parent.example.test", PARENT = "https://" + PARENT_HOST, PARENT_ISSUER = PARENT + "/api/auth";
const CHILD_HOST = "child.example.test", CHILD = "https://" + CHILD_HOST;
const CALLBACK = CHILD + "/api/auth/callback/nathan";
const PARENT_SECRET = randomKey() + randomKey(), CHILD_SECRET = randomKey() + randomKey();

let parent, child, parentDb, childDb, parentAdmin, childAdmin, client;
const outboundLog = [];
/** The child's outbound HTTP: only the parent exists. */
async function outbound(request) {
  const url = new URL(request.url);
  outboundLog.push({ url: url.href, method: request.method });
  if (url.origin !== PARENT) return new Response("unexpected outbound " + url.href, { status: 599 });
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer();
  const response = await parent.dispatchFetch(url.href, { method: request.method, headers: Object.fromEntries(request.headers), body, redirect: "manual" });
  return new Response(await response.arrayBuffer(), { status: response.status, headers: response.headers });
}
/** studioPost's fetcher shape over a Miniflare instance. */
const via = mf => ({ fetch: (url, init) => mf.dispatchFetch(url, init) });
const parentSql = (sql, ...args) => parentDb.prepare(sql).bind(...args).run();
const childSql = (sql, ...args) => childDb.prepare(sql).bind(...args).run();
async function parentUser(id, email, verified = true) {
  const now = new Date().toISOString();
  await parentSql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)', id, "Parent " + id, email, verified ? 1 : 0, now, now);
  return insertSession(parentDb, PARENT_SECRET, id);
}

before(async () => {
  parent = await authWorker(PARENT_HOST, { BETTER_AUTH_SECRET: PARENT_SECRET });
  parentDb = await parent.getD1Database("DB");
  child = await authWorker(CHILD_HOST, { BETTER_AUTH_SECRET: CHILD_SECRET, NATHAN_INSTANCE_NAME: "child" }, { outboundService: outbound });
  childDb = await child.getD1Database("DB");
  parentAdmin = await enrollAdmin(parentDb, PARENT_SECRET);
  childAdmin = await enrollAdmin(childDb, CHILD_SECRET);
  // The owner's step on the parent: an external, confidential client whose only redirect URI is the child's callback.
  const created = await studioPost(via(parent), PARENT, "/studio/api/clients", { name: "Child instance", kind: "external", redirectUri: CALLBACK }, parentAdmin.cookie);
  assert.equal(created.status, 200, await created.clone().text());
  client = await created.json();
  assert.ok(client.client_id && client.client_secret);
  // Test shortcut: the parent's consent page is Better Auth's own; this file is about the child.
  await parentSql('UPDATE "oauthClient" SET "skipConsent"=1 WHERE "clientId"=?', client.client_id);
});
after(() => Promise.all([parent?.dispose(), child?.dispose()]));

/** Cookie jar with SameSite handling: Lax cookies go with top-level cross-site GETs only. */
function merge(jar, response) {
  for (const line of response.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(";");
    const name = pair.slice(0, pair.indexOf("=")), value = pair.slice(pair.indexOf("=") + 1);
    const sameSite = (attrs.map(a => a.trim().split("=")).find(([k]) => k.toLowerCase() === "samesite")?.[1] || "lax").toLowerCase();
    if (!value || attrs.some(a => /^max-age=0$/i.test(a.trim()))) delete jar[name]; else jar[name] = { value, sameSite };
  }
  return jar;
}
const cookieHeader = (jar, crossSite = false) => Object.entries(jar)
  .filter(([, c]) => !crossSite || c.sameSite !== "strict").map(([k, c]) => k + "=" + c.value).join("; ");
let ip = 0;
/** Starts "Sign in with Nathan" on the child exactly as the hosted page does. */
async function begin(jar = {}, callbackURL = "/") {
  const response = await child.dispatchFetch(CHILD + "/api/auth/sign-in/social", {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/json", Origin: CHILD, Cookie: cookieHeader(jar), "cf-connecting-ip": "198.51.100." + (++ip) },
    body: JSON.stringify({ provider: "nathan", callbackURL, errorCallbackURL: "/sign-in" })
  });
  assert.equal(response.status, 200, "sign-in/social: " + await response.clone().text());
  merge(jar, response);
  return { authorize: new URL((await response.json()).url), jar };
}
/** The parent authorizes the signed-in parent user and redirects back to the child. */
async function authorizeAtParent(authorize, parentCookie) {
  const response = await parent.dispatchFetch(authorize.href, { redirect: "manual",
    headers: { Cookie: parentCookie, Accept: "text/html", "Sec-Fetch-Mode": "navigate" } });
  let target = response.headers.get("Location");
  if (response.status === 200) target = (await response.clone().json()).url;
  assert.ok(target, "parent did not redirect: " + response.status + " " + await response.clone().text());
  return new URL(target, PARENT);
}
/** The browser follows the parent's redirect to the child's callback (cross-site top-level GET). */
async function finish(back, jar) {
  const response = await child.dispatchFetch(back.href, { redirect: "manual", headers: { Cookie: cookieHeader(jar, true) } });
  merge(jar, response);
  return response;
}
async function signIn(parentSession, jar = {}, callbackURL = "/") {
  const { authorize } = await begin(jar, callbackURL);
  const back = await authorizeAtParent(authorize, parentSession.cookie);
  return { authorize, back, response: await finish(back, jar), jar };
}
const nathanAccount = sub => childDb.prepare('SELECT a."userId" AS userId, a."accountId" AS accountId, u."email" AS email, u."emailVerified" AS verified ' +
  'FROM "account" a JOIN "user" u ON u."id"=a."userId" WHERE a."providerId"=\'nathan\' AND a."accountId"=?').bind(PARENT_ISSUER + "#" + sub).first();
const childUserByEmail = email => childDb.prepare('SELECT "id","emailVerified" FROM "user" WHERE "email"=?').bind(email).first();
const audits = async action => (await childDb.prepare("SELECT actor,action,target,outcome FROM nathan_security_audit WHERE action=? ORDER BY rowid").bind(action).all()).results;
const configure = fields => studioPost(via(child), CHILD, "/studio/api/providers", { id: "nathan", fields }, childAdmin.cookie);
const VALID = () => ({ issuer: PARENT_ISSUER, clientId: client.client_id, clientSecret: client.client_secret, displayName: "Parent ID", trustEmailVerified: "true" });

test("Studio configures the upstream from the parent's real discovery; untrusted or wrong issuers are refused", async () => {
  const untrusted = await configure({ ...VALID(), trustEmailVerified: "" });
  assert.equal(untrusted.status, 409, await untrusted.clone().text());
  const wrongIssuer = await configure({ ...VALID(), issuer: PARENT });
  assert.equal(wrongIssuer.status, 409, "the issuer must be exactly the parent's published issuer");
  assert.match(await wrongIssuer.text(), /discovery/);
  assert.equal((await childDb.prepare("SELECT count(*) AS n FROM nathan_oauth_providers").first()).n, 0);

  const saved = await configure(VALID());
  assert.equal(saved.status, 200, await saved.clone().text());
  assert.equal((await saved.json()).callbackUrl, CALLBACK);
  const row = await childDb.prepare("SELECT * FROM nathan_oauth_providers WHERE id='nathan'").first();
  assert.ok(!JSON.stringify(row).includes(client.client_secret), "the parent client secret is encrypted at rest");
  assert.deepEqual((await audits("oauth_provider_update")).map(a => a.outcome),
    ["attempted", "failed_validation", "attempted", "failed_validation", "attempted", "succeeded"]);
  const status = (await (await child.dispatchFetch(CHILD + "/studio/api/providers", { headers: { Cookie: childAdmin.cookie } })).json())
    .providers.find(p => p.id === "nathan");
  assert.equal(status.callbackUrl, CALLBACK);
  assert.equal(status.consoleUrl, PARENT + "/studio");
  assert.equal(status.available, true);
  assert.ok(!JSON.stringify(status).includes(client.client_secret));

  const page = await (await child.dispatchFetch(CHILD + "/sign-in")).text();
  assert.ok(page.includes('data-provider="nathan">Sign in with Parent ID</button>'), "the configured button label");
});

test("invitation-only admission refuses a parent account that has no invitation", async () => {
  const frank = await parentUser("p-frank", "frank@example.test");
  const { response } = await signIn(frank);
  assert.equal(response.status, 302);
  assert.match(response.headers.get("Location"), /error=ACCOUNT_NOT_ADMITTED/);
  assert.equal(await childUserByEmail("frank@example.test"), null, "no account created");
  assert.equal(await nathanAccount("p-frank"), null);
});

let aliceJar;
test("an invited, verified parent account signs in with PKCE S256, state and nonce; the account is issuer-qualified", async () => {
  const alice = await parentUser("p-alice", "alice@example.test");
  await childSql("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,?,unixepoch()+3600)", crypto.randomUUID(), "alice@example.test", "admin-1");
  const tokenCalls = () => outboundLog.filter(o => o.url === PARENT_ISSUER + "/oauth2/token").length;
  const before = tokenCalls();
  const { authorize, back, response, jar } = await signIn(alice);
  assert.equal(authorize.origin + authorize.pathname, PARENT_ISSUER + "/oauth2/authorize", "the discovered authorization endpoint");
  assert.equal(authorize.searchParams.get("client_id"), client.client_id);
  assert.equal(authorize.searchParams.get("redirect_uri"), CALLBACK);
  assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
  assert.match(authorize.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  assert.ok(authorize.searchParams.get("nonce")?.length >= 32, "nonce");
  assert.ok(authorize.searchParams.get("state")?.length >= 32, "state");
  assert.deepEqual(authorize.searchParams.get("scope").split(" ").sort(), ["email", "openid", "profile"]);
  assert.equal(back.origin + back.pathname, CALLBACK);
  assert.equal(response.status, 302, await response.clone().text());
  assert.equal(response.headers.get("Location"), "/");
  assert.ok(jar["__Secure-nathan.session_token"], "child session issued");
  assert.equal(tokenCalls(), before + 1, "one code exchange at the parent");
  assert.ok(outboundLog.some(o => o.url === PARENT_ISSUER + "/jwks"), "the ID token was verified against the parent's JWKS");

  const account = await nathanAccount("p-alice");
  assert.equal(account.email, "alice@example.test");
  assert.equal(account.verified, 1);
  assert.equal(account.accountId, PARENT_ISSUER + "#p-alice");
  assert.equal((await childDb.prepare("SELECT uses FROM nathan_invitations WHERE email='alice@example.test'").first()).uses, 1, "invitation claimed");
  // The parent's authentication is not local MFA: the child session has no assurance evidence, so no nathan_amr/nathan_acr.
  const session = await (await child.dispatchFetch(CHILD + "/api/auth/get-session", { headers: { Cookie: cookieHeader(jar) } })).json();
  assert.equal(session.user.email, "alice@example.test");
  assert.equal((await childDb.prepare("SELECT count(*) AS n FROM nathan_admin_assurance WHERE user_id=?").bind(account.userId).first()).n, 0);
  // The state is single use: replaying the parent's redirect fails without another code exchange.
  const replay = await finish(back, { ...jar });
  assert.match(replay.headers.get("Location") || "", /error=/);
  assert.equal(tokenCalls(), before + 1);
  aliceJar = jar;
});

test("a parent account whose email is not verified is refused and audited", async () => {
  await childSql("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','test') ON CONFLICT(id) DO UPDATE SET mode='self-service'");
  const bob = await parentUser("p-bob", "bob@example.test", false);
  const { response } = await signIn(bob);
  assert.equal(response.status, 302);
  assert.match(response.headers.get("Location"), /error=/);
  assert.equal(await childUserByEmail("bob@example.test"), null, "no account, not even with self-service admission");
  assert.deepEqual((await audits("nathan_upstream_signin")).map(a => [a.actor, a.target, a.outcome]),
    [["system:nathan-upstream", "nathan", "refused_email_unverified"]]);
});

test("self-service admission creates an account for a verified parent address without an invitation", async () => {
  const erin = await parentUser("p-erin", "erin@example.test");
  const { response } = await signIn(erin);
  assert.equal(response.headers.get("Location"), "/");
  assert.equal((await nathanAccount("p-erin")).email, "erin@example.test");
});

test("linking: a verified parent address links only to a verified local account with the same address", async () => {
  const now = new Date().toISOString();
  await childSql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'c-carol\',\'Carol\',\'carol@example.test\',1,?,?)', now, now);
  await childSql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'c-dave\',\'Dave\',\'dave@example.test\',0,?,?)', now, now);
  const carol = await parentUser("p-carol", "carol@example.test");
  const linked = await signIn(carol);
  assert.equal(linked.response.headers.get("Location"), "/");
  assert.equal((await nathanAccount("p-carol")).userId, "c-carol", "linked to the existing verified account");
  const dave = await parentUser("p-dave", "dave@example.test");
  const refused = await signIn(dave);
  assert.match(refused.response.headers.get("Location"), /error=/, "an unverified local account is never linked");
  assert.equal(await nathanAccount("p-dave"), null);
  assert.equal((await childUserByEmail("dave@example.test")).emailVerified, 0);
});

test("a client-submitted ID token is refused for sign-in and linking", async () => {
  for (const path of ["/api/auth/sign-in/social", "/api/auth/link-social"]) {
    const response = await child.dispatchFetch(CHILD + path, {
      method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/json", Origin: CHILD, Cookie: cookieHeader(aliceJar), "cf-connecting-ip": "198.51.100." + (++ip) },
      body: JSON.stringify({ provider: "nathan", idToken: { token: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln", nonce: "x" } })
    });
    assert.equal(response.status, 400, path);
    assert.equal((await response.json()).code, "ID_TOKEN_SIGN_IN_DISABLED");
    assert.ok(!response.headers.getSetCookie().some(c => /session_token=[^;]/.test(c)));
  }
});

test("a forged state never reaches the parent's token endpoint", async () => {
  const before = outboundLog.length;
  const forged = await child.dispatchFetch(CALLBACK + "?code=stolen&state=" + "x".repeat(32) + "&iss=" + encodeURIComponent(PARENT_ISSUER), { redirect: "manual" });
  assert.match(forged.headers.get("Location") || "", /error=/);
  assert.ok(!outboundLog.slice(before).some(o => o.url.endsWith("/oauth2/token")));
});

test("Studio test sign-in through the parent records an administrator test", async () => {
  // The child's administrator (admin@example.test, verified) is also a verified account on the parent.
  const parentSide = parentAdmin;
  const begun = await studioPost(via(child), CHILD, "/studio/api/providers/test", { id: "nathan" }, childAdmin.cookie);
  assert.equal(begun.status, 200, await begun.clone().text());
  const { callbackURL } = await begun.json();
  const jar = {};
  const { response } = await signIn(parentSide, jar, callbackURL);
  assert.equal(response.headers.get("Location"), callbackURL, await response.clone().text());
  const done = await child.dispatchFetch(CHILD + callbackURL, { redirect: "manual", headers: { Cookie: cookieHeader(jar) } });
  assert.equal(done.status, 200, await done.clone().text());
  assert.match(await done.text(), /Test sign-in succeeded/);
  const state = await childDb.prepare("SELECT tested_user, tested_version FROM nathan_provider_state WHERE id='nathan'").first();
  assert.equal(state.tested_user, "admin-1", "the parent account linked to the child's verified administrator");
  assert.ok(state.tested_version);
  assert.equal((await nathanAccount("admin-1")).userId, "admin-1");
});
