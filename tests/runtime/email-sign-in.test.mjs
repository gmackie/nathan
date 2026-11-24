import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { build } from "esbuild";
import { EventEmitter, once } from "node:events";
import { createHash } from "node:crypto";
import { symmetricEncrypt } from "better-auth/crypto";
import { createOTP } from "@better-auth/utils/otp";
import { createLocalJWKSet, jwtVerify } from "jose";
import { authWorker, cookiesOf, enrollAdmin, randomKey } from "./helpers.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST, ISSUER = ORIGIN + "/api/auth";
const RESOURCE = "https://classcheck.example.test/api";
const CALLBACK = "https://classcheck.example.test/auth/callback";
const PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aB9sAAAAASUVORK5CYII=";
const messages = [], inbox = new EventEmitter();
const secret = randomKey() + randomKey();
let mf, db, client, sequence = 0;
const sql = (s, ...p) => db.prepare(s).bind(...p).run();
const one = (s, ...p) => db.prepare(s).bind(...p).first();
const cookie = (r, name) => {
  const entry = cookiesOf(r)[name];
  return entry ? name + "=" + entry.value : "";
};
const post = (path, body, cookies = "", ip = "192.0.2." + ++sequence) =>
  mf.dispatchFetch(ORIGIN + path, { method: "POST", redirect: "manual", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", Origin: ORIGIN, Cookie: cookies, "CF-Connecting-IP": ip } });
const flows = new Map();
async function requestCode(email, query, ip, browser = "") {
  const response = await post("/sign-in/email/request", { email, oauth_query: query }, browser, ip);
  if (response.ok) flows.set(cookie(response, "__Host-nathan-email"), (await response.clone().json()).flowId);
  return response;
}
const verify = (browser, code, extra = {}) => post("/sign-in/email/verify", { code, flowId: flows.get(browser), ...extra }, browser);
const invite = async email => {
  const id = crypto.randomUUID();
  await sql("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,'admin',unixepoch()+3600)", id, email);
  return id;
};
async function mailFor(email, index = 0) {
  const timeout = AbortSignal.timeout(5000);
  while (messages.filter(m => m.to.includes(email)).length <= index) await once(inbox, email, { signal: timeout });
  const mail = messages.filter(m => m.to.includes(email))[index];
  const code = mail.text.match(/\b[0-9]{6}\b/)?.[0];
  const link = new URL(mail.text.match(/https:\/\/[^\s]+/)?.[0]);
  assert.ok(code);
  return { mail, code, link };
}
// Execute the hosted island's fragment handler with a browser location, cookie jar and real
// Worker fetch. The GET alone (including a scanner's preview) has no credential to redeem.
async function tapLink(link, browser) {
  const page = await mf.dispatchFetch(link.origin + link.pathname);
  assert.match(await page.text(), /src="[^"]*email-sign-in-[^"]+\.js"/);
  const { outputFiles } = await build({ entryPoints: ["src/ui/islands/email-sign-in.ts"], format: "iife", bundle: true, write: false });
  const landed = Promise.withResolvers();
  AbortSignal.timeout(8000).addEventListener("abort", () => landed.reject(Error("The email link did not navigate")), { once: true });
  let response, fragmentCleared = false;
  const element = { addEventListener() {}, querySelector: () => ({}), focus() {} };
  const location = { hash: link.hash, search: "", pathname: link.pathname, assign: landed.resolve };
  runInNewContext(outputFiles[0].text, { URLSearchParams, location,
    document: { querySelector: () => element },
    history: { replaceState(_state, _title, path) { assert.equal(path, link.pathname); fragmentCleared = true; } },
    fetch: async (path, init) => {
      try {
        assert.equal(fragmentCleared, true);
        response = await post(path, JSON.parse(init.body), browser);
        if (!response.ok) throw Error("The hosted link could not be redeemed: " + response.status);
        return response.clone();
      } catch (error) { landed.reject(error); throw error; }
    }
  });
  const target = await landed.promise;
  assert.equal(target, (await response.clone().json()).url);
  return response;
}
async function beginAuthorization(email) {
  const verifier = randomKey(), state = randomKey(), nonce = randomKey();
  const params = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CALLBACK,
    scope: "openid email", state, nonce, login_hint: email, resource: RESOURCE,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" });
  const start = await mf.dispatchFetch(ISSUER + "/oauth2/authorize?" + params, { redirect: "manual", headers: { Accept: "text/html", "Sec-Fetch-Mode": "navigate" } });
  const location = start.headers.get("location") ?? (await start.json()).url;
  assert.ok(location, "authorization starts a hosted sign-in");
  const login = new URL(location, ORIGIN);
  assert.equal(login.pathname, "/sign-in");
  const hosted = await (await mf.dispatchFetch(login.href)).text();
  const href = hosted.match(/href="([^"]*\/sign-in\/email[^"]*)"/)?.[1];
  assert.ok(href, "hosted sign-in offers email");
  const page = new URL(href.replaceAll("&amp;", "&"), ORIGIN);
  const emailPage = await mf.dispatchFetch(page.href);
  assert.match(await emailPage.text(), /autocomplete="email"/i);
  assert.ok(page.searchParams.has("sig"));
  return { query: page.search.slice(1), state, verifier, nonce };
}
before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: secret, ENABLE_EMAIL_OTP: "true", RESEND_API_KEY: "test-sender", EMAIL_FROM: "nathan@example.test",
    NATHAN_EMAIL_LOGOS: JSON.stringify({ classcheck: PNG }), ENABLE_PASSWORD: "true" }, {
    outboundService: async req => {
      assert.equal(req.url, "https://api.resend.com/emails");
      const mail = await req.json();
      messages.push(mail);
      inbox.emit(mail.to[0]);
      return Response.json({ id: crypto.randomUUID() });
    }
  });
  db = await mf.getD1Database("DB");
  const admin = await enrollAdmin(db, secret);
  const r = await post("/studio/api/clients", { name: "ClassCheck Pilot", kind: "external", redirectUri: CALLBACK,
    appearance: { wordmark: "ClassCheck", logo: "classcheck" } }, admin.cookie);
  assert.ok(r.ok, await r.clone().text());
  client = await r.json();
  for (const operation of [{ op: "audience.register" }, { op: "audience.link", clientId: client.client_id }]) {
    const registered = await post("/studio/api/tokens", { ...operation, identifier: RESOURCE }, admin.cookie);
    assert.equal(registered.status, 200, await registered.clone().text());
  }
});
after(() => mf?.dispose());

test("configured mail alone leaves hosted email sign-in disabled", async () => {
  const disabled = await authWorker(HOST, { BETTER_AUTH_SECRET: secret, RESEND_API_KEY: "test-sender", EMAIL_FROM: "nathan@example.test" });
  try {
    const page = await disabled.dispatchFetch(ORIGIN + "/sign-in");
    assert.doesNotMatch(await page.text(), /href="\/sign-in\/email/);
    assert.equal((await disabled.dispatchFetch(ORIGIN + "/sign-in/email")).status, 404);
  } finally { await disabled.dispose(); }
});

for (const method of ["code", "link"]) test(method + " resumes hosted authorization, consent and PKCE with only email evidence", async () => {
  const email = method + "@example.test", invitation = await invite(email);
  const flow = await beginAuthorization(email);
  const start = await requestCode(email, flow.query);
  assert.equal(start.status, 202);
  const browser = cookie(start, "__Host-nathan-email");
  assert.match(start.headers.get("set-cookie"), /HttpOnly/i);
  const { mail, code, link } = await mailFor(email);
  assert.match(mail.subject, /ClassCheck/);
  assert.equal(mail.from, "nathan@example.test");
  assert.match(mail.html, /cid:classcheck/);
  assert.equal(mail.attachments[0].content, PNG);
  assert.equal(link.origin, ORIGIN);
  assert.equal(link.search, "");
  const [flowId, linkCode] = link.hash.slice(1).split(".");
  assert.equal(linkCode, code);
  assert.equal((await mf.dispatchFetch(link.origin + link.pathname)).status, 200);
  assert.equal((await one('SELECT count(*) n FROM "user" WHERE email=?', email)).n, 0);
  assert.equal((await verify("", code, { flowId })).status, 400);
  const result = method === "link" ? await tapLink(link, browser) : await verify(browser, code);
  assert.equal(result.status, 200, await result.clone().text());
  const session = cookie(result, "__Secure-nathan.session_token");
  assert.ok(session);
  const consent = new URL((await result.json()).url, ORIGIN);
  assert.equal(consent.pathname, "/consent");
  const approved = await post("/api/auth/oauth2/consent", { accept: true, oauth_query: consent.search.slice(1) }, session);
  const callback = new URL((await approved.json()).url);
  assert.equal(callback.origin + callback.pathname, CALLBACK);
  assert.equal(callback.searchParams.get("state"), flow.state);
  const token = await mf.dispatchFetch(ISSUER + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(client.client_id + ":" + client.client_secret) },
    body: new URLSearchParams({ grant_type: "authorization_code", code: callback.searchParams.get("code"), redirect_uri: CALLBACK, code_verifier: flow.verifier, resource: RESOURCE }) });
  assert.equal(token.status, 200, await token.clone().text());
  const tokens = await token.json();
  const keys = createLocalJWKSet(await (await mf.dispatchFetch(ISSUER + "/jwks")).json());
  const id = (await jwtVerify(tokens.id_token, keys, { issuer: ISSUER, audience: client.client_id })).payload;
  assert.equal(id.nonce, flow.nonce);
  const access = (await jwtVerify(tokens.access_token, keys, { issuer: ISSUER, audience: RESOURCE })).payload;
  assert.deepEqual(access.nathan_amr, ["email"]);
  assert.equal(access.nathan_acr, undefined);
  assert.deepEqual(await one("SELECT used_by_user AS subject,used_method AS method FROM nathan_invitations WHERE id=?", invitation),
    { subject: id.sub, method: "email-otp" });
  assert.equal((await verify(browser, code, method === "code" ? { flowId } : {})).status, 400);
});

test("email requests give the same reply for an invite, an unknown address, and delivery throttling", async () => {
  const address = "limited@example.test";
  await invite(address);
  const first = await requestCode(address.toUpperCase());
  const unknown = await requestCode("unknown@example.test");
  assert.equal(first.status, 202);
  assert.equal(unknown.status, first.status);
  const { message } = await first.json();
  assert.equal((await unknown.json()).message, message);
  const browser = cookie(first, "__Host-nathan-email");
  await mailFor(address);
  for (let i = 1; i <= 4; i++) {
    assert.equal((await (await requestCode(address, undefined, undefined, browser)).json()).message, message);
    if (i < 3) await mailFor(address, i);
  }
  const last = await mailFor(address, 2);
  assert.equal((await verify(browser, last.code)).status, 200, "throttled resend leaves the last email usable");
  assert.equal(messages.filter(m => m.to.includes(address)).length, 3);
  assert.equal(messages.filter(m => m.to.includes("unknown@example.test")).length, 0);
});

test("revocation before redemption, a new invitation, expiry and exhausting attempts refuse both choices", async () => {
  for (const reason of ["reissued", "expired", "attempts"]) {
    const email = reason + "@example.test", id = await invite(email);
    const start = await requestCode(email), browser = cookie(start, "__Host-nathan-email");
    const { code, link } = await mailFor(email);
    if (reason === "reissued") {
      await sql("UPDATE nathan_invitations SET revoked_at=unixepoch() WHERE id=?", id);
      await invite(email);
    } else if (reason === "expired") {
      await sql("UPDATE nathan_email_sign_ins SET expires_at=unixepoch()-1 WHERE email=?", email);
    } else {
      const wrong = code === "000000" ? "000001" : "000000";
      for (let i = 0; i < 5; i++) assert.equal((await verify(browser, wrong)).status, 400);
    }
    assert.equal((await verify(browser, code, { flowId: link.hash.slice(1).split(".")[0] })).status, 400);
    assert.equal(await one('SELECT id FROM "user" WHERE email=?', email), null);
  }
});

test("a verified, provisioned administrator can sign in once and still needs a recent passkey for Studio", async () => {
  const key = randomKey();
  await sql('UPDATE "user" SET twoFactorEnabled=1 WHERE id=?', "admin-1");
  await sql("UPDATE twoFactor SET secret=? WHERE userId=?", await symmetricEncrypt({ key: secret, data: key }), "admin-1");
  const start = await requestCode("admin@example.test"), browser = cookie(start, "__Host-nathan-email");
  const { code, link } = await mailFor("admin@example.test");
  const results = await Promise.all([verify(browser, code), verify(browser, code, { flowId: link.hash.slice(1).split(".")[0] })]);
  assert.deepEqual(results.map(r => r.status).sort(), [200, 400]);
  assert.deepEqual(await results.find(r => r.ok).json(), { twoFactorRedirect: true });
  const loggedIn = await post("/sign-in/email/verify", { totp: await createOTP(key).totp(), flowId: flows.get(browser) }, browser);
  const session = cookie(loggedIn, "__Secure-nathan.session_token");
  assert.ok(session);
  const studio = await mf.dispatchFetch(ORIGIN + "/studio/api/admission", { headers: { Cookie: session } });
  assert.equal(studio.status, 403);
  const register = await mf.dispatchFetch(ISSUER + "/passkey/generate-register-options", { headers: { Cookie: session } });
  assert.equal(register.status, 403, "mailbox proof cannot enroll a replacement admin passkey");
  assert.equal((await one("SELECT count(*) AS n FROM nathan_admin_assurance")).n, 1, "only the seeded passkey session");
});

test("the IP limit spans addresses, and disabled accounts and clients stay ineligible", async () => {
  const ip = "198.51.100.96", limited = "ip-limited@example.test";
  await invite(limited);
  for (let i = 0; i < 20; i++) assert.equal((await requestCode("ip" + i + "@example.test", undefined, ip)).status, 202);
  assert.equal((await requestCode(limited, undefined, ip)).status, 202);
  const accepted = await requestCode(limited);
  const { code } = await mailFor(limited);
  assert.equal(messages.filter(m => m.to.includes(limited)).length, 1);
  const allowed = await verify(cookie(accepted, "__Host-nathan-email"), code);
  assert.equal(allowed.status, 200);
  const start = await requestCode(limited);
  const issued = await mailFor(limited, 1);
  await sql('UPDATE "user" SET banned=1 WHERE email=?', limited);
  assert.equal((await verify(cookie(start, "__Host-nathan-email"), issued.code)).status, 400);
  const query = (await beginAuthorization(limited)).query;
  await sql('UPDATE "oauthClient" SET disabled=1 WHERE clientId=?', client.client_id);
  try {
    assert.equal((await requestCode(limited, query)).status, 400);
  } finally { await sql('UPDATE "oauthClient" SET disabled=0 WHERE clientId=?', client.client_id); }
});

test("hosted submission requires a signed continuation and same origin; internal OTP APIs are unreachable", async () => {
  const email = "unsigned@example.test";
  await invite(email);
  const query = (await beginAuthorization(email)).query;
  assert.equal((await requestCode(email, query.replace("client_id=", "other_id="))).status, 400);
  const cross = await mf.dispatchFetch(ORIGIN + "/sign-in/email/request", { method: "POST", body: JSON.stringify({ email }),
    headers: { Origin: "https://app.example.test", "Content-Type": "application/json" } });
  assert.equal(cross.status, 403);
  for (const path of ["/sign-in/email-otp", "/email-otp/send-verification-otp", "/email-otp/verify-email", "/email-otp/check-verification-otp", "/email-otp/request-password-reset"]) {
    assert.equal((await post("/api/auth" + path, { email, type: "sign-in", otp: "000000" })).status, 404, path);
  }
});

test("an active directory user outside enterprise SSO finishes enrolled TOTP before the OIDC handoff", async () => {
  const address = "mfa@example.test", key = randomKey(), now = new Date().toISOString();
  await sql('INSERT INTO "user"(id,name,email,emailVerified,twoFactorEnabled,createdAt,updatedAt) VALUES (\'mfa\',\'member\',?,1,1,?,?)', address, now, now);
  await sql("INSERT INTO twoFactor(id,userId,secret,backupCodes,verified) VALUES ('tf-mfa','mfa',?,'unused',1)", await symmetricEncrypt({ key: secret, data: key }));
  await sql("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES ('mfa-school','example.test','admin')");
  await sql("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,link_method) VALUES ('mfa-school','a','staff',?,1,'mfa','linked','jit')", address);
  const flow = await beginAuthorization(address), start = await requestCode(address, flow.query);
  const { code } = await mailFor(address), browser = cookie(start, "__Host-nathan-email");
  const primary = await verify(browser, code);
  assert.equal(primary.status, 200, await primary.clone().text());
  assert.deepEqual(await primary.json(), { twoFactorRedirect: true });
  assert.equal(cookie(primary, "__Secure-nathan.session_token"), "");
  assert.equal(await one('SELECT id FROM session WHERE userId=\'mfa\''), null);
  const totp = await createOTP(key).totp();
  const completions = await Promise.all([0, 1].map(() => post("/sign-in/email/verify", { totp, flowId: flows.get(browser) }, browser)));
  assert.deepEqual(completions.map(r => r.status).sort(), [200, 400]);
  const finished = completions.find(r => r.ok);
  assert.equal(finished.status, 200, await finished.clone().text());
  assert.equal(new URL((await finished.json()).url, ORIGIN).pathname, "/consent");
  const session = cookie(finished, "__Secure-nathan.session_token");
  assert.ok(session);
  assert.equal((await one("SELECT count(*) AS n FROM session WHERE userId='mfa'")).n, 1);
  assert.ok(await one('SELECT e.session_id FROM nathan_email_otp_sessions e JOIN session s ON s.id=e.session_id WHERE s.userId=\'mfa\' AND e.hosted=1'));
  assert.equal((await one("SELECT count(*) AS n FROM nathan_security_audit WHERE actor='mfa' AND action='email_otp_sign_in' AND outcome='succeeded'")).n, 1);
});

test("an invitee who proves an address held by a provisional password signup keeps no unproven password", async () => {
  const address = "provisional@example.test", inv = await invite(address);
  const signup = await post("/api/auth/sign-up/email", { name: "Provisional", email: address, password: randomKey() });
  assert.ok(signup.ok, await signup.clone().text());
  const idx = messages.filter(m => m.to.includes(address)).length;
  const issued = await requestCode(address), browser = cookie(issued, "__Host-nathan-email");
  const { code } = await mailFor(address, idx);
  assert.equal((await verify(browser, code)).status, 200);
  const user = await one('SELECT id,emailVerified FROM "user" WHERE email=?', address);
  assert.equal(user.emailVerified, 1);
  assert.deepEqual(await one('SELECT name,image FROM "user" WHERE id=?', user.id), { name: "", image: null });
  assert.equal(await one('SELECT id FROM account WHERE userId=? AND providerId=\'credential\'', user.id), null);
  assert.equal(await one("SELECT email FROM nathan_admission_pending WHERE email=?", address), null);
  assert.equal((await one("SELECT used_by_user AS id FROM nathan_invitations WHERE id=?", inv)).id, user.id);
});

test("expiry during mailbox proof leaves a provisional signup and its invitation untouched", async () => {
  const address = "expiry-race@example.test", inv = await invite(address);
  const signup = await post("/api/auth/sign-up/email", { name: "Unverified", email: address, password: randomKey() });
  assert.ok(signup.ok);
  const index = messages.filter(mail => mail.to.includes(address)).length;
  const start = await requestCode(address), browser = cookie(start, "__Host-nathan-email");
  const { code } = await mailFor(address, index);
  await sql("CREATE TRIGGER expire_during_proof AFTER DELETE ON verification BEGIN " +
    "UPDATE nathan_email_sign_ins SET expires_at=0 WHERE email='expiry-race@example.test'; END");
  try {
    assert.equal((await verify(browser, code)).status, 400);
    assert.equal((await one('SELECT emailVerified FROM "user" WHERE email=?', address)).emailVerified, 0);
    assert.equal((await one("SELECT uses FROM nathan_invitations WHERE id=?", inv)).uses, 0);
    assert.ok(await one("SELECT email FROM nathan_admission_pending WHERE email=?", address));
  } finally { await sql("DROP TRIGGER expire_during_proof"); }
});

test("a failed success audit discards the new session and its evidence", async () => {
  const email = "audit-failure@example.test";
  await invite(email);
  const start = await requestCode(email), browser = cookie(start, "__Host-nathan-email");
  const { code } = await mailFor(email);
  await sql("CREATE TRIGGER fail_email_sign_in_audit BEFORE INSERT ON nathan_security_audit " +
    "WHEN NEW.action='email_otp_sign_in' AND NEW.outcome='succeeded' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END");
  try {
    const response = await verify(browser, code);
    assert.equal(response.status, 400);
    assert.equal(cookie(response, "__Secure-nathan.session_token"), "");
    assert.equal(await one('SELECT s.id FROM session s JOIN "user" u ON s.userId=u.id WHERE u.email=?', email), null);
    assert.equal(await one('SELECT e.session_id FROM nathan_email_otp_sessions e JOIN "user" u ON u.id=e.user_id WHERE u.email=?', email), null);
  } finally { await sql("DROP TRIGGER fail_email_sign_in_audit"); }
});

test("a second tab cannot apply its code to another authorization in the same browser", async () => {
  const email = "tabs@example.test";
  await invite(email);
  const firstQuery = (await beginAuthorization(email)).query;
  const first = await requestCode(email, firstQuery), browser = cookie(first, "__Host-nathan-email");
  const firstId = (await first.json()).flowId;
  await mailFor(email);
  const nextQuery = (await beginAuthorization(email)).query;
  const next = await requestCode(email, nextQuery, undefined, browser);
  const secondId = (await next.json()).flowId;
  assert.notEqual(firstId, secondId);
  const { code } = await mailFor(email, 1);
  assert.equal((await verify(browser, code, { flowId: firstId })).status, 400);
  assert.equal((await verify(browser, code, { flowId: secondId })).status, 200);
});

test("an unverified active SCIM provisioned user keeps their subject when they prove the mailbox", async () => {
  const email = "provisioned@example.test", now = new Date().toISOString();
  await sql('INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt) VALUES (\'directory-user\',\'staff\',?,0,?,?)', email, now, now);
  await sql("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES ('school','example.test','admin')");
  await sql("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state,link_method) " +
    "VALUES ('school','u','teacher',?,1,'directory-user','linked','jit')", email);
  const start = await requestCode(email);
  assert.equal((await verify(cookie(start, "__Host-nathan-email"), (await mailFor(email)).code)).status, 200);
  assert.deepEqual(await one('SELECT id,emailVerified FROM "user" WHERE email=?', email), { id: "directory-user", emailVerified: 1 });
});
