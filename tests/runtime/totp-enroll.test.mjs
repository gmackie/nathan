/**
 * TOTP enrollment end to end through the built Worker, exactly as /security does it: enable (no
 * password; Nathan's social and passkey users have none), read the otpauth URI, compute the current
 * code from its secret like an authenticator app, verify. Staging 2026-11-22: the owner's verify left
 * twoFactorEnabled = 0, and no test covered this path.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { hashPassword, symmetricEncrypt } from "better-auth/crypto";
import { createHmac } from "node:crypto";
import { authWorker, randomKey, insertSession, cookiesOf, enrollAdmin } from "./helpers.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST, SECRET = randomKey() + randomKey();
let mf, db, member;

function base32(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "", out = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) bits += A.indexOf(c).toString(2).padStart(5, "0");
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, { period = 30, digits = 6, at = Date.now() } = {}) {
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / period)));
  const h = createHmac("sha1", base32(secret)).update(counter).digest(), o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 10 ** digits)).padStart(digits, "0");
}

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, NATHAN_INSTANCE_NAME: "gmacko" });
  db = await mf.getD1Database("DB");
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u-1\',\'u\',\'user@example.test\',1,?,?)').bind(now, now).run();
  member = await insertSession(db, SECRET, "u-1");
});
after(() => mf?.dispose());

const api = (path, body) => mf.dispatchFetch(ORIGIN + "/api/auth" + path, { method: "POST", body: JSON.stringify(body),
  headers: { Cookie: member.cookie, Origin: ORIGIN, "Content-Type": "application/json" } });

test("a passwordless signed-in user enrolls TOTP from /security's requests and verifies the current code", async () => {
  const enabled = await api("/two-factor/enable", { method: "totp" });
  const body = await enabled.json();
  assert.equal(enabled.status, 200, JSON.stringify(body));
  const uri = new URL(body.totpURI);
  assert.equal(uri.protocol, "otpauth:");
  // Authenticator apps show the issuer: the instance name, never Better Auth's default.
  assert.equal(uri.searchParams.get("issuer"), "gmacko");
  assert.match(decodeURIComponent(body.totpURI), /^otpauth:\/\/totp\/gmacko:/);
  const params = uri.searchParams;
  const code = totp(params.get("secret"), { period: Number(params.get("period") || 30), digits: Number(params.get("digits") || 6) });
  const verified = await api("/two-factor/verify-totp", { code, trustDevice: false });
  assert.equal(verified.status, 200, await verified.clone().text());
  const row = await db.prepare('SELECT "twoFactorEnabled" FROM "user" WHERE "id"=\'u-1\'').first();
  assert.equal(row.twoFactorEnabled, 1);
});

test("the installer-approved owner completes setup and registers a native PKCE client with only an authenticator app", async t => {
  const worker = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, ENABLE_PASSWORD: "true",
    NATHAN_SECURITY_PROFILE: "standard", NATHAN_ADMIN_STEPUP_METHOD: "passkey-or-totp" });
  t.after(() => worker.dispose());
  const database = await worker.getD1Database("DB");
  const email = "admin@example.test", password = randomKey();
  let deviceIP = "192.0.2.1";
  const post = (path, body, cookie = "") => worker.dispatchFetch(ORIGIN + path, {
    method: "POST", headers: { Origin: ORIGIN, Cookie: cookie, "cf-connecting-ip": deviceIP, "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  const get = (path, cookie = "") => worker.dispatchFetch(ORIGIN + path, {
    headers: { Cookie: cookie, Accept: "text/html" }, redirect: "manual"
  });
  const cookie = (r, name = "__Secure-nathan.session_token") => {
    const value = cookiesOf(r)[name]?.value;
    assert.ok(value, "expected " + name);
    return name + "=" + value;
  };
  // Start at the handoff from the installer, with the owner verified and promoted.
  const id = "setup-owner", stamp = new Date().toISOString();
  await database.prepare("INSERT INTO user(id,name,email,emailVerified,role,createdAt,updatedAt) VALUES(?,'Owner',?,1,'admin',?,?)")
    .bind(id, email, stamp, stamp).run();
  await database.prepare("INSERT INTO account(id,accountId,providerId,userId,password,createdAt,updatedAt) VALUES('acc',?,'credential',?,?,?,?)")
    .bind(id, id, await hashPassword(password), stamp, stamp).run();
  await database.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES('primary','fixture',?,?,'identity_verified')")
    .bind(email, id).run();
  assert.equal((await get("/studio")).headers.get("location"), ORIGIN + "/sign-in?setup=admin");
  const login = () => post("/api/auth/sign-in/email", { email, password });
  const initial = cookie(await login());
  assert.equal((await get("/studio", initial)).headers.get("location"), ORIGIN + "/security?setup=admin");
  const other = await insertSession(database, SECRET, id);
  const enabled = await post("/api/auth/two-factor/enable", { method: "totp", password }, initial);
  assert.equal(enabled.status, 200);
  const secret = new URL((await enabled.json()).totpURI).searchParams.get("secret");
  const verify = (code, session) => post("/api/auth/two-factor/verify-totp", { code, trustDevice: false }, session);
  assert.equal((await verify("bad", initial)).status, 401);
  assert.equal((await post("/security/api/bootstrap/complete", {}, initial)).status, 409);
  const now = Date.now();
  const currentCode = totp(secret, { at: now });
  const confirmation = await verify(currentCode, initial);
  assert.equal(confirmation.status, 200);
  const enrolled = cookie(confirmation);
  assert.equal((await post("/security/api/bootstrap/complete", {}, enrolled)).status, 200);
  assert.equal((await get("/studio", enrolled)).status, 200);
  const callback = "io.gmac.nathan.staging-check:/oauth";
  const registration = await post("/studio/api/v1/clients", { kind: "native", name: "Nathan staging check", publicClient: true, redirectUri: callback }, enrolled);
  const result = await registration.json();
  assert.equal(registration.status, 200, result.error?.message);
  assert.ok(result.data.client_id);
  assert.equal(result.data.token_endpoint_auth_method, "none");
  assert.equal(result.data.require_pkce, true);
  assert.deepEqual(result.data.redirect_uris, [callback]);

  const clients = session => get("/studio/api/v1/clients", session);
  assert.equal((await clients(initial)).status, 401, "rotated session");
  assert.equal((await clients(other.cookie)).status, 403, "different session");
  assert.equal((await verify(currentCode, other.cookie)).status, 403, "consumed code");
  assert.equal((await post("/api/auth/two-factor/get-totp-uri", { password }, other.cookie)).status, 403);
  assert.equal((await get("/api/auth/passkey/generate-register-options", other.cookie)).status, 403);
  assert.equal((await database.prepare("SELECT COUNT(*) AS n FROM nathan_admin_assurance").first()).n, 0, "no passkey evidence");

  deviceIP = "192.0.2.2"; // Returning from a second device with its own rate budget.
  const challenge = await login();
  assert.equal((await challenge.clone().json()).twoFactorRedirect, true);
  const signedIn = await verify(totp(secret, { at: now + 30000 }), cookie(challenge, "__Secure-nathan.two_factor"));
  assert.equal(signedIn.status, 200);
  const returning = cookie(signedIn);
  assert.equal((await clients(returning)).status, 200, "the password sign-in's verified app code carries into Studio");

  await database.prepare("INSERT INTO nathan_security_overrides(id,require_recent_admin_passkey,modified_by) VALUES('primary',1,?)").bind(id).run();
  assert.equal((await clients(returning)).status, 403, "strict runtime passkey override");
  await database.prepare("DELETE FROM nathan_security_overrides").run();
  await database.prepare("UPDATE nathan_admin_totp_assurance SET verified_at=unixepoch()-901").run();
  assert.equal((await clients(returning)).status, 403, "expired proof");
});

test("an already signed-in administrator can verify an existing app without rotating the session", async t => {
  const worker = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET,
    NATHAN_SECURITY_PROFILE: "standard", NATHAN_ADMIN_STEPUP_METHOD: "passkey-or-totp" });
  t.after(() => worker.dispose());
  const database = await worker.getD1Database("DB");
  await enrollAdmin(database, SECRET);
  const subject = "admin-1", secret = randomKey();
  await database.prepare("DELETE FROM passkey WHERE userId=?").bind(subject).run();
  await database.prepare("UPDATE user SET twoFactorEnabled=1 WHERE id=?").bind(subject).run();
  await database.prepare("UPDATE twoFactor SET secret=? WHERE userId=?").bind(await symmetricEncrypt({ key: SECRET, data: secret }), subject).run();
  const session = await insertSession(database, SECRET, subject);
  const clients = () => worker.dispatchFetch(ORIGIN + "/studio/api/v1/clients", { headers: { Cookie: session.cookie } });
  assert.equal((await clients()).status, 403);
  const { createOTP } = await import("@better-auth/utils/otp");
  const check = await worker.dispatchFetch(ORIGIN + "/api/auth/two-factor/verify-totp", {
    method: "POST", headers: { Cookie: session.cookie, Origin: ORIGIN, "Content-Type": "application/json" },
    body: JSON.stringify({ code: await createOTP(secret).totp(), trustDevice: false })
  });
  assert.equal(check.status, 200);
  assert.equal((await clients()).status, 200);
});
