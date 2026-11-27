import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { authWorker, cookiesOf, insertSession, randomKey } from "./helpers.mjs";
import "../fixtures/ts-modules.mjs";

const { storeManagementPasskey } = await import("../../src/auth/management-passkey.ts");
const { managementEmail } = await import("../../src/auth/env.ts");

test("the directory recognizes a legacy allowlisted administrator without a grant row", async () => {
  const secret = randomKey(), origin = "https://id.legacy.test";
  const mf = await authWorker("id.legacy.test", { BETTER_AUTH_SECRET: secret, NATHAN_BOOTSTRAP_REQUIRED: "false",
    NATHAN_ADMIN_EMAILS: "operator@example.test,peer@example.test" });
  try {
    const db = await mf.getD1Database("DB");
    for (const id of ["operator", "peer"])
      await db.prepare("INSERT INTO user(id,name,email,emailVerified,role,createdAt,updatedAt) VALUES (?1,?1,?1||'@example.test',1,'admin',0,0)").bind(id).run();
    const { cookie } = await insertSession(db, secret, "operator");
    const response = await mf.dispatchFetch(origin + "/studio/users?q=peer", { headers: { Cookie: cookie } });
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.ok(html.includes(">Administrator</td>"));
    assert.ok(!html.includes('data-operation="grant"'));
  } finally { await mf.dispose(); }
});

test("an invited owner completes setup and manages people using only an authenticator app", async () => {
  const host = "id.school.test", origin = "https://" + host;
  const email = "owner@example.test", password = randomKey();
  const issuer = "https://team.cloudflareaccess.com", audience = "b".repeat(64);
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "access", alg: "RS256" };
  const accessFor = account => new SignJWT({ email: account, type: "app" }).setProtectedHeader({ alg: "RS256", kid: jwk.kid })
    .setIssuer(issuer).setSubject(account).setAudience(audience).setExpirationTime("30m").sign(privateKey);
  const token = await accessFor(email);
  let verification;
  const mf = await authWorker(host, { NATHAN_APP_ORIGIN: "https://school.test", NATHAN_APP_ID: "school",
    NATHAN_ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com", NATHAN_ACCESS_AUD: audience,
    NATHAN_ADMIN_EMAILS: email, ENABLE_PASSWORD: "true", EMAIL_FROM: "school@example.test", RESEND_API_KEY: randomKey(),
    NATHAN_MANAGEMENT_AUTHENTICATORS: "passkey-or-totp" }, { async outboundService(request) {
    if (request.url === issuer + "/cdn-cgi/access/certs") return Response.json({ keys: [jwk] });
    assert.equal(request.url, "https://api.resend.com/emails");
    verification = (await request.json()).text.match(/https:\/\/[^\s]+/)[0];
    return Response.json({ id: "sent" });
  } });
  const ownerJar = new Map();
  async function visit(path, body, assertion = token, jar = ownerJar, ip = assertion===token ? "192.0.2.10" : "192.0.2.11") {
    const headers = { "Cf-Access-Jwt-Assertion": assertion, "CF-Connecting-IP": ip,
      Cookie: [...jar].map(([key,v]) => key + "=" + v).join("; ") };
    const form = body instanceof URLSearchParams;
    const response = await mf.dispatchFetch(new URL(path, origin).href, { redirect: "manual", headers: {
      ...headers, ...(body ? { Origin: origin, "Content-Type": form ? "application/x-www-form-urlencoded" : "application/json" } : {})
    }, method: body ? "POST" : "GET", body: body ? form ? body.toString() : JSON.stringify(body) : undefined });
    for (const [name, c] of Object.entries(cookiesOf(response))) {
      if (c.value) jar.set(name, c.value); else jar.delete(name);
    }
    return response;
  }
  try {
    const db = await mf.getD1Database("DB");
    const nextRequestWindow = () => db.prepare('UPDATE "rateLimit" SET lastRequest=lastRequest-60000').run();
    await db.prepare("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES ('primary','cli:install',?,'pending')").bind(email).run();
    await db.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES ('initial',?,'cli:install',unixepoch()+3600)").bind(email).run();
    await db.prepare("UPDATE nathan_bootstrap_status SET owner_invitation_id='initial' WHERE id='primary'").run();
    const setup = "/security/setup-owner";
    assert.equal((await visit("/studio/users")).headers.get("Location"), origin + setup);
    assert.equal((await visit(setup, new URLSearchParams({ password }))).status, 303);
    assert.equal((await visit(verification)).status, 302);
    const claimForm = () => new URLSearchParams({ action: "claim" });
    assert.equal((await visit(setup, claimForm())).status, 403);
    assert.equal((await visit("/api/auth/sign-in/email", { email, password })).status, 200);
    await db.prepare("UPDATE nathan_invitations SET created_by='different-installer' WHERE id='initial'").run();
    assert.equal((await visit(setup, claimForm())).status, 403);
    await db.prepare("UPDATE nathan_invitations SET created_by='cli:install' WHERE id='initial'").run();
    await db.prepare("UPDATE nathan_bootstrap_status SET owner_invitation_id=NULL WHERE id='primary'").run();
    assert.equal((await visit(setup, claimForm())).status, 403);
    await db.prepare("UPDATE nathan_bootstrap_status SET owner_invitation_id='initial' WHERE id='primary'").run();
    assert.match(await (await visit(setup)).text(), /Continue to account security/);
    const claim = await visit(setup, claimForm());
    assert.equal(claim.headers.get("Location"), origin + "/security?setup=admin");
    assert.equal((await visit(setup, claimForm())).headers.get("Location"), origin + "/security?setup=admin");
    assert.equal(await db.prepare("SELECT state FROM nathan_bootstrap_status").first("state"), "identity_verified");
    assert.equal(await db.prepare("SELECT COUNT(*) AS n FROM nathan_security_audit WHERE action='admin_bootstrap' AND outcome='succeeded'").first("n"), 1);
    assert.equal((await visit("/studio/api/users")).status, 403);
    const start = await visit("/api/auth/two-factor/enable", { password, method: "totp" });
    assert.equal(start.status, 200);
    const key = base32.decode(new URL((await start.json()).totpURI).searchParams.get("secret"));
    const code = offset => createOTP(key).hotp(Math.floor(Date.now()/30000) + offset);
    const verify = value => visit("/api/auth/two-factor/verify-totp", { code: value, trustDevice: false });
    const firstCode = await code(0);
    assert.equal((await verify(firstCode)).status, 200);
    assert.equal((await visit("/security/api/bootstrap/complete", {})).status, 200);
    assert.equal((await visit("/")).headers.get("Location"), origin + "/studio/users");
    assert.equal((await visit("/studio/api/users")).status, 200);
    assert.equal(await db.prepare("SELECT COUNT(*) AS n FROM passkey").first("n"), 0);
    assert.equal(await db.prepare("SELECT COUNT(*) AS n FROM nathan_admin_assurance").first("n"), 0);
    // Model the same elapsed time for the short-lived provider request window and Studio evidence.
    await db.batch([db.prepare("UPDATE nathan_management_totp SET verified_at=unixepoch()-901"),
      db.prepare('UPDATE "rateLimit" SET lastRequest=lastRequest-901000')]);
    assert.equal((await visit("/studio/api/users")).status, 403);
    assert.ok((await verify(firstCode)).status >= 400);
    assert.equal((await visit("/studio/api/users")).status, 403);
    const stepUpCode = await code(1);
    assert.equal((await verify(stepUpCode)).status, 200);
    assert.equal((await visit("/studio/api/users")).status, 200);
    await visit("/api/auth/sign-out", {});
    assert.equal((await visit("/studio/api/users")).status, 403);
    await nextRequestWindow();
    const login = await visit("/api/auth/sign-in/email", { email, password });
    assert.equal((await login.json()).twoFactorRedirect, true);
    assert.equal((await visit("/studio/api/users")).status, 403);
    // A second browser can submit a code from the same authenticator time step.
    const replay = await verify(stepUpCode);
    assert.equal(replay.status, 401);
    assert.equal((await replay.json()).code, "MANAGEMENT_SIGN_IN_RESTART");
    assert.equal((await visit("/studio/api/users")).status, 403);
    assert.equal((await (await visit("/api/auth/sign-in/email", { email, password })).json()).twoFactorRedirect, true);
    // Model the previous sign-in falling outside the authenticator's window.
    await db.prepare("UPDATE nathan_management_totp_steps SET step=step-30").run();
    const loginCode = await code(0);
    await db.prepare("UPDATE verification SET expiresAt=? WHERE identifier LIKE '2fa-%'").bind(new Date(0).toISOString()).run();
    assert.ok((await verify(loginCode)).status >= 400);
    assert.equal((await (await visit("/api/auth/sign-in/email", { email, password })).json()).twoFactorRedirect, true);
    assert.equal((await verify(loginCode)).status, 200, "a fresh password challenge can still use the code");
    const directory = await visit("/studio/users?q=owner");
    assert.equal(directory.status, 200);
    assert.match(await directory.text(), /Create invitation/);
    const now = new Date().toISOString();
    await db.prepare('INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES (?,?,?,1,?,?)')
      .bind("staff", "Design Staff", "staff@example.test", now, now).run();
    const users = await visit("/studio/api/users?q=design");
    assert.deepEqual((await users.json()).users.map(u => u.email), ["staff@example.test"]);
    const selected = { id: "staff", email: "staff@example.test", confirm: "CONFIRM GRANT ADMIN staff@example.test" };
    const row = await (await visit("/studio/users?q=design")).text();
    assert.match(row, /data-operation="grant"/);
    assert.equal((await visit("/studio/api/admins/grant", { ...selected, id: "previous-account" })).status, 409);
    const grant = await visit("/studio/api/admins/grant", selected);
    assert.equal(grant.status, 200);
    assert.match(await (await visit("/studio/users?q=design")).text(), /data-operation="revoke-admin"/);
    const staffAccess = await accessFor(selected.email), staffJar = new Map();
    const asStaff = (path, body) => visit(path, body, staffAccess, staffJar);
    const setupPassword = "/security/management-password";
    assert.equal((await asStaff("/studio/users")).headers.get("Location"), origin + "/sign-in");
    assert.equal((await asStaff(setupPassword)).status, 200);
    assert.equal((await asStaff(setupPassword, new URLSearchParams({ action: "request" }))).status, 200);
    const passwordLink = new URL(verification);
    assert.equal(passwordLink.origin + passwordLink.pathname, origin + setupPassword);
    const setPassword = new URLSearchParams({ action: "save", proof: passwordLink.hash.slice(1), password });
    assert.equal((await visit(setupPassword, setPassword)).status, 404, "the owner uses the owner setup route");
    const otherEmail = "second-admin@example.test";
    await db.prepare("INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt,role) VALUES (?,?,?,1,?,?,'admin')")
      .bind("second-admin", "Second administrator", otherEmail, now, now).run();
    assert.match(await (await visit("/studio/users?q=second-admin")).text(), /data-operation="grant"/);
    assert.equal((await visit("/studio/api/admins/grant", {
      id: "second-admin", email: otherEmail, confirm: "CONFIRM GRANT ADMIN " + otherEmail
    })).status, 200);
    const foreign = await visit(setupPassword, setPassword, await accessFor(otherEmail), new Map());
    assert.equal(foreign.status, 400, "a different eligible administrator cannot use the link");
    const resetTokenCount = () => db.prepare("SELECT count(*) AS n FROM verification WHERE value='staff' AND identifier GLOB 'reset-password:*'").first("n");
    const credentialCount = () => db.prepare("SELECT count(*) AS n FROM account WHERE userId='staff' AND providerId='credential'").first("n");
    assert.equal(await resetTokenCount(), 1);
    await db.prepare("CREATE TRIGGER fixture_password_audit_failure BEFORE INSERT ON nathan_security_audit WHEN NEW.action='management_password_set' BEGIN SELECT RAISE(ABORT,'fixture unavailable'); END").run();
    assert.equal((await asStaff(setupPassword, setPassword)).status, 500);
    assert.equal(await credentialCount(), 0);
    assert.equal(await resetTokenCount(), 1);
    await db.prepare("DROP TRIGGER fixture_password_audit_failure").run();
    assert.equal((await asStaff(setupPassword, setPassword)).status, 303);
    assert.equal((await asStaff(setupPassword, setPassword)).status, 400, "the link was consumed");
    assert.equal((await asStaff("/api/auth/sign-in/email", { email: selected.email, password })).status, 200);
    assert.equal((await asStaff("/studio/api/users")).status, 403);
    const staffFactor = await asStaff("/api/auth/two-factor/enable", { password, method:"totp" });
    assert.equal(staffFactor.status, 200);
    const staffKey = base32.decode(new URL((await staffFactor.json()).totpURI).searchParams.get("secret"));
    // An existing passkey must be proved even if the TOTP enrollment form was opened first.
    await db.prepare("INSERT INTO passkey(id,publicKey,userId,credentialID,counter,deviceType,backedUp) VALUES ('staff-key','test','staff','staff-credential',0,'singleDevice',0)").run();
    assert.equal((await asStaff("/api/auth/two-factor/verify-totp", {code: await createOTP(staffKey).totp()})).status, 403);
    assert.equal(await db.prepare("SELECT verified FROM twoFactor WHERE userId='staff'").first("verified"), 0);
    await db.prepare("DELETE FROM passkey WHERE id='staff-key'").run();
    await nextRequestWindow();
    await db.prepare("CREATE TRIGGER fixture_storage_failure BEFORE UPDATE OF verified ON twoFactor WHEN NEW.userId='staff' BEGIN SELECT RAISE(ABORT,'fixture unavailable'); END").run();
    const staffCode = await createOTP(staffKey).totp();
    assert.equal((await asStaff("/api/auth/two-factor/verify-totp", {code: staffCode})).status, 500);
    assert.equal(await db.prepare("SELECT COALESCE(twoFactorEnabled,0) AS enabled FROM user WHERE id='staff'").first("enabled"), 0);
    assert.equal(await db.prepare("SELECT verified FROM twoFactor WHERE userId='staff'").first("verified"), 0);
    await db.prepare("DROP TRIGGER fixture_storage_failure").run();
    // A pre-migration, unfinished setup keeps the original key in the authenticator.
    await db.prepare("UPDATE twoFactor SET verified=NULL WHERE userId='staff'").run();
    const otherBrowser = new Map();
    assert.equal((await visit("/api/auth/sign-in/email", { email: selected.email, password }, staffAccess, otherBrowser)).status, 200);
    const options = await visit("/api/auth/passkey/generate-register-options", undefined, staffAccess, otherBrowser);
    assert.equal(options.status, 200);
    const otherSession = await (await visit("/api/auth/get-session", undefined, staffAccess, otherBrowser)).json();
    const legacySetup = await (await asStaff("/security/api/bootstrap")).json();
    assert.equal(legacySetup.pendingLegacyTotp, true);
    assert.equal(legacySetup.requiresFactorRecovery, false);
    assert.equal((await asStaff("/api/auth/two-factor/verify-totp", { code: await createOTP(staffKey).totp(), trustDevice:false })).status, 200);
    assert.equal(await db.prepare("SELECT verified FROM twoFactor WHERE userId='staff'").first("verified"), 1);
    // Simulate a provider that verified the registration before the activation committed.
    // The final storage step must see the newly established factor and refuse the other session.
    await assert.rejects(storeManagementPasskey({ DB: db, [managementEmail]: selected.email }, otherSession.session.id,
      { userId: "staff", publicKey: "fixture", credentialID: "fixture", deviceType: "singleDevice", backedUp: false,
        counter: 0, createdAt: new Date() }), /Verify an enrolled sign-in method/);
    assert.equal(await db.prepare("SELECT COUNT(*) AS n FROM passkey WHERE userId='staff'").first("n"), 0);
    assert.equal((await asStaff("/studio/users")).status, 200);
    // Model a later visit. With the enrollment step outside the window, the
    // two challenges can use next then current, both valid across a tick.
    await db.prepare("UPDATE nathan_management_totp_steps SET step=step-30 WHERE factor_id IN (SELECT id FROM twoFactor WHERE userId='staff')").run();
    await nextRequestWindow();
    const jars = [new Map(), new Map()];
    for (const jar of jars) {
      const challenge = await visit("/api/auth/sign-in/email", { email: selected.email, password }, staffAccess, jar);
      assert.equal((await challenge.json()).twoFactorRedirect, true);
    }
    const nowStep = Math.floor(Date.now()/30000);
    const available = [nowStep+1, nowStep];
    for (const [i, jar] of jars.entries()) {
      const response = await visit("/api/auth/two-factor/verify-totp", {code: await createOTP(staffKey).hotp(available[i])}, staffAccess, jar);
      assert.equal(response.status, 200, "each challenge records its own code");
      assert.equal((await visit("/studio/users", undefined, staffAccess, jar)).status, 200);
    }
    assert.equal((await asStaff(setupPassword, new URLSearchParams({action: "request"}))).status, 200);
    const beforeRevocation = new URLSearchParams({action: "save", proof: new URL(verification).hash.slice(1), password});
    assert.equal((await visit("/studio/api/admins/revoke", { id: "staff", confirm: "CONFIRM REVOKE ADMIN staff" })).status, 200);
    assert.equal((await asStaff("/studio/users")).status, 403);
    assert.equal((await visit("/studio/api/admins/grant", selected)).status, 200);
    assert.equal((await asStaff(setupPassword, beforeRevocation)).status, 400);
    assert.equal((await visit("/studio/api/admission", { op: "invite", email: "invitee@example.test" })).status, 200);
    const inviteId = await db.prepare("SELECT id FROM nathan_invitations WHERE email='invitee@example.test'").first("id");
    assert.match(await (await visit("/studio/users?q=invitee")).text(), /data-operation="revoke-invite"/);
    assert.equal((await visit("/studio/api/admission", { op: "revoke", id: inviteId, confirm: "CONFIRM REVOKE INVITATION " + inviteId })).status, 200);
    await db.prepare("INSERT INTO nathan_security_overrides(id,require_recent_admin_passkey,modified_by) VALUES ('primary',1,'owner')").run();
    assert.equal((await visit("/studio/api/users")).status, 403);
    // Provider limits are per IP. This seed represents five attempts for the account in this minute.
    const limitKey = "management-totp:" + createHash("sha256").update(
      await db.prepare("SELECT admin_user_id FROM nathan_bootstrap_status").first("admin_user_id")
    ).digest("base64url").slice(0,22);
    const minute = Math.floor(Date.now()/60000);
    for (const bucket of [minute, minute + 1]) {
      await db.prepare("INSERT INTO nathan_mcp_limits(id,request_count,expires_at) VALUES (?,5,?) ON CONFLICT(id) DO UPDATE SET request_count=5")
        .bind(limitKey + ":" + bucket, (bucket+2)*60).run();
    }
    assert.equal((await visit("/api/auth/two-factor/verify-totp", { code: "invalid" }, token, ownerJar, "198.51.100.1")).status, 429);
    assert.equal((await visit("/api/auth/sign-out", {})).status, 200);
    const freshLogin = await visit("/sign-in?setup=passkey");
    assert.ok((await freshLogin.text()).includes("data-passkey-setup"));
  } finally { await mf.dispose(); }
});
