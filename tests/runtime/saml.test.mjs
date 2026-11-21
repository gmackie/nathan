/**
 * NATH-10 Step 0 and end-to-end: inbound SAML inside workerd. A Node-side test
 * IdP signs Responses with xml-crypto; the built auth Worker (samlify, xmldom,
 * xml-crypto via @better-auth/sso) validates them at the ACS endpoint.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, cookiesOf, randomKey } from "./helpers.mjs";
import { makeCertificate } from "../fixtures/x509.mjs";
import { idpMetadata, authnRequestId, samlResponse } from "../fixtures/saml-idp.mjs";

const HOST = "login.example.test";
const ORIGIN = "https://" + HOST;
const IDP = "https://idp.acme.example/saml";
const PID = "acme-saml";
const DOMAIN = "acme.example";
const ACS = ORIGIN + "/api/auth/sso/saml2/sp/acs/" + PID;
const SP_ENTITY = ORIGIN + "/api/auth/sso/saml2/sp/metadata?providerId=" + PID;
const SECRET = randomKey() + randomKey();
let mf, db, idp, admin;
after(() => mf?.dispose());

/** A complete, recently stepped-up administrator session, seeded directly in D1. */
async function seedAdmin() {
  const now = new Date().toISOString(), later = new Date(Date.now() + 3600e3).toISOString();
  const token = "tok_" + randomKey();
  const stmts = [
    ['INSERT INTO "user"(id,name,email,emailVerified,role,createdAt,updatedAt) VALUES(?,?,?,1,?,?,?)', ["admin1", "Admin", "admin@example.test", "admin", now, now]],
    ["INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES('primary','cf','admin@example.test','admin1','complete')", []],
    ['INSERT INTO "passkey"(id,publicKey,userId,credentialID,counter,deviceType,backedUp) VALUES(?,?,?,?,0,?,0)', ["pk1", "x", "admin1", "cred", "singleDevice"]],
    ['INSERT INTO "twoFactor"(id,secret,backupCodes,userId,verified) VALUES(?,?,?,?,1)', ["tf1", "x", "x", "admin1"]],
    ['INSERT INTO "session"(id,expiresAt,token,createdAt,updatedAt,userId) VALUES(?,?,?,?,?,?)', ["s1", later, token, now, now, "admin1"]],
    ["INSERT INTO nathan_admin_assurance(session_id,user_id,method,verified_at) VALUES('s1','admin1','passkey',unixepoch())", []]
  ];
  for (const [sql, args] of stmts) await db.prepare(sql).bind(...args).run();
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token))).toString("base64");
  return "__Secure-nathan.session_token=" + encodeURIComponent(token + "." + sig);
}
function studio(path, body, cookie = admin) {
  return mf.dispatchFetch(ORIGIN + path, body === undefined ? { headers: { Cookie: cookie } } : {
    method: "POST", headers: { Cookie: cookie, Origin: ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
}
async function ok(response) {
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  return body;
}

// Better Auth rate-limits /sign-in/* per client IP; give each simulated browser its own.
let client = 0;
const ip = () => "198.51.100." + (++client % 250);
async function startLogin(email = "jane@" + DOMAIN) {
  const response = await mf.dispatchFetch(ORIGIN + "/sign-in/sso/start", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "cf-connecting-ip": ip() },
    body: JSON.stringify({ email })
  });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  const url = new URL(body.url);
  assert.equal(url.origin + url.pathname, "https://idp.acme.example/sso", "routes to the IdP's HTTP-Redirect SSO URL");
  return { id: authnRequestId(body.url), relayState: url.searchParams.get("RelayState") };
}
function post(SAMLResponse, RelayState) {
  return mf.dispatchFetch(ACS, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://idp.acme.example" },
    body: new URLSearchParams({ SAMLResponse, ...(RelayState ? { RelayState } : {}) })
  });
}
const sessionCookie = r => cookiesOf(r)["__Secure-nathan.session_token"]?.value;
const good = (over = {}) => ({ issuer: IDP, audience: SP_ENTITY, acs: ACS, email: "jane@" + DOMAIN,
  privateKey: idp.privateKey, certB64: idp.certB64, ...over });
async function login(over = {}) {
  const { id, relayState } = await startLogin(over.email);
  return post(samlResponse(good({ inResponseTo: id, ...over })), relayState);
}
async function assertRejected(r, label) {
  const text = await r.clone().text();
  assert.equal(sessionCookie(r), undefined, label + ": must not create a session");
  const location = r.headers.get("location") || "";
  assert.ok(r.status >= 400 || /[?&]error=/.test(location),
    label + ": expected rejection, got " + r.status + " " + location + " " + text.slice(0, 200));
}
const auditCount = async (action, outcome) =>
  (await db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action=? AND outcome=?").bind(action, outcome).first()).n;

before(async () => {
  mf = await authWorker(HOST, { ENTERPRISE_SSO: "true", BETTER_AUTH_SECRET: SECRET });
  db = await mf.getD1Database("DB");
  idp = makeCertificate({ cn: "acme idp" });
  admin = await seedAdmin();
});

test("raw Better Auth SSO management stays blocked", async () => {
  for (const path of ["/api/auth/sso/register", "/api/auth/sso/update-provider", "/api/auth/sso/delete-provider"]) {
    const r = await mf.dispatchFetch(ORIGIN + path, { method: "POST", headers: { Cookie: admin, Origin: ORIGIN, "Content-Type": "application/json" }, body: "{}" });
    assert.equal(r.status, 404, path);
  }
});

test("Studio SAML API requires a stepped-up administrator", async () => {
  assert.equal((await studio("/studio/api/saml", undefined, "")).status, 403);
  const r = await mf.dispatchFetch(ORIGIN + "/studio/api/saml/connections", {
    method: "POST", headers: { Cookie: admin, Origin: "https://evil.example", "Content-Type": "application/json" }, body: "{}" });
  assert.equal(r.status, 403, "cross-origin write denied");
});

test("metadata preview reports problems without saving", async () => {
  const weak = makeCertificate({ bits: 1024 });
  const bad = await studio("/studio/api/saml/preview", { metadataXml: idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [weak.certB64] }) });
  assert.equal(bad.status, 409);
  assert.match((await bad.json()).error, /2048/);
  const good = await ok(await studio("/studio/api/saml/preview", { providerId: PID, metadataXml: idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [idp.certB64] }) }));
  assert.equal(good.idp.entityID, IDP);
  assert.equal(good.sp.acsUrl, ACS);
  assert.equal((await ok(await studio("/studio/api/saml"))).connections.length, 0);
});

test("creating a connection through Studio registers it disabled with Nathan's SP values", async () => {
  const created = await ok(await studio("/studio/api/saml/connections", {
    providerId: PID, domain: DOMAIN, provisioning: "just-in-time",
    metadataXml: idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [idp.certB64] })
  }));
  assert.equal(created.enabled, false);
  assert.equal(created.domainVerified, false);
  assert.deepEqual(created.sp, { entityId: SP_ENTITY, acsUrl: ACS, metadataUrl: SP_ENTITY });
  assert.equal(created.verification.txtHost, "_better-auth-token-" + PID + "." + DOMAIN);
  assert.ok(created.verification.txtValue, "TXT challenge value is returned once");
  assert.equal(await auditCount("saml_connection_create", "succeeded"), 1);
  const listed = await ok(await studio("/studio/api/saml"));
  assert.equal(listed.connections.length, 1);
  assert.ok(listed.connections[0].warnings.some(w => /Domain not verified/.test(w)));
  const duplicate = await studio("/studio/api/saml/connections", { providerId: PID, domain: DOMAIN,
    metadataXml: idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [idp.certB64] }) });
  assert.equal(duplicate.status, 409, "connection IDs are unique");
  const md = await mf.dispatchFetch(SP_ENTITY);
  assert.equal(md.status, 200);
  const xml = await md.text();
  assert.ok(xml.includes('entityID="' + SP_ENTITY.replace("&", "&amp;") + '"'), xml);
  assert.ok(xml.includes(ACS), "SP metadata advertises the ACS URL");
  assert.match(xml, /WantAssertionsSigned="true"/);
});

test("a disabled or unverified connection cannot be used", async () => {
  const start = await mf.dispatchFetch(ORIGIN + "/sign-in/sso/start", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ email: "jane@" + DOMAIN }) });
  assert.equal(start.status, 404);
  const raw = await mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/sso", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ providerId: PID, callbackURL: "/" }) });
  assert.equal(raw.status, 404, "raw sign-in cannot bypass the disabled state");
  const byEmail = await mf.dispatchFetch(ORIGIN + "/api/auth/sign-in/sso", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ email: "jane@" + DOMAIN, callbackURL: "/" }) });
  assert.equal(byEmail.status, 400, "raw sign-in must name a connection");
  assert.equal((await post(samlResponse(good({})))).status, 404, "ACS is closed while disabled");
  const enable = await studio("/studio/api/saml/status", { providerId: PID, enabled: true, confirm: "CONFIRM ENABLE SAML " + PID });
  assert.equal(enable.status, 409);
  assert.match((await enable.json()).error, /Verify the connection's domain/);
  assert.equal((await studio("/studio/api/saml/status", { providerId: PID, enabled: true, confirm: "yes" })).status, 409, "exact confirmation");
  assert.equal(await auditCount("saml_connection_enable", "failed"), 1, "refused enablement is audited");
});

test("enabling after domain verification opens SSO for the domain", async () => {
  // Better Auth's DNS TXT verification (existing Studio flow) sets this flag; DNS itself is not exercised here.
  await db.prepare('UPDATE "ssoProvider" SET "domainVerified"=1 WHERE "providerId"=?').bind(PID).run();
  const enabled = await ok(await studio("/studio/api/saml/status", { providerId: PID, enabled: true, confirm: "CONFIRM ENABLE SAML " + PID }));
  assert.equal(enabled.enabled, true);
  assert.equal(await auditCount("saml_connection_enable", "succeeded"), 1);
});

test("SP-initiated SAML login creates a session in workerd", async () => {
  const r = await login();
  assert.equal(r.status, 302, await r.clone().text());
  assert.ok(sessionCookie(r), "session cookie expected; location=" + r.headers.get("location"));
  const user = await db.prepare('SELECT "emailVerified" AS v FROM "user" WHERE email=?').bind("jane@" + DOMAIN).first();
  assert.equal(user.v, 1, "just-in-time users inside the verified domain have a verified email");
  const account = await db.prepare('SELECT "providerId" AS p FROM "account" WHERE "providerId"=?').bind(PID).first();
  assert.ok(account, "SAML account linked to the connection");
});

test("tampered signed response is rejected", async () => {
  await assertRejected(await login({ mutate: x => x.split("jane@acme.example").join("mallory@acme.example") }), "tampered");
});
test("unsigned response is rejected", async () => {
  await assertRejected(await login({ sign: false }), "unsigned");
});
test("response signed by a key not in the IdP metadata is rejected", async () => {
  const other = makeCertificate({ cn: "attacker" });
  await assertRejected(await login({ privateKey: other.privateKey, certB64: other.certB64 }), "foreign key");
});
test("response from a different issuer is rejected", async () => {
  await assertRejected(await login({ issuer: "https://evil.example/saml" }), "issuer");
});
test("expired assertion is rejected", async () => {
  const past = Date.now() - 60 * 60e3;
  await assertRejected(await login({ notBefore: past - 60e3, notOnOrAfter: past }), "expired");
});
test("assertion 3 minutes past NotOnOrAfter is outside the 2 minute skew", async () => {
  const t = Date.now() - 3 * 60e3;
  await assertRejected(await login({ notBefore: t - 60e3, notOnOrAfter: t }), "skew");
});
test("not-yet-valid assertion is rejected", async () => {
  const t = Date.now() + 10 * 60e3;
  await assertRejected(await login({ notBefore: t, notOnOrAfter: t + 5 * 60e3 }), "future");
});
test("wrong audience is rejected", async () => {
  await assertRejected(await login({ audience: "https://other-sp.example/saml" }), "audience");
});
test("replayed InResponseTo is rejected", async () => {
  const { id, relayState } = await startLogin();
  assert.ok(sessionCookie(await post(samlResponse(good({ inResponseTo: id })), relayState)), "first use must succeed");
  await assertRejected(await post(samlResponse(good({ inResponseTo: id })), relayState), "replayed InResponseTo");
});
test("replayed assertion is rejected", async () => {
  const { id, relayState } = await startLogin();
  const b64 = samlResponse(good({ inResponseTo: id }));
  assert.ok(sessionCookie(await post(b64, relayState)), "first use must succeed");
  await assertRejected(await post(b64, relayState), "replayed assertion");
});
test("IdP-initiated response (no InResponseTo) is rejected", async () => {
  await assertRejected(await post(samlResponse(good({}))), "IdP-initiated");
});
test("unknown InResponseTo is rejected", async () => {
  await assertRejected(await post(samlResponse(good({ inResponseTo: "_never_issued" }))), "unknown request");
});
test("SHA-1 signed response is rejected", async () => {
  await assertRejected(await login({ signatureAlgorithm: "rsa-sha1" }), "sha1");
});
test("an IdP cannot create users outside its verified domain", async () => {
  const { id, relayState } = await startLogin();
  await assertRejected(await post(samlResponse(good({ inResponseTo: id, email: "ceo@other.example" })), relayState), "foreign domain");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind("ceo@other.example").first(), null);
});

test("invitation-only provisioning admits existing users but creates nobody", async () => {
  await ok(await studio("/studio/api/saml/provisioning", { providerId: PID, provisioning: "invitation-only",
    confirm: "CONFIRM PROVISIONING invitation-only " + PID }));
  await assertRejected(await login({ email: "newhire@" + DOMAIN }), "new user under invitation-only");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind("newhire@" + DOMAIN).first(), null);
  assert.ok(sessionCookie(await login()), "existing linked user still signs in");
});

test("certificate rotation: trust the next certificate, then retire the old one", async () => {
  const next = makeCertificate({ cn: "acme idp 2027" });
  const weak = makeCertificate({ hash: "sha1" });
  const rejected = await studio("/studio/api/saml/certificates", { providerId: PID, certificate: weak.certPem });
  assert.equal(rejected.status, 409);
  assert.match((await rejected.json()).error, /SHA-1/);
  const added = await ok(await studio("/studio/api/saml/certificates", { providerId: PID, certificate: next.certPem }));
  assert.deepEqual(added.certificates.map(c => c.role), ["active", "next"]);
  assert.ok(sessionCookie(await login()), "old certificate still trusted during rotation");
  assert.ok(sessionCookie(await login({ privateKey: next.privateKey, certB64: next.certB64 })), "next certificate trusted");
  const old = added.certificates[0].sha256;
  const noConfirm = await studio("/studio/api/saml/certificates/retire", { providerId: PID, sha256: old, confirm: "yes" });
  assert.equal(noConfirm.status, 409);
  const retired = await ok(await studio("/studio/api/saml/certificates/retire", { providerId: PID, sha256: old, confirm: "CONFIRM RETIRE CERTIFICATE " + PID }));
  assert.deepEqual(retired.certificates.map(c => c.role), ["active"]);
  await assertRejected(await login(), "retired certificate");
  assert.ok(sessionCookie(await login({ privateKey: next.privateKey, certB64: next.certB64 })), "new certificate works");
  const last = await studio("/studio/api/saml/certificates/retire", { providerId: PID, sha256: retired.certificates[0].sha256, confirm: "CONFIRM RETIRE CERTIFICATE " + PID });
  assert.equal(last.status, 409, "cannot retire the only certificate");
  assert.equal(await auditCount("saml_certificate_add", "succeeded"), 1);
  assert.equal(await auditCount("saml_certificate_retire", "succeeded"), 1);
  idp = next;
});

test("disabling closes the ACS and SSO routing again", async () => {
  await ok(await studio("/studio/api/saml/status", { providerId: PID, enabled: false, confirm: "CONFIRM DISABLE SAML " + PID }));
  assert.equal((await post(samlResponse(good({ inResponseTo: "_x" })))).status, 404);
  const start = await mf.dispatchFetch(ORIGIN + "/sign-in/sso/start", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: JSON.stringify({ email: "jane@" + DOMAIN }) });
  assert.equal(start.status, 404);
  assert.equal(await auditCount("saml_connection_disable", "succeeded"), 1);
});

test("Studio and sign-in pages carry the SAML UI with valid inline scripts", async () => {
  const scriptOf = html => /<script nonce="[^"]+">([\s\S]*)<\/script>/.exec(html)[1];
  const studioPage = await studio("/studio");
  assert.equal(studioPage.status, 200);
  const html = await studioPage.text();
  for (const id of ["saml-create", "saml-enable", "saml-add-cert", "saml-retire-cert", "saml-sp-acs"])
    assert.ok(html.includes('id="' + id + '"'), id);
  assert.doesNotThrow(() => new Function(scriptOf(html)), "Studio script parses");
  const signIn = await (await mf.dispatchFetch(ORIGIN + "/sign-in")).text();
  assert.ok(signIn.includes("Sign in with SSO"));
  assert.ok(signIn.includes("/sign-in/sso/start"));
  assert.doesNotThrow(() => new Function(scriptOf(signIn)), "sign-in script parses");
});
