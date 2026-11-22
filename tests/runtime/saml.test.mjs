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

/**
 * Outbound HTTP from the Worker. workerd's node:dns (used by Better Auth's
 * domain verification) resolves TXT records over DNS-over-HTTPS at
 * cloudflare-dns.com, so the DNS check is mocked at that real boundary.
 */
const dnsTxt = new Map();
const dnsQueries = [];
const METADATA_URL = "https://idp.acme.example/app/metadata";
async function outbound(request) {
  const url = new URL(request.url);
  if (url.hostname === "cloudflare-dns.com" && url.pathname === "/dns-query") {
    const name = url.searchParams.get("name");
    dnsQueries.push(name + " " + url.searchParams.get("type"));
    const records = url.searchParams.get("type") === "TXT" ? dnsTxt.get(name) : undefined;
    return Response.json({ Status: records ? 0 : 3, TC: false, RD: true, RA: true, AD: false, CD: false,
      Question: [{ name, type: 16 }],
      ...(records ? { Answer: records.map(data => ({ name, type: 16, TTL: 60, data: JSON.stringify(data) })) } : {}) },
    { headers: { "content-type": "application/dns-json" } });
  }
  if (url.href === METADATA_URL)
    return new Response(idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [idp.certB64] }),
      { headers: { "content-type": "application/samlmetadata+xml" } });
  return new Response("unexpected outbound request", { status: 599 });
}

async function signed(token) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token))).toString("base64");
  return "__Secure-nathan.session_token=" + encodeURIComponent(token + "." + sig);
}
/** A signed-in session for an existing user, seeded directly in D1; `stepUpAge` seconds since a passkey step-up, or none. */
async function seedSession(userId, { stepUpAge } = {}) {
  const now = new Date().toISOString(), later = new Date(Date.now() + 3600e3).toISOString();
  const id = "s_" + randomKey().slice(0, 12), token = "tok_" + randomKey();
  await db.prepare('INSERT INTO "session"(id,expiresAt,token,createdAt,updatedAt,userId) VALUES(?,?,?,?,?,?)').bind(id, later, token, now, now, userId).run();
  if (stepUpAge !== undefined)
    await db.prepare("INSERT INTO nathan_admin_assurance(session_id,user_id,method,verified_at) VALUES(?,?,'passkey',unixepoch()-?)").bind(id, userId, stepUpAge).run();
  return signed(token);
}
async function seedUser(id, email, { role = "user", emailVerified = 1 } = {}) {
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"(id,name,email,emailVerified,role,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?)')
    .bind(id, id, email, emailVerified, role, now, now).run();
}

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
  return signed(token);
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
  return postForm([["SAMLResponse", SAMLResponse], ...(RelayState ? [["RelayState", RelayState]] : [])]);
}
/** Posts form fields in the given order, repeated names included. */
function postForm(fields, url = ACS) {
  return mf.dispatchFetch(url, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://idp.acme.example" },
    body: new URLSearchParams(fields).toString()
  });
}
/** Asserts that Nathan's SAML protocol gate, not the plugin, refused the message. */
async function assertGateRejected(r, code, label) {
  assert.equal(sessionCookie(r), undefined, label + ": must not create a session");
  assert.equal(r.status, 400, label + ": " + (await r.clone().text()).slice(0, 200));
  assert.equal((await r.json()).code, code, label);
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
  mf = await authWorker(HOST, { ENTERPRISE_SSO: "true", BETTER_AUTH_SECRET: SECRET }, { outboundService: outbound });
  db = await mf.getD1Database("DB");
  // NATH-16: these tests cover SAML provisioning itself, so the installation admits self-service
  // sign-ups; invitation-only admission of SAML just-in-time users is tested at the end.
  await db.prepare("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary','self-service','test')").run();
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
  const metadataXml = idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [idp.certB64] });
  const create = { providerId: "stepup-test", domain: "stepup.example", metadataXml };
  await seedUser("member1", "member@example.test");
  const member = await seedSession("member1", { stepUpAge: 0 });
  const noStepUp = await seedSession("admin1");
  const staleStepUp = await seedSession("admin1", { stepUpAge: 16 * 60 });
  for (const [label, cookie] of [["signed-in non-admin", member], ["admin without passkey step-up", noStepUp], ["admin with a step-up older than 15 minutes", staleStepUp]]) {
    assert.equal((await studio("/studio/api/saml", undefined, cookie)).status, 403, label + " reads");
    const write = await studio("/studio/api/saml/connections", create, cookie);
    assert.equal(write.status, 403, label + " writes");
    assert.match((await write.json()).error, /recent passkey/, label);
    assert.equal((await studio("/studio/api/saml/preview", { metadataXml }, cookie)).status, 403, label + " previews");
  }
  assert.equal(await db.prepare("SELECT count(*) AS n FROM nathan_saml_connections").first().then(x => x.n), 0, "nothing was created");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE action LIKE 'saml_%'").first().then(x => x.n), 0,
    "refused callers never reach the audited service");
});

test("metadata preview reports problems without saving", async () => {
  const weak = makeCertificate({ bits: 1024 });
  const bad = await studio("/studio/api/saml/preview", { metadataXml: idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [weak.certB64] }) });
  assert.equal(bad.status, 409);
  assert.match((await bad.json()).error, /2048/);
  const good = await ok(await studio("/studio/api/saml/preview", { providerId: PID, metadataXml: idpMetadata({ entityID: IDP, ssoUrl: "https://idp.acme.example/sso", certB64s: [idp.certB64] }) }));
  assert.equal(good.idp.entityID, IDP);
  assert.equal(good.sp.acsUrl, ACS);
  const fetched = await ok(await studio("/studio/api/saml/preview", { metadataUrl: METADATA_URL }));
  assert.equal(fetched.idp.entityID, IDP, "metadata fetched through the Worker's outbound fetch");
  const audits = (await db.prepare("SELECT actor,target,outcome FROM nathan_security_audit WHERE action='saml_metadata_preview' ORDER BY rowid").all()).results;
  assert.deepEqual(audits.map(a => [a.actor, a.target, a.outcome]), [
    ["admin1", "pasted", "attempted"], ["admin1", "pasted", "failed"],
    ["admin1", "pasted", "attempted"], ["admin1", "pasted", "succeeded"],
    ["admin1", "idp.acme.example", "attempted"], ["admin1", "idp.acme.example", "succeeded"]
  ], "privileged metadata preview is audited with actor, target host and outcome");
  const leaked = await db.prepare("SELECT count(*) AS n FROM nathan_security_audit WHERE target LIKE '%<%' OR target LIKE '%/%' OR length(target)>253").first();
  assert.equal(leaked.n, 0, "the audit never stores the metadata document or URL path");
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

test("Better Auth's DNS TXT check verifies the domain only with the issued token", async () => {
  const txtHost = "_better-auth-token-" + PID + "." + DOMAIN;
  const { value: token } = await db.prepare("SELECT value FROM verification WHERE identifier=?").bind("_better-auth-token-" + PID).first();
  const verify = () => studio("/studio/api/sso/verify", { providerId: PID });
  const verified = async () => Number((await db.prepare('SELECT "domainVerified" AS v FROM "ssoProvider" WHERE "providerId"=?').bind(PID).first()).v) === 1;
  const queried = dnsQueries.length;
  assert.equal((await verify()).status, 400, "no TXT record published");
  assert.ok(dnsQueries.slice(queried).includes(txtHost + " TXT"), "the TXT lookup went out over DNS-over-HTTPS: " + dnsQueries.join(", "));
  assert.equal(await verified(), false);
  dnsTxt.set(txtHost, ["_better-auth-token-" + PID + "=wrong-" + token.slice(6), "unrelated=1"]);
  assert.equal((await verify()).status, 400, "wrong token");
  assert.equal(await verified(), false);
  dnsTxt.set(txtHost.replace(DOMAIN, "evil.example"), ["_better-auth-token-" + PID + "=" + token]);
  assert.equal((await verify()).status, 400, "the right token in another zone does not count");
  assert.equal(await verified(), false);
  assert.equal(await auditCount("enterprise_sso_domain_verify", "failed"), 3);
  dnsTxt.set(txtHost, ["unrelated=1", "_better-auth-token-" + PID + "=" + token]);
  await ok(await verify());
  assert.equal(await verified(), true, "the issued token in the connection's own zone verifies the domain");
  assert.equal(await auditCount("enterprise_sso_domain_verify", "succeeded"), 1);
});

test("enabling after domain verification opens SSO for the domain", async () => {
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
test("SHA-1 signed response is rejected by Nathan's algorithm guard", async () => {
  const r = await login({ signatureAlgorithm: "rsa-sha1", email: "sha1user@" + DOMAIN });
  await assertGateRejected(r, "saml_weak_algorithm", "sha1");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind("sha1user@" + DOMAIN).first(), null);
});

test("duplicate SAMLResponse fields are refused before parsing, in either order", async () => {
  const sha1user = "sha1user@" + DOMAIN;
  for (const order of ["strong first", "weak first"]) {
    const { id, relayState } = await startLogin();
    const strong = samlResponse(good({ inResponseTo: id }));
    const weak = samlResponse(good({ inResponseTo: id, email: sha1user, signatureAlgorithm: "rsa-sha1" }));
    const pair = order === "strong first" ? [strong, weak] : [weak, strong];
    const r = await postForm([["SAMLResponse", pair[0]], ["SAMLResponse", pair[1]], ["RelayState", relayState]]);
    await assertGateRejected(r, "saml_duplicate_parameter", order);
  }
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind(sha1user).first(), null, "no user created");
  const events = (await db.prepare("SELECT actor,target,outcome FROM nathan_security_audit WHERE action='saml_message_rejected'").all()).results;
  const dup = events.filter(e => e.target === PID + ":saml_duplicate_parameter");
  assert.ok(dup.length >= 1, "audited as a security event");
  assert.ok(dup.every(e => e.actor === "anonymous" && e.outcome === "rejected"), "without payloads");
});

/** Posts a raw form body exactly as given, so malformed escapes reach the Worker untouched. */
function postRaw(body, url = ACS) {
  return mf.dispatchFetch(url, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://idp.acme.example" },
    body
  });
}

test("a malformed percent-escape cannot smuggle a second SAMLResponse past the guard", async () => {
  // URLSearchParams keeps "SAMLResp%onse" as its own name; workerd's formData(), which the
  // plugin uses, drops the stray '%' and reads a second SAMLResponse (the last one wins).
  const sha1user = "smuggled@" + DOMAIN;
  const { id, relayState } = await startLogin();
  const strong = encodeURIComponent(samlResponse(good({ inResponseTo: id })));
  const weak = encodeURIComponent(samlResponse(good({ inResponseTo: id, email: sha1user, signatureAlgorithm: "rsa-sha1" })));
  const body = "SAMLResponse=" + strong + "&RelayState=" + encodeURIComponent(relayState) + "&SAMLResp%onse=" + weak;
  await assertGateRejected(await postRaw(body), "saml_noncanonical_encoding", "smuggled field name");
  await assertGateRejected(await postRaw("SAMLResponse=" + strong + "%zz&RelayState=" + encodeURIComponent(relayState)),
    "saml_noncanonical_encoding", "malformed escape in a value");
  const slo = ORIGIN + "/api/auth/sso/saml2/sp/slo/" + PID;
  await assertGateRejected(await mf.dispatchFetch(slo + "?SAMLReq%uest=a&SAMLRequest=b", { redirect: "manual" }),
    "saml_noncanonical_encoding", "malformed escape in the query");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind(sha1user).first(), null, "no user created");
});

/**
 * Sends a raw HTTP/1.1 request to the Miniflare entry (fetch() refuses a GET with a body). Headers
 * and body go out in one write, and the result is taken on `close`: the gate may answer and close
 * the connection before the body is fully read, which can surface as EPIPE/ECONNRESET. That is the
 * server refusing early, so a socket error after a response arrived is not a test failure.
 */
async function rawRequest(method, path, headers, body) {
  const { connect } = await import("node:net");
  const base = new URL(await mf.ready);
  const payload = Buffer.from(body ?? "");
  // MF-Original-URL is how dispatchFetch tells Miniflare's entry the public URL (https issuer origin).
  const head = [method + " " + path + " HTTP/1.1", "Host: " + HOST, "Connection: close", "MF-Original-URL: https://" + HOST + path,
    "Content-Length: " + payload.length, ...Object.entries(headers).map(([k, v]) => k + ": " + v)].join("\r\n") + "\r\n\r\n";
  return new Promise((resolve, reject) => {
    const chunks = [];
    let socketError = null;
    const socket = connect(Number(base.port), base.hostname, () => socket.end(Buffer.concat([Buffer.from(head), payload])));
    socket.on("data", c => chunks.push(c));
    socket.on("error", e => { socketError = e; });
    socket.on("close", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      if (!text) return reject(socketError ?? new Error("no response"));
      resolve({ status: Number(text.split(" ")[1]), text, sessionSet: /session_token=[^;\s]/.test(text) });
    });
  });
}

test("a SAML message in the body of a non-POST request never reaches the plugin", async () => {
  const sha1user = "getbody@" + DOMAIN;
  for (const [type, encode] of [["application/x-www-form-urlencoded", (r, s) => "SAMLResponse=" + encodeURIComponent(r) + "&RelayState=" + encodeURIComponent(s)],
                                ["application/json", (r, s) => JSON.stringify({ SAMLResponse: r, RelayState: s })]]) {
    const { id, relayState } = await startLogin();
    const weak = samlResponse(good({ inResponseTo: id, email: sha1user, signatureAlgorithm: "rsa-sha1" }));
    const r = await rawRequest("GET", new URL(ACS).pathname, { "Content-Type": type, Origin: "https://idp.acme.example" }, encode(weak, relayState));
    assert.equal(r.sessionSet, false, type + ": GET with a body must not sign in");
    assert.equal(r.status, 400, type + ": " + r.text.slice(0, 300));
    assert.match(r.text, /saml_body_not_allowed/, type);
  }
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind(sha1user).first(), null, "no user created");
});

test("SAML single logout is refused at the gate while single logout is not enabled", async () => {
  const slo = "/api/auth/sso/saml2/sp/slo/" + PID;
  const get = await mf.dispatchFetch(ORIGIN + slo + "?SAMLRequest=abc", { redirect: "manual" });
  assert.equal(get.status, 404, await get.clone().text());
  const post = await postForm([["SAMLRequest", "abc"]], ORIGIN + slo);
  assert.ok([400, 404].includes(post.status), "refused by the gate: " + post.status);
});

test("rejected SAML messages write at most one audit row per connection, reason and minute", async () => {
  await db.prepare("DELETE FROM nathan_security_audit WHERE action='saml_message_rejected'").run();
  for (let i = 0; i < 12; i++)
    await assertGateRejected(await postForm([["RelayState", "x" + i]]), "saml_missing_response", "flood " + i);
  const rows = (await db.prepare("SELECT target FROM nathan_security_audit WHERE action='saml_message_rejected'").all()).results;
  assert.ok(rows.length >= 1 && rows.length <= 2, "flood must not grow the audit log per request, got " + rows.length);
});

test("duplicate RelayState and repeated SAML query parameters are refused", async () => {
  const { id, relayState } = await startLogin();
  const b64 = samlResponse(good({ inResponseTo: id }));
  await assertGateRejected(await postForm([["SAMLResponse", b64], ["RelayState", relayState], ["RelayState", "x"]]), "saml_duplicate_parameter", "RelayState twice");
  await assertGateRejected(await postForm([["SAMLResponse", b64], ["RelayState", relayState]], ACS + "?RelayState=x"), "saml_duplicate_parameter", "RelayState in query and body");
  await assertGateRejected(await postForm([["RelayState", relayState]]), "saml_missing_response", "no SAMLResponse");
  const slo = ORIGIN + "/api/auth/sso/saml2/sp/slo/" + PID;
  for (const name of ["SAMLRequest", "SAMLResponse", "SigAlg", "Signature", "RelayState"]) {
    const r = await mf.dispatchFetch(slo + "?" + name + "=a&" + name + "=b", { redirect: "manual" });
    await assertGateRejected(r, "saml_duplicate_parameter", "SLO query " + name);
    const acs = await mf.dispatchFetch(ACS + "?" + name + "=a&" + name + "=b", { redirect: "manual" });
    await assertGateRejected(acs, "saml_duplicate_parameter", "ACS query " + name);
  }
  assert.ok(sessionCookie(await post(b64, relayState)), "the same single-field response still signs in");
});

test("a response with an encrypted assertion is refused (Nathan configures no decryption key)", async () => {
  const { id, relayState } = await startLogin();
  const r = await post(samlResponse(good({ inResponseTo: id, mutate: x => x.replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/,
    '<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>') })), relayState);
  await assertGateRejected(r, "saml_encrypted_assertion", "encrypted");
});
test("an IdP cannot create users outside its verified domain", async () => {
  const { id, relayState } = await startLogin();
  await assertRejected(await post(samlResponse(good({ inResponseTo: id, email: "ceo@other.example" })), relayState), "foreign domain");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind("ceo@other.example").first(), null);
});

test("an IdP cannot sign in or link an existing verified user from another domain", async () => {
  await seedUser("cfo1", "cfo@other.example");
  const { id, relayState } = await startLogin();
  await assertRejected(await post(samlResponse(good({ inResponseTo: id, email: "cfo@other.example" })), relayState), "existing user outside the verified domain");
  assert.equal(await db.prepare('SELECT id FROM "account" WHERE "userId"=?').bind("cfo1").first(), null, "no account linked");
  assert.equal(await db.prepare('SELECT id FROM "session" WHERE "userId"=?').bind("cfo1").first(), null, "no session");
});

test("invitation-only provisioning admits existing users but creates nobody", async () => {
  await ok(await studio("/studio/api/saml/provisioning", { providerId: PID, provisioning: "invitation-only",
    confirm: "CONFIRM PROVISIONING invitation-only " + PID }));
  await assertRejected(await login({ email: "newhire@" + DOMAIN }), "new user under invitation-only");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind("newhire@" + DOMAIN).first(), null);
  assert.ok(sessionCookie(await login()), "existing linked user still signs in");
});

test("invitation-only links an existing verified user inside the domain on first SAML sign-in", async () => {
  // Design: invitation means "the account already exists". An admin-created (or
  // previously signed-up) verified user in the DNS-verified domain is linked to
  // the connection the first time the IdP signs for that address.
  await seedUser("alice1", "alice@" + DOMAIN);
  const r = await login({ email: "alice@" + DOMAIN });
  assert.ok(sessionCookie(r), "existing user signs in: " + r.headers.get("location"));
  const account = await db.prepare('SELECT "accountId" AS a FROM "account" WHERE "userId"=? AND "providerId"=?').bind("alice1", PID).first();
  assert.ok(account, "SAML account linked to the existing user");
  assert.equal((await db.prepare('SELECT count(*) AS n FROM "user" WHERE email=?').bind("alice@" + DOMAIN).first()).n, 1, "no duplicate user");
});

test("invitation-only refuses an existing user outside the domain", async () => {
  await seedUser("bob1", "bob@other.example");
  const { id, relayState } = await startLogin();
  await assertRejected(await post(samlResponse(good({ inResponseTo: id, email: "bob@other.example" })), relayState), "existing user outside the domain");
  assert.equal(await db.prepare('SELECT id FROM "account" WHERE "userId"=?').bind("bob1").first(), null, "no account linked");
  assert.equal(await db.prepare('SELECT id FROM "session" WHERE "userId"=?').bind("bob1").first(), null, "no session");
});

test("NATH-16: an invitation-only installation refuses SAML just-in-time users without an invitation; an invitation works once", async () => {
  await ok(await studio("/studio/api/saml/provisioning", { providerId: PID, provisioning: "just-in-time",
    confirm: "CONFIRM PROVISIONING just-in-time " + PID }));
  await ok(await studio("/studio/api/admission", { op: "mode", mode: "invitation-only", confirm: "CONFIRM ADMISSION invitation-only" }));
  const email = "hire@" + DOMAIN;
  const refused = await login({ email });
  await assertRejected(refused, "uninvited SAML just-in-time user");
  assert.match(refused.headers.get("location") || "", /ACCOUNT_NOT_ADMITTED/, "the refusal names the reason");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind(email).first(), null, "no user row");
  const invitation = await ok(await studio("/studio/api/admission", { op: "invite", email }));
  const admitted = await login({ email });
  assert.ok(sessionCookie(admitted), "invited SAML user signs in: " + admitted.headers.get("location"));
  const user = await db.prepare('SELECT id, "emailVerified" AS v FROM "user" WHERE email=?').bind(email).first();
  assert.equal(user.v, 1);
  const used = await db.prepare("SELECT uses, used_method AS method, used_by_user AS userId FROM nathan_invitations WHERE id=?").bind(invitation.id).first();
  assert.deepEqual({ ...used }, { uses: 1, method: "saml:" + PID, userId: user.id });
  // Single use: the same invitation never creates the account twice.
  await db.prepare('DELETE FROM "user" WHERE id=?').bind(user.id).run();
  await assertRejected(await login({ email }), "used invitation");
  assert.equal(await db.prepare('SELECT id FROM "user" WHERE email=?').bind(email).first(), null);
  // Existing users still sign in under invitation-only admission.
  assert.ok(sessionCookie(await login()), "existing linked user still signs in");
  await ok(await studio("/studio/api/admission", { op: "mode", mode: "self-service", confirm: "CONFIRM ADMISSION self-service" }));
  await ok(await studio("/studio/api/saml/provisioning", { providerId: PID, provisioning: "invitation-only",
    confirm: "CONFIRM PROVISIONING invitation-only " + PID }));
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

test("concurrent certificate changes never silently lose an update", async () => {
  const a = makeCertificate({ cn: "acme idp a" }), b = makeCertificate({ cn: "acme idp b" });
  const results = await Promise.all([a, b].map(c => studio("/studio/api/saml/certificates", { providerId: PID, certificate: c.certPem })));
  const bodies = await Promise.all(results.map(r => r.json()));
  const accepted = results.filter(r => r.status === 200).length;
  assert.ok(accepted >= 1, JSON.stringify(bodies));
  for (const [i, r] of results.entries())
    if (r.status !== 200) assert.match(bodies[i].error, /changed concurrently/, "a lost race is reported, not swallowed");
  const { certificates, samlConfig } = await db.prepare('SELECT c.certificates AS certificates,p."samlConfig" AS samlConfig FROM nathan_saml_connections c JOIN "ssoProvider" p ON p."providerId"=c.provider_id WHERE c.provider_id=?').bind(PID).first();
  const stored = JSON.parse(certificates);
  assert.equal(stored.length, 1 + accepted, "every accepted certificate is still stored");
  for (const der of stored.map(c => c.der)) assert.ok(JSON.parse(samlConfig).idpMetadata.metadata.includes(der), "plugin metadata matches Nathan's list");
  // Remove whatever was added so the rest of the suite sees one certificate.
  for (const c of stored.slice(1))
    await ok(await studio("/studio/api/saml/certificates/retire", { providerId: PID, sha256: c.sha256, confirm: "CONFIRM RETIRE CERTIFICATE " + PID }));
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
