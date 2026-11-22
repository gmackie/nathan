/**
 * NATH-12 end-to-end in workerd: Nathan as a SAML IdP. A real SP library (samlify's
 * ServiceProvider, in Node) creates AuthnRequests and validates the signed Responses that the built
 * auth Worker issues. Every refusal case must produce no assertion.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import * as samlify from "samlify";
import { XMLValidator } from "fast-xml-parser";
import { deflateRawSync } from "node:zlib";
import { authWorker, cookiesOf, randomKey, enrollAdmin, insertSession, studioPost } from "./helpers.mjs";
import { makeCertificate } from "../fixtures/x509.mjs";

samlify.setSchemaValidator({ async validate(xml) { if (XMLValidator.validate(xml) === true) return "ok"; throw Error("invalid xml"); } });

const HOST = "login.example.test";
const ORIGIN = "https://" + HOST;
const SSO = ORIGIN + "/saml/idp/sso";
const SP_ENTITY = "https://grafana.example.test/saml/metadata";
const ACS = "https://grafana.example.test/saml/acs";
const SECRET = randomKey() + randomKey();
const POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
let mf, db, admin;
after(() => mf?.dispose());

const run = (sql, ...args) => db.prepare(sql).bind(...args).run();
async function seedUser(id, { emailVerified = 1, banned = 0 } = {}) {
  const now = new Date().toISOString();
  await run('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role","banned") VALUES (?,?,?,?,?,?,\'user\',?)',
    id, "User " + id, id + "@example.test", emailVerified, now, now, banned);
  return (await insertSession(db, SECRET, id)).cookie;
}
const grant = (appId, userId, role = "viewer") =>
  run("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES (?,?,?,'user',?,'admin-1')", crypto.randomUUID(), appId, role, userId);
const studio = (body, cookie = admin) => studioPost({ fetch: (url, init) => mf.dispatchFetch(url, init) }, ORIGIN, "/studio/api/saml-idp", body, cookie);
async function ok(response) {
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  return body;
}
const auditRows = async (action, target) =>
  (await db.prepare("SELECT actor, target, outcome FROM nathan_security_audit WHERE action=? AND target LIKE ? ORDER BY created_at, rowid").bind(action, target).all()).results;

async function idpFromMetadata() {
  const response = await mf.dispatchFetch(ORIGIN + "/saml/idp/metadata");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /samlmetadata\+xml/);
  const metadata = await response.text();
  return { idp: samlify.IdentityProvider({ metadata }), certificates: metadata.match(/<ds:X509Certificate>/g).length };
}
const serviceProvider = (over = {}) => samlify.ServiceProvider({
  entityID: SP_ENTITY, wantAssertionsSigned: true, authnRequestsSigned: false,
  assertionConsumerService: [{ Binding: POST_BINDING, Location: ACS }], ...over
});

/** SSO request through Nathan: returns the 303 response (or a refusal page). */
function redirectLogin(url, cookie) {
  return mf.dispatchFetch(url, { redirect: "manual", headers: cookie ? { Cookie: cookie } : {} });
}
function postLogin(fields) {
  return mf.dispatchFetch(SSO, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://grafana.example.test" },
    body: new URLSearchParams(fields).toString() });
}
const resumeCookie = response => {
  const c = cookiesOf(response)["__Host-nathan-saml-idp"];
  assert.ok(c?.value, "a resume cookie is set: " + response.status);
  assert.match(c.raw, /HttpOnly/); assert.match(c.raw, /Secure/); assert.match(c.raw, /SameSite=Lax/);
  return "__Host-nathan-saml-idp=" + c.value;
};
/** Follows Nathan's 303 to /saml/idp/continue with the browser's cookies; returns the final page. */
async function continueWith(response, session) {
  assert.equal(response.status, 303, (await response.clone().text()).slice(0, 300));
  assert.equal(response.headers.get("location"), ORIGIN + "/saml/idp/continue");
  return mf.dispatchFetch(ORIGIN + "/saml/idp/continue", { redirect: "manual", headers: { Cookie: resumeCookie(response) + (session ? "; " + session : "") } });
}
/** The hidden form fields of Nathan's auto-POST page. */
async function form(page) {
  const html = await page.text();
  assert.equal(page.status, 200, html.slice(0, 400));
  const field = name => { const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(html); return m ? m[1].replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&") : null; };
  return { html, action: /action="([^"]+)"/.exec(html)?.[1].replace(/&amp;/g, "&"), SAMLResponse: field("SAMLResponse"), RelayState: field("RelayState"), csp: page.headers.get("content-security-policy") };
}
async function refused(page, label) {
  const html = await page.text();
  assert.ok(page.status >= 400, label + ": expected a refusal, got " + page.status);
  assert.doesNotMatch(html, /SAMLResponse/, label + ": no assertion may be issued");
  return html;
}
const xmlOf = b64 => Buffer.from(b64, "base64").toString("utf8");
/** A hand-built unsigned AuthnRequest URL (HTTP-Redirect) for cases an SP library does not produce. */
const manual = (attrs, issuedAt = new Date().toISOString()) => SSO + "?SAMLRequest=" + encodeURIComponent(deflateRawSync(
  `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_m${randomKey().replace(/-/g, "")}" Version="2.0" IssueInstant="${issuedAt}"${attrs}><saml:Issuer>${SP_ENTITY}</saml:Issuer></samlp:AuthnRequest>`).toString("base64"));

const SP_METADATA_URL = "https://sp.example.com/saml/metadata";
const spMetadata = (acs = ACS) => `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${SP_ENTITY}"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService Binding="${POST_BINDING}" Location="${acs}" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>`;
const outbound = [];
async function outboundService(request) {
  outbound.push(request.url);
  if (request.url === SP_METADATA_URL) return new Response(spMetadata(), { headers: { "content-type": "application/samlmetadata+xml" } });
  if (request.url === "https://sp.example.com/redirecting") return new Response(null, { status: 302, headers: { Location: SP_METADATA_URL } });
  return new Response("unexpected outbound request", { status: 599 });
}

let user, idp;
before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET }, { outboundService });
  db = await mf.getD1Database("DB");
  admin = (await enrollAdmin(db, SECRET)).cookie;
  await run("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('grafana','grafana.example.test',1,'approved')");
  await run("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('grafana','viewer'),('grafana','editor')");
  user = await seedUser("jane");
  await grant("grafana", "jane", "editor");
});

test("metadata is unavailable until a signing key exists; Studio writes need an enrolled admin and exact confirmation", async () => {
  assert.equal((await mf.dispatchFetch(ORIGIN + "/saml/idp/metadata")).status, 404);
  assert.equal((await studio({ op: "key.generate", confirm: "CONFIRM GENERATE SAML IDP KEY" }, user)).status, 403, "non-admin refused");
  const wrong = await studio({ op: "key.generate", confirm: "yes" });
  assert.equal(wrong.status, 409);
  assert.match((await wrong.json()).error, /CONFIRM GENERATE SAML IDP KEY/);
  const crossSite = await mf.dispatchFetch(ORIGIN + "/studio/api/saml-idp", { method: "POST", body: "{}",
    headers: { Cookie: admin, Origin: "https://evil.example", "Content-Type": "application/json" } });
  assert.equal(crossSite.status, 403);
  const key = await ok(await studio({ op: "key.generate", confirm: "CONFIRM GENERATE SAML IDP KEY" }));
  assert.equal(key.status, "active");
  assert.equal(key.bits, 2048);
  assert.equal(key.privateKey, undefined);
  const stored = await db.prepare("SELECT private_key FROM nathan_saml_idp_keys WHERE id=?").bind(key.id).first();
  assert.match(stored.private_key, /^v1\./, "sealed under NATHAN_CONFIG_KEY");
  assert.doesNotMatch(JSON.stringify(await ok(await mf.dispatchFetch(ORIGIN + "/studio/api/saml-idp", { headers: { Cookie: admin } }))), /v1\.[A-Za-z0-9_-]{16}/,
    "the overview never returns key material");
  ({ idp } = await idpFromMetadata());
  const md = await (await mf.dispatchFetch(ORIGIN + "/saml/idp")).text();
  assert.match(md, /entityID="https:\/\/login\.example\.test\/saml\/idp"/);
  assert.match(md, /HTTP-Redirect" Location="https:\/\/login\.example\.test\/saml\/idp\/sso"/);
  assert.match(md, /HTTP-POST" Location="https:\/\/login\.example\.test\/saml\/idp\/sso"/);
});

test("SP registration: validated, bound to an existing app, disabled by default, audited", async () => {
  const base = { op: "sp.create", id: "grafana", name: "Grafana", appId: "grafana", entityId: SP_ENTITY, acsUrls: [ACS],
    attributes: [{ name: "email", source: "email" }, { name: "displayName", source: "name" }, { name: "role", source: "roles" }] };
  const bad = async (over, pattern) => { const r = await studio({ ...base, confirm: "CONFIRM CREATE SAML SP grafana", ...over }); assert.equal(r.status, 409); assert.match((await r.json()).error, pattern); };
  await bad({ appId: "missing" }, /Unknown application/);
  await bad({ acsUrls: ["https://*.example.test/acs"] }, /wildcard/);
  await bad({ acsUrls: ["http://grafana.example.test/saml/acs"] }, /https/);
  await bad({ confirm: "CONFIRM CREATE SAML SP other" }, /confirmation/);
  const created = await ok(await studio({ ...base, confirm: "CONFIRM CREATE SAML SP grafana" }));
  assert.equal(created.enabled, false);
  assert.equal(created.nameIdFormat, "persistent");
  assert.equal(created.allowIdpInitiated, false);
  const sp = serviceProvider();
  const { context } = sp.createLoginRequest(idp, "redirect");
  assert.ok(context.startsWith(SSO + "?"), context);
  await refused(await redirectLogin(context), "disabled SP");
  assert.ok((await auditRows("saml_idp_request_rejected", "grafana:saml_sp_disabled")).length >= 1);
  await ok(await studio({ op: "sp.status", id: "grafana", enabled: true, confirm: "CONFIRM ENABLE SAML SP grafana" }));
  assert.deepEqual((await auditRows("saml_idp_sp_create", "grafana")).map(r => r.outcome).slice(-2), ["attempted", "succeeded"]);
  assert.deepEqual((await auditRows("saml_idp_sp_enable", "grafana")).map(r => r.outcome), ["attempted", "succeeded"]);
});

test("SP metadata preview: pasted or fetched over HTTPS without redirects, audited by host, never stored", async () => {
  const pasted = await ok(await studio({ op: "sp.preview", metadataXml: spMetadata() }));
  assert.deepEqual([pasted.entityId, pasted.acsUrls, pasted.nameIdFormat], [SP_ENTITY, [ACS], "persistent"]);
  const fetched = await ok(await studio({ op: "sp.preview", metadataUrl: SP_METADATA_URL }));
  assert.equal(fetched.entityId, SP_ENTITY);
  assert.ok(outbound.includes(SP_METADATA_URL));
  const redirected = await studio({ op: "sp.preview", metadataUrl: "https://sp.example.com/redirecting" });
  assert.equal(redirected.status, 409, "redirects are not followed");
  for (const [body, pattern] of [[{ metadataUrl: "http://sp.example.com/m" }, /HTTPS/i], [{ metadataUrl: "https://10.0.0.1/m" }, /public/],
    [{ metadataXml: '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>' + spMetadata() }, /DTD/]]) {
    const r = await studio({ op: "sp.preview", ...body });
    assert.equal(r.status, 409);
    assert.match((await r.json()).error, pattern);
  }
  const rows = await auditRows("saml_idp_sp_metadata_preview", "%");
  assert.ok(rows.some(r => r.target === "sp.example.com" && r.outcome === "succeeded"));
  assert.ok(rows.some(r => r.target === "pasted" && r.outcome === "succeeded"));
  assert.ok(rows.every(r => !r.target.includes("/")), "the URL path is never logged");
  assert.equal((await db.prepare("SELECT count(*) AS n FROM nathan_saml_service_providers WHERE id<>'grafana'").first()).n, 0);
});

test("ForceAuthn needs a sign-in after the request; IsPassive never prompts", async () => {
  const stale = await insertSession(db, SECRET, "jane");
  await run('UPDATE "session" SET "createdAt"=? WHERE "id"=?', new Date(Date.now() - 3600e3).toISOString(), stale.id);
  const forced = await continueWith(await redirectLogin(manual(' ForceAuthn="true"')), stale.cookie);
  assert.equal(forced.status, 302);
  assert.equal(forced.headers.get("location"), ORIGIN + "/sign-in", "an old session must sign in again");
  const fresh = await form(await continueWith(await redirectLogin(manual(' ForceAuthn="true"')), user));
  assert.equal(fresh.action, ACS, "a session created for this request is accepted");
  await refused(await continueWith(await redirectLogin(manual(' IsPassive="true"'))), "passive without a session");
  assert.equal((await auditRows("saml_idp_assertion", "grafana")).at(-1).outcome, "denied:passive_requires_sign_in");
});

test("SP-initiated login (HTTP-Redirect): a signed Response that an independent SP library validates", async () => {
  const sp = serviceProvider();
  const { id, context } = sp.createLoginRequest(idp, "redirect");
  const url = new URL(context);
  url.searchParams.set("RelayState", "/d/home");
  const page = await continueWith(await redirectLogin(url.href), user);
  const { action, SAMLResponse, RelayState, csp, html } = await form(page);
  assert.equal(action, ACS);
  assert.equal(RelayState, "/d/home");
  assert.match(csp, /form-action https:\/\/grafana\.example\.test;/, "form-action limited to the ACS origin");
  assert.match(csp, /script-src 'nonce-/);
  assert.equal(page.headers.get("referrer-policy"), "same-origin");
  assert.match(page.headers.get("set-cookie"), /__Host-nathan-saml-idp=; .*Max-Age=0/, "the resume handle is cleared");
  assert.doesNotMatch(html, /<script>/, "only nonce'd scripts");
  const { extract } = await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse, RelayState } });
  assert.equal(extract.issuer, ORIGIN + "/saml/idp");
  assert.equal(extract.audience, SP_ENTITY);
  assert.equal(extract.response.inResponseTo, id);
  assert.match(extract.nameID, /^[A-Za-z0-9_-]{32}$/, "persistent pairwise opaque NameID");
  assert.equal(extract.attributes.email, "jane@example.test");
  assert.equal(extract.attributes.displayName, "User jane");
  assert.equal(extract.attributes.role, "editor");
  const xml = xmlOf(SAMLResponse);
  assert.match(xml, /nameid-format:persistent/);
  assert.match(xml, /ac:classes:unspecified/, "no assurance claimed without verified evidence");
  assert.match(xml, new RegExp('Recipient="' + ACS));
  // The same user gets the same NameID next time; the audit row names SP, user and outcome only.
  const again = await form(await continueWith(await redirectLogin(sp.createLoginRequest(idp, "redirect").context), user));
  assert.equal((await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: again.SAMLResponse } })).extract.nameID, extract.nameID);
  const rows = await auditRows("saml_idp_assertion", "grafana");
  assert.deepEqual(rows.slice(-2).map(r => [r.actor, r.outcome]), [["jane", "issued"], ["jane", "issued"]]);
  const all = JSON.stringify((await db.prepare("SELECT * FROM nathan_security_audit").all()).results);
  assert.ok(!all.includes(extract.nameID) && !all.includes(SAMLResponse.slice(0, 40)), "no assertion content in the audit log");
});

test("tampering with Nathan's response breaks validation at the SP", async () => {
  const sp = serviceProvider();
  const { SAMLResponse } = await form(await continueWith(await redirectLogin(sp.createLoginRequest(idp, "redirect").context), user));
  const tampered = Buffer.from(xmlOf(SAMLResponse).replace("jane@example.test", "admin@example.test")).toString("base64");
  await assert.rejects(sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: tampered } }));
});

test("without a Nathan session the browser signs in first and resumes through '/' (single use)", async () => {
  const sp = serviceProvider();
  const first = await redirectLogin(sp.createLoginRequest(idp, "redirect").context);
  const resume = resumeCookie(first);
  const noSession = await continueWith(first);
  assert.equal(noSession.status, 302);
  assert.equal(noSession.headers.get("location"), ORIGIN + "/sign-in");
  const home = await mf.dispatchFetch(ORIGIN + "/", { redirect: "manual", headers: { Cookie: resume + "; " + user } });
  assert.equal(home.headers.get("location"), ORIGIN + "/saml/idp/continue");
  const page = await mf.dispatchFetch(ORIGIN + "/saml/idp/continue", { headers: { Cookie: resume + "; " + user } });
  await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: (await form(page)).SAMLResponse } });
  await refused(await mf.dispatchFetch(ORIGIN + "/saml/idp/continue", { headers: { Cookie: resume + "; " + user } }), "the pending request is single use");
  const forged = resume.replace(/=(.{10})/, "=AAAAAAAAAA");
  await refused(await mf.dispatchFetch(ORIGIN + "/saml/idp/continue", { headers: { Cookie: forged + "; " + user } }), "a forged handle is refused");
});

test("SP-initiated login with the HTTP-POST binding (the SP posts cross-site; the session cookie arrives on the redirect)", async () => {
  const sp = serviceProvider();
  const { context, relayState } = sp.createLoginRequest(idp, "post");
  const page = await continueWith(await postLogin({ SAMLRequest: context, RelayState: relayState || "rs-1" }), user);
  const { SAMLResponse, RelayState } = await form(page);
  assert.equal(RelayState, relayState || "rs-1");
  await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse } });
});

test("unknown SP, wrong ACS, replayed request ID, stale or misaddressed requests: no assertion", async () => {
  const stranger = serviceProvider({ entityID: "https://stranger.example.test/saml" });
  await refused(await redirectLogin(stranger.createLoginRequest(idp, "redirect").context), "unknown SP");
  const wrongAcs = serviceProvider({ assertionConsumerService: [{ Binding: POST_BINDING, Location: "https://evil.example.test/acs" }] });
  const html = await refused(await redirectLogin(wrongAcs.createLoginRequest(idp, "redirect").context), "wrong ACS");
  assert.match(html, /saml_acs_mismatch/);
  assert.doesNotMatch(html, /evil\.example\.test/, "the refusal page never links to the unregistered ACS");
  const { context } = serviceProvider().createLoginRequest(idp, "redirect");
  await continueWith(await redirectLogin(context), user);
  assert.match(await refused(await redirectLogin(context), "replayed request ID"), /saml_replayed_request/);
  assert.match(await refused(await redirectLogin(manual("", new Date(Date.now() - 10 * 60e3).toISOString())), "stale"), /saml_stale_request/);
  assert.match(await refused(await redirectLogin(manual(' Destination="https://other-idp.example.test/sso"')), "destination"), /saml_destination_mismatch/);
  assert.match(await refused(await redirectLogin(manual(' AssertionConsumerServiceIndex="5"')), "bad index"), /saml_acs_mismatch/);
  assert.match(await refused(await redirectLogin(manual(' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"')), "artifact"), /saml_unsupported_binding/);
  // The default ACS is used when the request names none.
  const page = await form(await continueWith(await redirectLogin(manual("")), user));
  assert.equal(page.action, ACS);
});

test("duplicate and non-canonical binding parameters, bodies on GET-style requests and wrong content types are refused", async () => {
  const { context } = serviceProvider().createLoginRequest(idp, "redirect");
  const query = new URL(context).search.slice(1);
  const value = /SAMLRequest=([^&]+)/.exec(query)[1];
  const cases = [
    [SSO + "?" + query + "&SAMLRequest=" + value, "saml_duplicate_parameter"],
    [SSO + "?" + query + "&SAMLReq%75est=" + value, "saml_duplicate_parameter"],
    [SSO + "?" + query + "&SAMLResp%onse=x", "saml_noncanonical_encoding"],
    [SSO + "?" + query + "&&RelayState=x", "saml_noncanonical_encoding"],
    [SSO + "?" + query + "&RelayState=a&RelayState=b", "saml_duplicate_parameter"],
    [SSO + "?" + query + "&extra=1", "saml_unknown_parameter"],
    [SSO + "?RelayState=x", "saml_missing_request"]
  ];
  for (const [url, code] of cases) assert.match(await refused(await redirectLogin(url), code), new RegExp(code), url);
  const { context: posted } = serviceProvider().createLoginRequest(idp, "post");
  const body = "SAMLRequest=" + encodeURIComponent(posted);
  const post = (b, headers = {}, url = SSO) => mf.dispatchFetch(url, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers }, body: b });
  assert.match(await refused(await post(body + "&" + body), "post dup"), /saml_duplicate_parameter/);
  assert.match(await refused(await post(body + "&SAMLRequ%est=x"), "post noncanonical"), /saml_noncanonical_encoding/);
  assert.match(await refused(await post(body, {}, SSO + "?SAMLRequest=" + encodeURIComponent(value)), "post with query"), /saml_unknown_parameter/);
  assert.match(await refused(await post(JSON.stringify({ SAMLRequest: posted }), { "Content-Type": "application/json" }), "json"), /saml_form_required/);
  assert.equal((await mf.dispatchFetch(SSO, { method: "PUT", body })).status, 405);
  assert.ok((await auditRows("saml_idp_request_rejected", "%saml_duplicate_parameter")).length >= 1);
});

test("signed AuthnRequests: required means unsigned is refused; Redirect and POST signatures from the SP's key verify", async () => {
  const spKey = makeCertificate({ cn: "Signed SP" });
  const entity = "https://signed.example.test/saml";
  const acs = "https://signed.example.test/acs";
  await ok(await studio({ op: "sp.create", id: "signed", name: "Signed SP", appId: "grafana", entityId: entity, acsUrls: [acs],
    wantRequestsSigned: true, certificates: [spKey.certPem], confirm: "CONFIRM CREATE SAML SP signed" }));
  await ok(await studio({ op: "sp.status", id: "signed", enabled: true, confirm: "CONFIRM ENABLE SAML SP signed" }));
  const assertionConsumerService = [{ Binding: POST_BINDING, Location: acs }];
  const unsigned = serviceProvider({ entityID: entity, assertionConsumerService });
  assert.match(await refused(await redirectLogin(unsigned.createLoginRequest(idp, "redirect").context), "unsigned redirect"), /saml_signature_required/);
  assert.match(await refused(await postLogin({ SAMLRequest: unsigned.createLoginRequest(idp, "post").context }), "unsigned post"), /saml_signature_required/);
  const signingIdp = samlify.IdentityProvider({ metadata: (await (await mf.dispatchFetch(ORIGIN + "/saml/idp/metadata")).text()).replace('WantAuthnRequestsSigned="false"', 'WantAuthnRequestsSigned="true"') });
  const signer = serviceProvider({ entityID: entity, assertionConsumerService, authnRequestsSigned: true, privateKey: spKey.privateKey, signingCert: spKey.certPem,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" });
  const viaRedirect = await form(await continueWith(await redirectLogin(signer.createLoginRequest(signingIdp, "redirect").context), user));
  assert.equal(viaRedirect.action, acs);
  const viaPost = await form(await continueWith(await postLogin({ SAMLRequest: signer.createLoginRequest(signingIdp, "post").context }), user));
  assert.equal(viaPost.action, acs);
  // A signature from another key, or over a different message, is refused.
  const otherKey = makeCertificate();
  const impostor = serviceProvider({ entityID: entity, assertionConsumerService, authnRequestsSigned: true, privateKey: otherKey.privateKey, signingCert: otherKey.certPem,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" });
  assert.match(await refused(await redirectLogin(impostor.createLoginRequest(signingIdp, "redirect").context), "foreign key"), /saml_bad_signature/);
  const signedUrl = new URL(signer.createLoginRequest(signingIdp, "redirect").context);
  const swapped = signedUrl.href.replace(/SAMLRequest=[^&]+/, "SAMLRequest=" + new URL(unsigned.createLoginRequest(idp, "redirect").context).searchParams.get("SAMLRequest").replace(/[+/=]/g, c => encodeURIComponent(c)));
  assert.match(await refused(await redirectLogin(swapped), "swapped message"), /saml_bad_signature/);
});

test("users without access, blocked, deprovisioned, not admitted or unverified get no assertion (deny by default)", async () => {
  const sp = serviceProvider();
  const attempt = async cookie => continueWith(await redirectLogin(sp.createLoginRequest(idp, "redirect").context), cookie);
  const noGrant = await seedUser("nogrant");
  await refused(await attempt(noGrant), "no app access");
  const banned = await seedUser("banned", { banned: 1 });
  await grant("grafana", "banned");
  await refused(await attempt(banned), "banned");
  const gone = await seedUser("gone");
  await grant("grafana", "gone");
  await run("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES ('acme','example.test','admin-1')");
  await run("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state) VALUES ('acme','s1','e1','gone',0,'gone','deprovisioned')");
  await refused(await attempt(gone), "SCIM-deprovisioned");
  const provisional = await seedUser("provisional");
  await grant("grafana", "provisional");
  await run("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES ('provisional@example.test','provisional','password')");
  await refused(await attempt(provisional), "admission-refused");
  const unverified = await seedUser("unverified", { emailVerified: 0 });
  await grant("grafana", "unverified");
  await refused(await attempt(unverified), "unverified email");
  const outcomes = Object.fromEntries((await auditRows("saml_idp_assertion", "grafana")).filter(r => r.outcome.startsWith("denied") && r.actor !== "anonymous").map(r => [r.actor, r.outcome]));
  assert.deepEqual(outcomes, { nogrant: "denied:no_access:no_grant", banned: "denied:user_blocked", gone: "denied:deprovisioned",
    provisional: "denied:not_admitted", unverified: "denied:email_unverified" });
  // Disabling the app (NATH-13 evaluator) also stops the SP.
  await run("UPDATE nathan_applications SET enabled=0 WHERE id='grafana'");
  await refused(await attempt(user), "disabled application");
  await run("UPDATE nathan_applications SET enabled=1 WHERE id='grafana'");
});

test("passkey requirement uses verified evidence only and is reflected in AuthnContextClassRef", async () => {
  await ok(await studio({ op: "sp.update", id: "grafana", name: "Grafana", appId: "grafana", entityId: SP_ENTITY, acsUrls: [ACS], requirePasskey: true,
    attributes: [{ name: "email", source: "email" }], confirm: "CONFIRM UPDATE SAML SP grafana" }));
  const sp = serviceProvider();
  const html = await refused(await continueWith(await redirectLogin(sp.createLoginRequest(idp, "redirect").context), user), "no passkey evidence");
  assert.match(html, /passkey/);
  const session = await insertSession(db, SECRET, "jane");
  await run("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES (?,?,'passkey')", session.id, "jane");
  const { SAMLResponse } = await form(await continueWith(await redirectLogin(sp.createLoginRequest(idp, "redirect").context), session.cookie));
  assert.match(xmlOf(SAMLResponse), /<saml:AuthnContextClassRef>urn:nathan:acr:passkey<\/saml:AuthnContextClassRef>/);
  await ok(await studio({ op: "sp.update", id: "grafana", name: "Grafana", appId: "grafana", entityId: SP_ENTITY, acsUrls: [ACS], nameIdFormat: "email", signResponse: true,
    attributes: [{ name: "email", source: "email" }], confirm: "CONFIRM UPDATE SAML SP grafana" }));
  const email = await form(await continueWith(await redirectLogin(sp.createLoginRequest(idp, "redirect").context), user));
  const { extract } = await sp.parseLoginResponse(idp, "post", { body: { SAMLResponse: email.SAMLResponse } });
  assert.equal(extract.nameID, "jane@example.test");
  assert.equal((xmlOf(email.SAMLResponse).match(/<ds:Signature /g) ?? []).length, 2, "Response and Assertion signed");
});

test("IdP-initiated sign-in is off by default and, when enabled, needs a same-origin confirmation", async () => {
  assert.equal((await mf.dispatchFetch(ORIGIN + "/saml/idp/start/grafana", { headers: { Cookie: user } })).status, 404);
  await ok(await studio({ op: "sp.update", id: "grafana", name: "Grafana", appId: "grafana", entityId: SP_ENTITY, acsUrls: [ACS], allowIdpInitiated: true,
    defaultRelayState: "/d/home", attributes: [{ name: "email", source: "email" }], confirm: "CONFIRM UPDATE SAML SP grafana" }));
  const page = await mf.dispatchFetch(ORIGIN + "/saml/idp/start/grafana", { headers: { Cookie: user } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /method="post" action="\/saml\/idp\/start\/grafana"/);
  const cross = await mf.dispatchFetch(ORIGIN + "/saml/idp/start/grafana", { method: "POST", headers: { Cookie: user, Origin: "https://evil.example" } });
  await refused(cross, "cross-site IdP-initiated");
  const issued = await form(await mf.dispatchFetch(ORIGIN + "/saml/idp/start/grafana", { method: "POST", headers: { Cookie: user, Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" } }));
  assert.equal(issued.RelayState, "/d/home");
  assert.doesNotMatch(xmlOf(issued.SAMLResponse), /InResponseTo/);
  await serviceProvider().parseLoginResponse(idp, "post", { body: { SAMLResponse: issued.SAMLResponse } });
  assert.equal((await auditRows("saml_idp_assertion", "grafana")).at(-1).outcome, "issued:idp_initiated");
});

test("key rotation: next key published first, activation after the overlap, SPs keep working throughout", async () => {
  const sp = serviceProvider();
  const login = async () => (await form(await continueWith(await redirectLogin(sp.createLoginRequest(idp, "redirect").context), user))).SAMLResponse;
  const oldIdp = idp;
  const next = await ok(await studio({ op: "key.generate", confirm: "CONFIRM GENERATE SAML IDP KEY" }));
  assert.equal(next.status, "next");
  const overlap = await idpFromMetadata();
  assert.equal(overlap.certificates, 2, "metadata publishes the active and the next certificate");
  // During the overlap Nathan still signs with the old key: both SP views accept it.
  const during = await login();
  await sp.parseLoginResponse(oldIdp, "post", { body: { SAMLResponse: during } });
  await sp.parseLoginResponse(overlap.idp, "post", { body: { SAMLResponse: during } });
  const early = await studio({ op: "key.activate", sha256: next.sha256, confirm: "CONFIRM ACTIVATE SAML IDP KEY" });
  assert.equal(early.status, 409);
  assert.match((await early.json()).error, /24 hours/);
  await run("UPDATE nathan_saml_idp_keys SET created_at=created_at-90000 WHERE id=?", next.id);
  assert.equal((await ok(await studio({ op: "key.activate", sha256: next.sha256, confirm: "CONFIRM ACTIVATE SAML IDP KEY" }))).status, "active");
  const afterSwitch = await login();
  await sp.parseLoginResponse(overlap.idp, "post", { body: { SAMLResponse: afterSwitch } });
  await assert.rejects(sp.parseLoginResponse(oldIdp, "post", { body: { SAMLResponse: afterSwitch } }), "proves the new key signs now");
  const previous = (await ok(await mf.dispatchFetch(ORIGIN + "/studio/api/saml-idp", { headers: { Cookie: admin } }))).keys.find(k => k.status === "previous");
  assert.equal((await studio({ op: "key.retire", sha256: next.sha256, confirm: "CONFIRM RETIRE SAML IDP KEY" })).status, 409, "the active key cannot be retired");
  await ok(await studio({ op: "key.retire", sha256: previous.sha256, confirm: "CONFIRM RETIRE SAML IDP KEY" }));
  assert.equal((await idpFromMetadata()).certificates, 1);
  assert.equal((await db.prepare("SELECT private_key FROM nathan_saml_idp_keys WHERE status='retired'").first()).private_key, null, "a retired key's private key is deleted");
  for (const action of ["saml_idp_key_generate", "saml_idp_key_activate", "saml_idp_key_retire"])
    assert.ok((await auditRows(action, "%")).some(r => r.outcome === "succeeded"), action);
});
