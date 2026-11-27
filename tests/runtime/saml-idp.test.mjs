/**
 * NATH-12 end-to-end in workerd: Nathan as a SAML IdP. A real SP library (samlify's
 * ServiceProvider, in Node) creates AuthnRequests and validates the signed Responses that the built
 * auth Worker issues. Every refusal case must produce no assertion and show Nathan's reason code.
 *
 * Tests are independent of their order: each registers its own SP bound to its own application
 * (freshSp), tests that change signing keys reset them first (resetKeys), and every request comes
 * from its own client IP so the per-IP rate limit only applies where a test asks for it.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import * as samlify from "samlify";
import { XMLValidator } from "fast-xml-parser";
import { deflateRawSync } from "node:zlib";
import { authWorker, cookiesOf, randomKey, enrollAdmin, insertSession, studioPost, rawHttp, openEndedBody } from "./helpers.mjs";
import { makeCertificate } from "../fixtures/x509.mjs";

// samlify's XSD schema validation is replaced by a well-formedness check (it needs a JVM or a
// native validator). Every SP-side result below relies on samlify's signature, issuer, audience,
// recipient and time checks, not on schema validation.
samlify.setSchemaValidator({ async validate(xml) { if (XMLValidator.validate(xml) === true) return "ok"; throw Error("invalid xml"); } });

const HOST = "login.example.test";
const ORIGIN = "https://" + HOST;
const SSO = ORIGIN + "/saml/idp/sso";
const SECRET = randomKey() + randomKey();
const POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
let mf, db, admin, user;
after(() => mf?.dispose());

const run = (sql, ...args) => db.prepare(sql).bind(...args).run();
let ipSeq = 0;
/** Every request gets its own client IP unless the test sets one (the SSO limit is per IP). */
function dispatch(url, init = {}) {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", "10.9." + ((ipSeq >> 8) & 255) + "." + (ipSeq++ & 255));
  return mf.dispatchFetch(url, { ...init, headers });
}
async function seedUser(id, { emailVerified = 1, banned = 0, name = "User " + id, email = id + "@example.test" } = {}) {
  const now = new Date().toISOString();
  await run('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role","banned") VALUES (?,?,?,?,?,?,\'user\',?)',
    id, name, email, emailVerified, now, now, banned);
  return (await insertSession(db, SECRET, id)).cookie;
}
const grant = (appId, userId, role = "viewer") =>
  run("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES (?,?,?,'user',?,'admin-1')", crypto.randomUUID(), appId, role, userId);
const studio = (body, cookie = admin) => studioPost({ fetch: (url, init) => dispatch(url, init) }, ORIGIN, "/studio/api/saml-idp", body, cookie);
async function ok(response) {
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  return body;
}
const auditRows = async (action, target) =>
  (await db.prepare("SELECT actor, target, outcome FROM nathan_security_audit WHERE action=? AND target LIKE ? ORDER BY created_at, rowid").bind(action, target).all()).results;

async function idpFromMetadata() {
  const response = await dispatch(ORIGIN + "/saml/idp/metadata");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /samlmetadata\+xml/);
  const metadata = await response.text();
  return { idp: samlify.IdentityProvider({ metadata }), metadata, certificates: metadata.match(/<ds:X509Certificate>/g).length };
}
const GENERATE = { op: "key.generate", confirm: "CONFIRM GENERATE SAML IDP KEY" };
/** Deletes every IdP key; generates a fresh active one unless told not to. */
async function resetKeys({ generate = true } = {}) {
  await run("DELETE FROM nathan_saml_idp_keys");
  if (generate) await ok(await studio(GENERATE));
}
/** The IdP as an SP sees it now (an active key is generated if none exists). */
async function currentIdp() {
  if (!await db.prepare("SELECT 1 AS x FROM nathan_saml_idp_keys WHERE status='active'").first()) await ok(await studio(GENERATE));
  return (await idpFromMetadata()).idp;
}
const serviceProvider = (entityID, acs, over = {}) => samlify.ServiceProvider({
  entityID, wantAssertionsSigned: true, authnRequestsSigned: false,
  assertionConsumerService: [{ Binding: POST_BINDING, Location: acs }], ...over
});

let spSeq = 0;
/**
 * A new SP bound to a new application in which jane is an editor, registered through Studio and
 * enabled. `over` changes the registration; returns the samlify SP for it and an update helper.
 */
async function freshSp(over = {}, { enable = true, grantJane = "editor" } = {}) {
  const id = "sp" + (++spSeq) + "-" + Date.now().toString(36);
  const host = id + ".example.test";
  await run("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES (?,?,1,'approved')", id, host);
  await run("INSERT INTO nathan_rbac_roles(app_id,key) VALUES (?,'viewer'),(?,'editor')", id, id);
  if (grantJane) await grant(id, "jane", grantJane);
  const body = { id, name: "App " + id, appId: id, entityId: "https://" + host + "/saml/metadata", acsUrls: ["https://" + host + "/saml/acs"],
    attributes: [{ name: "email", source: "email" }, { name: "displayName", source: "name" }, { name: "role", source: "roles" }], ...over };
  const created = await ok(await studio({ op: "sp.create", ...body, confirm: "CONFIRM CREATE SAML SP " + id }));
  if (enable) await ok(await studio({ op: "sp.status", id, enabled: true, confirm: "CONFIRM ENABLE SAML SP " + id }));
  const idp = await currentIdp();
  return {
    id, entity: body.entityId, acs: body.acsUrls[0], host, created, idp,
    sp: serviceProvider(body.entityId, body.acsUrls[0]),
    update: async changes => ok(await studio({ op: "sp.update", ...body, ...changes, confirm: "CONFIRM UPDATE SAML SP " + id }))
  };
}

/** SSO request through Nathan: returns the 303 response (or a refusal page). */
function redirectLogin(url, cookie, headers = {}) {
  return dispatch(url, { redirect: "manual", headers: { ...(cookie ? { Cookie: cookie } : {}), ...headers } });
}
function postLogin(fields, headers = {}) {
  return dispatch(SSO, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://sp.example.test", ...headers },
    body: new URLSearchParams(fields).toString() });
}
const resumeCookie = response => {
  const c = cookiesOf(response)["__Host-nathan-saml-idp"];
  assert.ok(c?.value, "a resume cookie is set: " + response.status);
  assert.match(c.raw, /HttpOnly/); assert.match(c.raw, /Secure/); assert.match(c.raw, /SameSite=Lax/);
  return "__Host-nathan-saml-idp=" + c.value;
};
/** Nathan's "Continue to <SP> as <user>?" page: its single-use confirmation token, or null. */
// NATH-38: React 19 writes a form's action before its method, and closes void elements with "/>".
const confirmationToken = html => /<form (?:method="post" action="\/saml\/idp\/continue"|action="\/saml\/idp\/continue" method="post")><input type="hidden" name="confirm" value="([A-Za-z0-9_-]+)"\/?>/.exec(html)?.[1] ?? null;
/** Nathan's scripts on a page: every one carries the page nonce; returns the executable ones (not the import map). */
const pageScripts = (html, csp) => {
  const nonce = /'nonce-([^']+)'/.exec(csp)[1];
  const scripts = [...html.matchAll(/<script\b([^>]*)>([^]*?)<\/script>/g)];
  for (const [, attrs] of scripts) assert.ok(attrs.includes('nonce="' + nonce + '"'), "every script carries the page nonce");
  return scripts.filter(([, attrs]) => !/type="importmap"/.test(attrs));
};
/** The auto-POST page runs exactly one script: the hashed, SRI-pinned auto-post island, with no inline code. */
const assertOnlyAutoPostScript = (html, csp) => {
  const executable = pageScripts(html, csp);
  assert.equal(executable.length, 1, "only Nathan's submit script");
  assert.match(executable[0][1], /type="module" src="\/__nathan\/ui\/auto-post-[A-Za-z0-9]+\.js" integrity="sha384-/);
  assert.equal(executable[0][2], "", "no inline code");
};
/** The browser pressing Continue (or Cancel) on Nathan's confirmation page: a same-origin form POST. */
function confirmPost(resume, session, token, action = "continue", headers = {}) {
  return dispatch(ORIGIN + "/saml/idp/continue", { method: "POST", redirect: "manual", body: "confirm=" + token + "&action=" + action,
    headers: { Cookie: resume + (session ? "; " + session : ""), Origin: ORIGIN, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded", ...headers } });
}
/**
 * Follows Nathan's 303 to /saml/idp/continue with the browser's cookies; returns the page. An
 * unsigned request answered with a session that already existed shows the confirmation page: the
 * user presses Continue unless `confirm` is false (then the confirmation page itself is returned).
 */
async function continueWith(response, session, { confirm = true } = {}) {
  assert.equal(response.status, 303, (await response.clone().text()).slice(0, 300));
  assert.equal(response.headers.get("location"), ORIGIN + "/saml/idp/continue");
  const resume = resumeCookie(response);
  const page = await dispatch(ORIGIN + "/saml/idp/continue", { redirect: "manual", headers: { Cookie: resume + (session ? "; " + session : "") } });
  if (!confirm || page.status !== 200) return page;
  const token = confirmationToken(await page.clone().text());
  return token ? confirmPost(resume, session, token) : page;
}
const unescapeHtml = s => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
/** The hidden form fields of Nathan's auto-POST page. */
async function form(page) {
  const html = await page.text();
  assert.equal(page.status, 200, html.slice(0, 400));
  const field = name => { const m = new RegExp('name="' + name + '" value="([^"]*)"').exec(html); return m ? unescapeHtml(m[1]) : null; };
  return { html, action: /action="([^"]+)"/.exec(html)?.[1].replace(/&amp;/g, "&"), SAMLResponse: field("SAMLResponse"), RelayState: field("RelayState"), csp: page.headers.get("content-security-policy") };
}
/** A refusal: an error status, no assertion anywhere in the page, and Nathan's reason code. */
async function refused(page, label, code) {
  assert.ok(typeof code === "string" && code, label + ": give the expected reason code");
  const html = await page.text();
  assert.ok(page.status >= 400, label + ": expected a refusal, got " + page.status + " " + html.slice(0, 300));
  assert.doesNotMatch(html, /SAMLResponse/, label + ": no assertion may be issued");
  assert.ok(html.includes("(" + code + ")"), label + ": expected reason " + code + " in " + html.replace(/<style[^]*?<\/style>/, "").slice(0, 600));
  return html;
}
const xmlOf = b64 => Buffer.from(b64, "base64").toString("utf8");
/** A hand-built unsigned AuthnRequest URL (HTTP-Redirect) for cases an SP library does not produce. */
const manual = (issuer, attrs = "", issuedAt = new Date().toISOString(), extraQuery = "") => SSO + "?SAMLRequest=" + encodeURIComponent(deflateRawSync(
  `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_m${randomKey().replace(/-/g, "")}" Version="2.0" IssueInstant="${issuedAt}"${attrs}><saml:Issuer>${issuer}</saml:Issuer></samlp:AuthnRequest>`).toString("base64")) + extraQuery;

const PREVIEW_ENTITY = "https://preview.example.test/saml/metadata";
const PREVIEW_ACS = "https://preview.example.test/saml/acs";
const SP_METADATA_URL = "https://sp.example.com/saml/metadata";
const spMetadata = (entity = PREVIEW_ENTITY, endpoints = [[PREVIEW_ACS, 0]]) =>
  `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entity}"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
  endpoints.map(([location, index]) => `<md:AssertionConsumerService Binding="${POST_BINDING}" Location="${location}" index="${index}"/>`).join("") +
  "</md:SPSSODescriptor></md:EntityDescriptor>";
const outbound = [];
async function outboundService(request) {
  outbound.push(request.url);
  if (request.url === SP_METADATA_URL) return new Response(spMetadata(), { headers: { "content-type": "application/samlmetadata+xml" } });
  if (request.url === "https://sp.example.com/redirecting") return new Response(null, { status: 302, headers: { Location: SP_METADATA_URL } });
  return new Response("unexpected outbound request", { status: 599 });
}

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET }, { outboundService });
  db = await mf.getD1Database("DB");
  admin = (await enrollAdmin(db, SECRET)).cookie;
  user = await seedUser("jane");
});

test("metadata is unavailable until a signing key exists; Studio writes need an enrolled admin and exact confirmation", async () => {
  await resetKeys({ generate: false });
  assert.equal((await dispatch(ORIGIN + "/saml/idp/metadata")).status, 404);
  assert.equal((await studio(GENERATE, user)).status, 403, "non-admin refused");
  const wrong = await studio({ op: "key.generate", confirm: "yes" });
  assert.equal(wrong.status, 409);
  assert.match((await wrong.json()).error, /CONFIRM GENERATE SAML IDP KEY/);
  const crossSite = await dispatch(ORIGIN + "/studio/api/saml-idp", { method: "POST", body: "{}",
    headers: { Cookie: admin, Origin: "https://evil.example", "Content-Type": "application/json" } });
  assert.equal(crossSite.status, 403);
  const key = await ok(await studio(GENERATE));
  assert.equal(key.status, "active");
  assert.equal(key.bits, 2048);
  assert.equal(key.privateKey, undefined);
  const stored = await db.prepare("SELECT private_key FROM nathan_saml_idp_keys WHERE id=?").bind(key.id).first();
  assert.match(stored.private_key, /^v1\./, "sealed under NATHAN_CONFIG_KEY");
  assert.doesNotMatch(JSON.stringify(await ok(await dispatch(ORIGIN + "/studio/api/saml-idp", { headers: { Cookie: admin } }))), /v1\.[A-Za-z0-9_-]{16}/,
    "the overview never returns key material");
  const md = await (await dispatch(ORIGIN + "/saml/idp")).text();
  assert.match(md, /entityID="https:\/\/login\.example\.test\/saml\/idp"/);
  assert.match(md, /HTTP-Redirect" Location="https:\/\/login\.example\.test\/saml\/idp\/sso"/);
  assert.match(md, /HTTP-POST" Location="https:\/\/login\.example\.test\/saml\/idp\/sso"/);
});

test("SP registration: validated, bound to an existing app, disabled by default, audited", async () => {
  const idp = await currentIdp();
  const id = "registration";
  const entity = "https://registration.example.test/saml/metadata", acs = "https://registration.example.test/saml/acs";
  await run("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES (?,?,1,'approved')", id, "registration.example.test");
  const base = { op: "sp.create", id, name: "Registration", appId: id, entityId: entity, acsUrls: [acs],
    attributes: [{ name: "email", source: "email" }, { name: "displayName", source: "name" }, { name: "role", source: "roles" }] };
  const bad = async (over, pattern) => { const r = await studio({ ...base, confirm: "CONFIRM CREATE SAML SP " + id, ...over }); assert.equal(r.status, 409); assert.match((await r.json()).error, pattern); };
  await bad({ appId: "missing" }, /Unknown application/);
  await bad({ acsUrls: ["https://*.example.test/acs"] }, /wildcard/);
  await bad({ acsUrls: ["http://registration.example.test/saml/acs"] }, /https/);
  await bad({ confirm: "CONFIRM CREATE SAML SP other" }, /confirmation/);
  const created = await ok(await studio({ ...base, confirm: "CONFIRM CREATE SAML SP " + id }));
  assert.equal(created.enabled, false);
  assert.equal(created.nameIdFormat, "persistent");
  assert.equal(created.allowIdpInitiated, false);
  const { context } = serviceProvider(entity, acs).createLoginRequest(idp, "redirect");
  assert.ok(context.startsWith(SSO + "?"), context);
  await refused(await redirectLogin(context), "disabled SP", "saml_sp_disabled");
  assert.ok((await auditRows("saml_idp_request_rejected", id + ":saml_sp_disabled")).length >= 1);
  await ok(await studio({ op: "sp.status", id, enabled: true, confirm: "CONFIRM ENABLE SAML SP " + id }));
  assert.deepEqual((await auditRows("saml_idp_sp_create", id)).map(r => r.outcome).slice(-2), ["attempted", "succeeded"]);
  assert.deepEqual((await auditRows("saml_idp_sp_enable", id)).map(r => r.outcome), ["attempted", "succeeded"]);
});

test("SP metadata preview: pasted or fetched over HTTPS without redirects, audited by host, never stored", async () => {
  const pasted = await ok(await studio({ op: "sp.preview", metadataXml: spMetadata() }));
  assert.deepEqual([pasted.entityId, pasted.acsUrls, pasted.nameIdFormat], [PREVIEW_ENTITY, [PREVIEW_ACS], "persistent"]);
  const fetched = await ok(await studio({ op: "sp.preview", metadataUrl: SP_METADATA_URL }));
  assert.equal(fetched.entityId, PREVIEW_ENTITY);
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
  assert.equal(await db.prepare("SELECT id FROM nathan_saml_service_providers WHERE entity_id=?").bind(PREVIEW_ENTITY).first(), null, "a preview stores nothing");
});

test("ForceAuthn needs a sign-in after the request; IsPassive never prompts", async () => {
  const s = await freshSp();
  const stale = await insertSession(db, SECRET, "jane");
  await run('UPDATE "session" SET "createdAt"=? WHERE "id"=?', new Date(Date.now() - 3600e3).toISOString(), stale.id);
  const forced = await continueWith(await redirectLogin(manual(s.entity, ' ForceAuthn="true"')), stale.cookie);
  assert.equal(forced.status, 302);
  assert.equal(forced.headers.get("location"), ORIGIN + "/sign-in", "an old session must sign in again");
  const response = await redirectLogin(manual(s.entity, ' ForceAuthn="true"'));
  const fresh = await form(await continueWith(response, (await insertSession(db, SECRET, "jane")).cookie));
  assert.equal(fresh.action, s.acs, "a session created for this request is accepted");
  // The boundary, in milliseconds: a session created at the request's instant counts, one 1 ms older does not.
  const atBoundary = async offsetMs => {
    const sso = await redirectLogin(manual(s.entity, ' ForceAuthn="true"'));
    const { requested } = await db.prepare("SELECT requested_at_ms AS requested FROM nathan_saml_idp_pending WHERE sp_id=? AND used=0 ORDER BY requested_at_ms DESC LIMIT 1").bind(s.id).first();
    const session = await insertSession(db, SECRET, "jane");
    await run('UPDATE "session" SET "createdAt"=? WHERE "id"=?', new Date(Number(requested) + offsetMs).toISOString(), session.id);
    return continueWith(sso, session.cookie, { confirm: false });
  };
  assert.ok(confirmationToken(await (await atBoundary(0)).text()), "created at the request's instant: fresh (then confirmed, it is unsigned)");
  assert.equal((await atBoundary(-1)).headers.get("location"), ORIGIN + "/sign-in", "1 ms older: sign in again");
  // Re-authenticating is not consent: a forged unsigned ForceAuthn request still asks after the new sign-in.
  const forcedForged = await continueWith(await redirectLogin(manual(s.entity, ' ForceAuthn="true"', undefined, "&RelayState=evil")),
    (await insertSession(db, SECRET, "jane")).cookie, { confirm: false });
  assert.ok(confirmationToken(await forcedForged.text()), "the confirmation page, not an auto-post");
  await refused(await continueWith(await redirectLogin(manual(s.entity, ' IsPassive="true"'))), "passive without a session", "saml_passive_requires_sign_in");
  assert.equal((await auditRows("saml_idp_assertion", s.id)).at(-1).outcome, "denied:passive_requires_sign_in");
});

test("SP-initiated login (HTTP-Redirect): a signed Response that an independent SP library validates", async () => {
  const s = await freshSp();
  const { id, context } = s.sp.createLoginRequest(s.idp, "redirect");
  const url = new URL(context);
  url.searchParams.set("RelayState", "/d/home");
  const page = await continueWith(await redirectLogin(url.href), user);
  const { action, SAMLResponse, RelayState, csp, html } = await form(page);
  assert.equal(action, s.acs);
  assert.equal(RelayState, "/d/home");
  assert.match(csp, new RegExp("form-action https://" + s.host.replace(/\./g, "\\.") + ";"), "form-action limited to the ACS origin");
  assert.match(csp, /script-src 'self' 'nonce-/);
  assertOnlyAutoPostScript(html, csp);
  assert.equal(page.headers.get("referrer-policy"), "same-origin");
  assert.match(page.headers.get("set-cookie"), /__Host-nathan-saml-idp=; .*Max-Age=0/, "the resume handle is cleared");
  assert.doesNotMatch(html, /<script>/, "only nonce'd scripts");
  const { extract } = await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse, RelayState } });
  assert.equal(extract.issuer, ORIGIN + "/saml/idp");
  assert.equal(extract.audience, s.entity);
  assert.equal(extract.response.inResponseTo, id);
  assert.match(extract.nameID, /^[A-Za-z0-9_-]{32}$/, "persistent pairwise opaque NameID");
  assert.equal(extract.attributes.email, "jane@example.test");
  assert.equal(extract.attributes.displayName, "User jane");
  assert.equal(extract.attributes.role, "editor");
  const xml = xmlOf(SAMLResponse);
  assert.match(xml, /nameid-format:persistent/);
  assert.match(xml, /ac:classes:unspecified/, "no assurance claimed without verified evidence");
  assert.match(xml, new RegExp('Recipient="' + s.acs));
  // The same user gets the same NameID next time; the audit row names SP, user and outcome only.
  const again = await form(await continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), user));
  assert.equal((await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: again.SAMLResponse } })).extract.nameID, extract.nameID);
  const rows = await auditRows("saml_idp_assertion", s.id);
  assert.deepEqual(rows.slice(-2).map(r => [r.actor, r.outcome]), [["jane", "issued"], ["jane", "issued"]]);
  const all = JSON.stringify((await db.prepare("SELECT * FROM nathan_security_audit").all()).results);
  assert.ok(!all.includes(extract.nameID) && !all.includes(SAMLResponse.slice(0, 40)), "no assertion content in the audit log");
});

test("tampering with Nathan's response breaks validation at the SP", async () => {
  const s = await freshSp();
  const { SAMLResponse } = await form(await continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), user));
  const tampered = Buffer.from(xmlOf(SAMLResponse).replace("jane@example.test", "admin@example.test")).toString("base64");
  await assert.rejects(s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: tampered } }));
});

test("without a Nathan session the browser signs in first and resumes through '/' (single use)", async () => {
  const s = await freshSp();
  const first = await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context);
  const resume = resumeCookie(first);
  const noSession = await continueWith(first);
  assert.equal(noSession.status, 302);
  assert.equal(noSession.headers.get("location"), ORIGIN + "/sign-in");
  const signedIn = (await insertSession(db, SECRET, "jane")).cookie;
  const home = await dispatch(ORIGIN + "/", { redirect: "manual", headers: { Cookie: resume + "; " + signedIn } });
  assert.equal(home.headers.get("location"), ORIGIN + "/saml/idp/continue");
  const page = await dispatch(ORIGIN + "/saml/idp/continue", { headers: { Cookie: resume + "; " + signedIn } });
  const token = confirmationToken(await page.text());
  assert.ok(token, "an unsigned request is confirmed even right after a sign-in");
  await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: (await form(await confirmPost(resume, signedIn, token))).SAMLResponse } });
  await refused(await dispatch(ORIGIN + "/saml/idp/continue", { headers: { Cookie: resume + "; " + signedIn } }), "the pending request is single use", "saml_resume_used");
});

test("SP-initiated login with the HTTP-POST binding (the SP posts cross-site; the session cookie arrives on the redirect)", async () => {
  const s = await freshSp();
  const { context, relayState } = s.sp.createLoginRequest(s.idp, "post");
  const page = await continueWith(await postLogin({ SAMLRequest: context, RelayState: relayState || "rs-1" }), user);
  const { SAMLResponse, RelayState } = await form(page);
  assert.equal(RelayState, relayState || "rs-1");
  await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse } });
});

test("unknown SP, wrong ACS, replayed request ID, stale or misaddressed requests: no assertion", async () => {
  const s = await freshSp();
  const stranger = serviceProvider("https://stranger.example.test/saml", "https://stranger.example.test/acs");
  await refused(await redirectLogin(stranger.createLoginRequest(s.idp, "redirect").context), "unknown SP", "saml_unknown_sp");
  assert.ok((await auditRows("saml_idp_request_rejected", "unknown:saml_unknown_sp")).length >= 1);
  const wrongAcs = serviceProvider(s.entity, "https://evil.example.test/acs");
  const html = await refused(await redirectLogin(wrongAcs.createLoginRequest(s.idp, "redirect").context), "wrong ACS", "saml_acs_mismatch");
  assert.doesNotMatch(html, /evil\.example\.test/, "the refusal page never links to the unregistered ACS");
  const { context } = s.sp.createLoginRequest(s.idp, "redirect");
  await continueWith(await redirectLogin(context), user);
  await refused(await redirectLogin(context), "replayed request ID", "saml_replayed_request");
  await refused(await redirectLogin(manual(s.entity, "", new Date(Date.now() - 10 * 60e3).toISOString())), "stale", "saml_stale_request");
  await refused(await redirectLogin(manual(s.entity, ' Destination="https://other-idp.example.test/sso"')), "destination", "saml_destination_mismatch");
  await refused(await redirectLogin(manual(s.entity, ' AssertionConsumerServiceIndex="5"')), "bad index", "saml_acs_mismatch");
  await refused(await redirectLogin(manual(s.entity, ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"')), "artifact", "saml_unsupported_binding");
  // The default ACS is used when the request names none.
  const page = await form(await continueWith(await redirectLogin(manual(s.entity)), user));
  assert.equal(page.action, s.acs);
});

test("duplicate and non-canonical binding parameters, bodies on GET-style requests and wrong content types are refused", async () => {
  const s = await freshSp();
  const { context } = s.sp.createLoginRequest(s.idp, "redirect");
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
  for (const [url, code] of cases) await refused(await redirectLogin(url), url, code);
  const { context: posted } = s.sp.createLoginRequest(s.idp, "post");
  const body = "SAMLRequest=" + encodeURIComponent(posted);
  const post = (b, headers = {}, url = SSO) => dispatch(url, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers }, body: b });
  await refused(await post(body + "&" + body), "post dup", "saml_duplicate_parameter");
  await refused(await post(body + "&SAMLRequ%est=x"), "post noncanonical", "saml_noncanonical_encoding");
  await refused(await post(body, {}, SSO + "?SAMLRequest=" + encodeURIComponent(value)), "post with query", "saml_unknown_parameter");
  await refused(await post(JSON.stringify({ SAMLRequest: posted }), { "Content-Type": "application/json" }), "json", "saml_form_required");
  await refused(await dispatch(SSO, { method: "PUT", body }), "PUT", "saml_method_not_allowed");
  assert.ok((await auditRows("saml_idp_request_rejected", "%saml_duplicate_parameter")).length >= 1);
});

test("signed AuthnRequests: required means unsigned is refused; Redirect and POST signatures from the SP's key verify", async () => {
  const spKey = makeCertificate({ cn: "Signed SP" });
  const s = await freshSp({ wantRequestsSigned: true, certificates: [spKey.certPem] });
  await refused(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), "unsigned redirect", "saml_signature_required");
  await refused(await postLogin({ SAMLRequest: s.sp.createLoginRequest(s.idp, "post").context }), "unsigned post", "saml_signature_required");
  const signingIdp = samlify.IdentityProvider({ metadata: (await idpFromMetadata()).metadata.replace('WantAuthnRequestsSigned="false"', 'WantAuthnRequestsSigned="true"') });
  const signer = serviceProvider(s.entity, s.acs, { authnRequestsSigned: true, privateKey: spKey.privateKey, signingCert: spKey.certPem,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" });
  // A valid signature (with Nathan as Destination) goes straight through, even with an older session.
  const viaRedirect = await form(await continueWith(await redirectLogin(signer.createLoginRequest(signingIdp, "redirect").context), user, { confirm: false }));
  assert.equal(viaRedirect.action, s.acs);
  const viaPost = await form(await continueWith(await postLogin({ SAMLRequest: signer.createLoginRequest(signingIdp, "post").context }), user, { confirm: false }));
  assert.equal(viaPost.action, s.acs);
  // The POST signature covers the XML, not the RelayState field: with a RelayState the user confirms.
  const postWithRelay = await continueWith(await postLogin({ SAMLRequest: signer.createLoginRequest(signingIdp, "post").context, RelayState: "https://attacker.example/x" }), user, { confirm: false });
  assert.ok(confirmationToken(await postWithRelay.text()), "signed POST with an unsigned RelayState: confirmed");
  // The Redirect signature covers RelayState, so a signed Redirect request with one goes straight through.
  const relaySigner = serviceProvider(s.entity, s.acs, { authnRequestsSigned: true, privateKey: spKey.privateKey, signingCert: spKey.certPem,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", relayState: "rs-signed" });
  const relayUrl = relaySigner.createLoginRequest(signingIdp, "redirect").context;
  assert.match(relayUrl, /RelayState=rs-signed/);
  const redirectWithRelay = await form(await continueWith(await redirectLogin(relayUrl), user, { confirm: false }));
  assert.equal(redirectWithRelay.action, s.acs);
  assert.equal(redirectWithRelay.RelayState, "rs-signed");
  // A signature from another key, or over a different message, is refused.
  const otherKey = makeCertificate();
  const impostor = serviceProvider(s.entity, s.acs, { authnRequestsSigned: true, privateKey: otherKey.privateKey, signingCert: otherKey.certPem,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" });
  await refused(await redirectLogin(impostor.createLoginRequest(signingIdp, "redirect").context), "foreign key", "saml_bad_signature");
  const signedUrl = new URL(signer.createLoginRequest(signingIdp, "redirect").context);
  const swapped = signedUrl.href.replace(/SAMLRequest=[^&]+/, "SAMLRequest=" + new URL(s.sp.createLoginRequest(s.idp, "redirect").context).searchParams.get("SAMLRequest").replace(/[+/=]/g, c => encodeURIComponent(c)));
  await refused(await redirectLogin(swapped), "swapped message", "saml_bad_signature");
});

test("users without access, blocked, deprovisioned, not admitted or unverified get no assertion (deny by default)", async () => {
  const s = await freshSp();
  const attempt = async cookie => continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), cookie);
  const tag = s.id.replace(/-/g, "");
  const noGrant = await seedUser("nogrant" + tag);
  await refused(await attempt(noGrant), "no app access", "saml_no_access");
  const banned = await seedUser("banned" + tag, { banned: 1 });
  await grant(s.id, "banned" + tag);
  await refused(await attempt(banned), "banned", "saml_user_blocked");
  const gone = await seedUser("gone" + tag);
  await grant(s.id, "gone" + tag);
  await run("INSERT INTO nathan_scim_connections(id,domain,created_by) VALUES (?,?,'admin-1')", "acme" + tag, tag + ".example.test");
  await run("INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,user_id,link_state) VALUES (?,'s1','e1','gone',0,?,'deprovisioned')", "acme" + tag, "gone" + tag);
  await refused(await attempt(gone), "SCIM-deprovisioned", "saml_deprovisioned");
  const provisional = await seedUser("provisional" + tag);
  await grant(s.id, "provisional" + tag);
  await run("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES (?,?,'password')", "provisional" + tag + "@example.test", "provisional" + tag);
  await refused(await attempt(provisional), "admission-refused", "saml_not_admitted");
  const unverified = await seedUser("unverified" + tag, { emailVerified: 0 });
  await grant(s.id, "unverified" + tag);
  await refused(await attempt(unverified), "unverified email", "saml_email_unverified");
  const outcomes = Object.fromEntries((await auditRows("saml_idp_assertion", s.id)).filter(r => r.outcome.startsWith("denied") && r.actor !== "anonymous").map(r => [r.actor.replace(tag, ""), r.outcome]));
  assert.deepEqual(outcomes, { nogrant: "denied:no_access:no_grant", banned: "denied:user_blocked", gone: "denied:deprovisioned",
    provisional: "denied:not_admitted", unverified: "denied:email_unverified" });
  // Disabling the app (NATH-13 evaluator) also stops the SP.
  await run("UPDATE nathan_applications SET enabled=0 WHERE id=?", s.id);
  await refused(await attempt(user), "disabled application", "saml_no_access");
});

test("passkey requirement uses verified evidence only and is reflected in AuthnContextClassRef", async () => {
  const s = await freshSp({ requirePasskey: true, attributes: [{ name: "email", source: "email" }] });
  const html = await refused(await continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), user), "no passkey evidence", "saml_passkey_required");
  assert.match(html, /passkey/);
  const session = await insertSession(db, SECRET, "jane");
  await run("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES (?,?,'passkey')", session.id, "jane");
  const { SAMLResponse } = await form(await continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), session.cookie));
  assert.match(xmlOf(SAMLResponse), /<saml:AuthnContextClassRef>urn:nathan:acr:passkey<\/saml:AuthnContextClassRef>/);
  await s.update({ requirePasskey: false, nameIdFormat: "email", signResponse: true, attributes: [{ name: "email", source: "email" }] });
  const email = await form(await continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), user));
  const { extract } = await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: email.SAMLResponse } });
  assert.equal(extract.nameID, "jane@example.test");
  assert.equal((xmlOf(email.SAMLResponse).match(/<ds:Signature /g) ?? []).length, 2, "Response and Assertion signed");
});

test("IdP-initiated sign-in is off by default and, when enabled, needs a same-origin confirmation", async () => {
  const s = await freshSp();
  const start = ORIGIN + "/saml/idp/start/" + s.id;
  await refused(await dispatch(start, { headers: { Cookie: user } }), "off by default", "saml_idp_initiated_unavailable");
  await s.update({ allowIdpInitiated: true, defaultRelayState: "/d/home", attributes: [{ name: "email", source: "email" }] });
  const page = await dispatch(start, { headers: { Cookie: user } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), new RegExp('<form (method="post" action="/saml/idp/start/' + s.id + '"|action="/saml/idp/start/' + s.id + '" method="post")>'));
  const cross = await dispatch(start, { method: "POST", headers: { Cookie: user, Origin: "https://evil.example" } });
  await refused(cross, "cross-site IdP-initiated", "saml_cross_site_request");
  const issued = await form(await dispatch(start, { method: "POST", headers: { Cookie: user, Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" } }));
  assert.equal(issued.RelayState, "/d/home");
  assert.doesNotMatch(xmlOf(issued.SAMLResponse), /InResponseTo/);
  await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: issued.SAMLResponse } });
  assert.equal((await auditRows("saml_idp_assertion", s.id)).at(-1).outcome, "issued:idp_initiated");
});

test("key rotation: next key published first, activation after the overlap, SPs keep working throughout", async () => {
  await resetKeys();
  const s = await freshSp();
  const login = async () => (await form(await continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), user))).SAMLResponse;
  const oldIdp = s.idp;
  const next = await ok(await studio(GENERATE));
  assert.equal(next.status, "next");
  const overlap = await idpFromMetadata();
  assert.equal(overlap.certificates, 2, "metadata publishes the active and the next certificate");
  // During the overlap Nathan still signs with the old key: both SP views accept it.
  const during = await login();
  await s.sp.parseLoginResponse(oldIdp, "post", { body: { SAMLResponse: during } });
  await s.sp.parseLoginResponse(overlap.idp, "post", { body: { SAMLResponse: during } });
  const early = await studio({ op: "key.activate", sha256: next.sha256, confirm: "CONFIRM ACTIVATE SAML IDP KEY" });
  assert.equal(early.status, 409);
  assert.match((await early.json()).error, /24 hours/);
  await run("UPDATE nathan_saml_idp_keys SET created_at=created_at-90000 WHERE id=?", next.id);
  assert.equal((await ok(await studio({ op: "key.activate", sha256: next.sha256, confirm: "CONFIRM ACTIVATE SAML IDP KEY" }))).status, "active");
  const afterSwitch = await login();
  await s.sp.parseLoginResponse(overlap.idp, "post", { body: { SAMLResponse: afterSwitch } });
  await assert.rejects(s.sp.parseLoginResponse(oldIdp, "post", { body: { SAMLResponse: afterSwitch } }), "proves the new key signs now");
  const previous = (await ok(await dispatch(ORIGIN + "/studio/api/saml-idp", { headers: { Cookie: admin } }))).keys.find(k => k.status === "previous");
  assert.equal((await studio({ op: "key.retire", sha256: next.sha256, confirm: "CONFIRM RETIRE SAML IDP KEY" })).status, 409, "the active key cannot be retired");
  await ok(await studio({ op: "key.retire", sha256: previous.sha256, confirm: "CONFIRM RETIRE SAML IDP KEY" }));
  assert.equal((await idpFromMetadata()).certificates, 1);
  assert.equal((await db.prepare("SELECT private_key FROM nathan_saml_idp_keys WHERE status='retired'").first()).private_key, null, "a retired key's private key is deleted");
  for (const action of ["saml_idp_key_generate", "saml_idp_key_activate", "saml_idp_key_retire"])
    assert.ok((await auditRows(action, "%")).some(r => r.outcome === "succeeded"), action);
});

test("request bodies are read with a byte limit: a chunked body without Content-Length is refused at the limit (413), not buffered", { timeout: 30_000 }, async () => {
  // 256 KiB, more than either limit, then the body stays open: request.text() would wait forever.
  const sso = openEndedBody(262_144);
  const ssoPage = await dispatch(SSO, { method: "POST", body: sso.body, duplex: "half", headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  assert.equal(ssoPage.status, 413);
  assert.match(await ssoPage.text(), /\(saml_unreadable\)/);
  const studioBody = openEndedBody(262_144);
  const studioPage = await dispatch(ORIGIN + "/studio/api/saml-idp", { method: "POST", body: studioBody.body, duplex: "half",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "Sec-Fetch-Site": "same-origin", Cookie: admin } });
  assert.equal(studioPage.status, 413);
  assert.deepEqual(await studioPage.json(), { error: "Request too large" });
  // A declared Content-Length over the limit is refused before reading.
  const declared = await dispatch(SSO, { method: "POST", body: "SAMLRequest=" + "a".repeat(200_001), headers: { "Content-Type": "application/x-www-form-urlencoded" } });
  await refused(declared, "declared length", "saml_unreadable");
  assert.equal(declared.status, 413);
});

test("AssertionConsumerServiceIndex resolves by the SP metadata's index attribute, not by list position", async () => {
  const entity = "https://indexed.example.test/saml/metadata";
  const first = "https://indexed.example.test/saml/acs-one", second = "https://indexed.example.test/saml/acs-two";
  const preview = await ok(await studio({ op: "sp.preview", metadataXml: spMetadata(entity, [[first, 1], [second, 2]]) }));
  assert.deepEqual([preview.acsUrls, preview.acsIndexes], [[first, second], [1, 2]]);
  const s = await freshSp({ entityId: entity, acsUrls: preview.acsUrls, acsIndexes: preview.acsIndexes });
  assert.deepEqual(s.created.acsIndexes, [1, 2]);
  const via = async index => continueWith(await redirectLogin(manual(entity, ' AssertionConsumerServiceIndex="' + index + '"')), user);
  assert.equal((await form(await via(1))).action, first, "index 1 is the endpoint the metadata numbered 1");
  assert.equal((await form(await via(2))).action, second);
  await refused(await redirectLogin(manual(entity, ' AssertionConsumerServiceIndex="0"')), "index the metadata does not list", "saml_acs_mismatch");
  await refused(await redirectLogin(manual(entity, ' AssertionConsumerServiceIndex="3"')), "index past the end", "saml_acs_mismatch");
  // Entered by hand without indexes: numbered 0, 1, ... in the order given.
  const manualEntry = await freshSp({ acsUrls: ["https://manual-acs.example.test/a", "https://manual-acs.example.test/b"] });
  assert.deepEqual(manualEntry.created.acsIndexes, [0, 1]);
  const byIndex = async index => (await form(await continueWith(await redirectLogin(manual(manualEntry.entity, ' AssertionConsumerServiceIndex="' + index + '"')), user))).action;
  assert.equal(await byIndex(1), "https://manual-acs.example.test/b");
  await refused(await redirectLogin(manual(manualEntry.entity, ' AssertionConsumerServiceIndex="2"')), "unknown index", "saml_acs_mismatch");
});

test("a forged unsigned AuthnRequest answered with an existing Nathan session asks the user first; nothing is posted to the SP", async () => {
  // The reported attack: an SP that neither allows IdP-initiated sign-in nor requires signed requests.
  const s = await freshSp({ name: "Grafana <Prod> & \"Ops\"" });
  assert.equal(s.created.allowIdpInitiated, false);
  assert.equal(s.created.wantRequestsSigned, false);
  // An attacker's page navigates the victim's browser cross-site (a top-level GET carries the Lax
  // session cookie) with an unsigned request: the SP's public entity ID, a fresh ID, their RelayState.
  const attackerRelay = "https://attacker.example/landing?next=<b>x</b>";
  const forged = manual(s.entity, "", undefined, "&RelayState=" + encodeURIComponent(attackerRelay));
  const sso = await redirectLogin(forged, user, { "Sec-Fetch-Site": "cross-site", Referer: "https://attacker.example/" });
  const resume = resumeCookie(sso);
  const page = await continueWith(sso, user, { confirm: false });
  const html = await page.text();
  assert.equal(page.status, 200);
  assert.doesNotMatch(html, /SAMLResponse/, "no assertion without the user's confirmation");
  assert.doesNotMatch(html, /<script/, "the page never submits itself");
  assert.ok(html.includes("Continue to Grafana &lt;Prod&gt; &amp; &quot;Ops&quot; as jane@example.test?"), html.slice(0, 900));
  assert.ok(!html.includes(attackerRelay) && !html.includes("<b>x</b>"), "the RelayState is not shown or echoed");
  const csp = page.headers.get("content-security-policy");
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /form-action 'self'/);
  assert.match(csp, /style-src 'self' 'nonce-[^']+'/);
  assert.match(csp, /script-src 'none'/);
  assert.equal(page.headers.get("referrer-policy"), "same-origin");
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  const token = confirmationToken(html);
  assert.ok(token, "the page carries a confirmation token");
  assert.equal((await auditRows("saml_idp_assertion", s.id)).length, 0, "nothing issued or denied yet");

  // A cross-site POST, or one without Origin, cannot press Continue.
  await refused(await confirmPost(resume, user, token, "continue", { Origin: "https://attacker.example", "Sec-Fetch-Site": "cross-site" }), "cross-site Continue", "saml_cross_site_request");
  await refused(await confirmPost(resume, user, token, "continue", { Origin: ORIGIN, "Sec-Fetch-Site": "cross-site" }), "Sec-Fetch-Site cross-site", "saml_cross_site_request");
  const noOrigin = await dispatch(ORIGIN + "/saml/idp/continue", { method: "POST", body: "confirm=" + token + "&action=continue",
    headers: { Cookie: resume + "; " + user, "Content-Type": "application/x-www-form-urlencoded" } });
  await refused(noOrigin, "no Origin", "saml_cross_site_request");
  // Bound to the session that saw the page, and to the token on it.
  const other = await insertSession(db, SECRET, "jane");
  await refused(await confirmPost(resume, other.cookie, token), "another session", "saml_confirmation_invalid");
  await refused(await confirmPost(resume, user, token.slice(0, -2) + (token.endsWith("AA") ? "BB" : "AA")), "wrong token", "saml_confirmation_invalid");
  await refused(await confirmPost(resume, user, token, "elsewhere"), "unknown action", "saml_invalid_confirmation_form");

  // The user presses Continue on Nathan's page: a same-origin POST issues the assertion.
  const issued = await form(await confirmPost(resume, user, token));
  assert.equal(issued.action, s.acs);
  assert.equal(issued.RelayState, attackerRelay, "after the user confirmed, the RelayState is echoed verbatim");
  await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: issued.SAMLResponse } });
  assert.deepEqual((await auditRows("saml_idp_assertion", s.id)).map(r => r.outcome), ["issued"]);
  // Single use: replaying the confirmation issues nothing.
  await refused(await confirmPost(resume, user, token), "replayed confirmation", "saml_resume_used");
});

test("the confirmation expires, Cancel issues nothing, and an unsigned IsPassive request cannot be confirmed", async () => {
  const s = await freshSp();
  const pageFor = async (url = manual(s.entity)) => {
    const sso = await redirectLogin(url, user);
    const resume = resumeCookie(sso);
    const page = await continueWith(sso, user, { confirm: false });
    const token = confirmationToken(await page.text());
    assert.ok(token, "confirmation page");
    return { resume, token };
  };
  const late = await pageFor();
  await run("UPDATE nathan_saml_idp_pending SET confirm_expires=unixepoch()-1 WHERE sp_id=? AND used=0", s.id);
  await refused(await confirmPost(late.resume, user, late.token), "expired confirmation", "saml_confirmation_expired");

  const cancel = await pageFor();
  const cancelled = await confirmPost(cancel.resume, user, cancel.token, "cancel");
  const html = await cancelled.text();
  assert.equal(cancelled.status, 200);
  assert.doesNotMatch(html, /SAMLResponse/);
  assert.match(html, /\(saml_cancelled\)/);
  assert.match(cancelled.headers.get("set-cookie"), /__Host-nathan-saml-idp=; .*Max-Age=0/);
  await refused(await confirmPost(cancel.resume, user, cancel.token), "Continue after Cancel", "saml_resume_used");
  assert.equal((await auditRows("saml_idp_assertion", s.id)).at(-1).outcome, "denied:cancelled");

  // Continue for a request whose page was never shown, and a reload that replaces the token.
  const unseen = resumeCookie(await redirectLogin(manual(s.entity), user));
  await refused(await confirmPost(unseen, user, randomKey()), "Continue without the page", "saml_confirmation_invalid");
  const reloaded = await pageFor();
  const again = confirmationToken(await (await dispatch(ORIGIN + "/saml/idp/continue", { headers: { Cookie: reloaded.resume + "; " + user } })).text());
  assert.ok(again && again !== reloaded.token);
  await refused(await confirmPost(reloaded.resume, user, reloaded.token), "the first page's token after a reload", "saml_confirmation_invalid");
  assert.equal((await form(await confirmPost(reloaded.resume, user, again))).action, s.acs, "the reloaded page's token works");
  // The SP is disabled, or its ACS URL removed, between the page and Continue.
  const disabled = await pageFor();
  await ok(await studio({ op: "sp.status", id: s.id, enabled: false, confirm: "CONFIRM DISABLE SAML SP " + s.id }));
  await refused(await confirmPost(disabled.resume, user, disabled.token), "SP disabled after the page", "saml_sp_unavailable");
  assert.equal((await auditRows("saml_idp_assertion", s.id)).at(-1).outcome, "denied:sp_unavailable");
  await ok(await studio({ op: "sp.status", id: s.id, enabled: true, confirm: "CONFIRM ENABLE SAML SP " + s.id }));
  const moved = await pageFor();
  await s.update({ acsUrls: ["https://" + s.host + "/saml/acs2"] });
  await refused(await confirmPost(moved.resume, user, moved.token), "ACS removed after the page", "saml_acs_changed");
  await s.update({ acsUrls: [s.acs] });

  await refused(await continueWith(await redirectLogin(manual(s.entity, ' IsPassive="true"'), user), user, { confirm: false }),
    "passive unsigned request with an older session", "saml_passive_requires_confirmation");
  assert.equal((await auditRows("saml_idp_assertion", s.id)).at(-1).outcome, "denied:passive_requires_confirmation");
});

test("a sign-in is not consent: a request planted before an unrelated sign-in is still confirmed; a signature without Destination is not enough", async () => {
  const s = await freshSp();
  // A page sends a signed-out browser to Nathan with an unsigned request and its own RelayState...
  const sso = await redirectLogin(manual(s.entity, "", undefined, "&RelayState=" + encodeURIComponent("https://attacker.example/x")));
  const resume = resumeCookie(sso);
  assert.equal((await continueWith(sso)).headers.get("location"), ORIGIN + "/sign-in");
  // ...later the user signs in to Nathan for something else, and "/" resumes the planted request.
  const signedIn = (await insertSession(db, SECRET, "jane")).cookie;
  assert.equal((await dispatch(ORIGIN + "/", { redirect: "manual", headers: { Cookie: resume + "; " + signedIn } })).headers.get("location"), ORIGIN + "/saml/idp/continue");
  const page = await dispatch(ORIGIN + "/saml/idp/continue", { headers: { Cookie: resume + "; " + signedIn } });
  const html = await page.text();
  assert.equal(page.status, 200);
  assert.doesNotMatch(html, /SAMLResponse/, "nothing is posted to the SP without the user's click");
  assert.ok(confirmationToken(html), "the user is asked first");
  // Signed: covered in the signed-request test (Redirect and POST, older session, no confirmation).
  // A signature without Nathan as Destination is not enough to skip the confirmation.
  const spKey = makeCertificate({ cn: "Optional signer" });
  const optional = await freshSp({ certificates: [spKey.certPem] });
  const { createSign } = await import("node:crypto");
  const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_n${randomKey().replace(/-/g, "")}" Version="2.0" IssueInstant="${new Date().toISOString()}"><saml:Issuer>${optional.entity}</saml:Issuer></samlp:AuthnRequest>`;
  const signedQuery = "SAMLRequest=" + encodeURIComponent(deflateRawSync(xml).toString("base64")) + "&SigAlg=" + encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
  const signature = createSign("RSA-SHA256").update(signedQuery).sign(spKey.privateKey, "base64");
  const noDestination = await continueWith(await redirectLogin(SSO + "?" + signedQuery + "&Signature=" + encodeURIComponent(signature), user), user, { confirm: false });
  assert.ok(confirmationToken(await noDestination.text()), "signed without Destination: still confirmed by the user");
});

test("a real body on GET is refused before parsing (raw socket), and RelayState may appear only once in a POST", async () => {
  const s = await freshSp();
  const target = new URL(s.sp.createLoginRequest(s.idp, "redirect").context);
  const r = await rawHttp(mf, HOST, { method: "GET", path: target.pathname + target.search, body: "SAMLRequest=x&RelayState=y",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: user, "cf-connecting-ip": "10.66.0.1" } });
  assert.equal(r.status, 400, r.text.slice(0, 300));
  assert.match(r.text, /\(saml_body_not_allowed\)/);
  assert.doesNotMatch(r.text, /SAMLResponse|__Host-nathan-saml-idp=[A-Za-z0-9]/, "no assertion, no pending request");
  assert.ok((await auditRows("saml_idp_request_rejected", "unknown:saml_body_not_allowed")).length >= 1);
  const { context } = s.sp.createLoginRequest(s.idp, "post");
  const twice = await dispatch(SSO, { method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "SAMLRequest=" + encodeURIComponent(context) + "&RelayState=a&RelayState=b" });
  await refused(twice, "RelayState twice", "saml_duplicate_parameter");
});

test("the resume handle: missing, tampered, wrong length, expired, forged on the return redirect or replayed, each with its reason", async () => {
  const s = await freshSp();
  const pending = async () => resumeCookie(await redirectLogin(manual(s.entity)));
  const at = (cookie, session = user) => dispatch(ORIGIN + "/saml/idp/continue", { redirect: "manual", headers: { Cookie: [cookie, session].filter(Boolean).join("; ") } });
  const swap = (value, i) => value.slice(0, i) + (value[i] === "A" ? "B" : "A") + value.slice(i + 1);
  const resume = await pending();
  const value = resume.slice(resume.indexOf("=") + 1);
  assert.equal(value.length, 86, "43-character handle followed by its 43-character HMAC");
  await refused(await at(null), "no cookie", "saml_resume_missing");
  await refused(await at("__Host-nathan-saml-idp=" + swap(value, 60)), "HMAC half changed", "saml_resume_invalid");
  await refused(await at("__Host-nathan-saml-idp=" + swap(value, 10)), "handle half changed", "saml_resume_invalid");
  await refused(await at("__Host-nathan-saml-idp=" + value.slice(0, 85)), "too short", "saml_resume_invalid");
  await refused(await at("__Host-nathan-saml-idp=" + value + "A"), "too long", "saml_resume_invalid");
  await refused(await at("__Host-nathan-saml-idp=" + value.slice(0, 85) + "*"), "outside the alphabet", "saml_resume_invalid");
  // After a sign-in, "/" resumes only a handle Nathan signed.
  const home = cookie => dispatch(ORIGIN + "/", { redirect: "manual", headers: { Cookie: cookie + "; " + user } });
  assert.equal((await home(resume)).headers.get("location"), ORIGIN + "/saml/idp/continue");
  assert.notEqual((await home("__Host-nathan-saml-idp=" + swap(value, 60))).headers.get("location"), ORIGIN + "/saml/idp/continue", "a forged handle is not resumed");
  // Expiry: the pending request is older than its 10 minutes.
  const expiring = await pending();
  await run("UPDATE nathan_saml_idp_pending SET expires_at=unixepoch()-1 WHERE sp_id=? AND used=0", s.id);
  await refused(await at(expiring), "expired", "saml_resume_expired");
  // Replay: a used handle stays refused, and after cleanup removes the row it reads as expired.
  const used = await pending();
  await form(await at(used).then(async page => {
    const token = confirmationToken(await page.text());
    return confirmPost(used, user, token);
  }));
  await refused(await at(used), "replayed", "saml_resume_used");
  await run("UPDATE nathan_saml_idp_pending SET expires_at=unixepoch()-7200 WHERE sp_id=?", s.id);
  await refused(await at(used), "replayed after the window", "saml_resume_used");
  await run("DELETE FROM nathan_saml_idp_pending WHERE sp_id=? AND expires_at < unixepoch() - 3600", s.id);
  await refused(await at(used), "replayed after cleanup", "saml_resume_expired");
});

test("IdP-initiated sign-in: no Origin, cross-site Sec-Fetch-Site or no session refuse the POST; the GET page issues nothing", async () => {
  const s = await freshSp({ allowIdpInitiated: true });
  const start = ORIGIN + "/saml/idp/start/" + s.id;
  const page = await dispatch(start, { headers: { Cookie: user } });
  const html = await page.text();
  assert.equal(page.status, 200);
  assert.doesNotMatch(html, /SAMLResponse|<script/, "the confirmation page issues nothing and does not submit itself");
  assert.match(page.headers.get("content-security-policy"), /form-action 'self'.*frame-ancestors 'none'/);
  await refused(await dispatch(start, { method: "POST", headers: { Cookie: user } }), "no Origin", "saml_cross_site_request");
  await refused(await dispatch(start, { method: "POST", headers: { Cookie: user, Origin: ORIGIN, "Sec-Fetch-Site": "cross-site" } }), "Origin right, Sec-Fetch-Site cross-site", "saml_cross_site_request");
  await refused(await dispatch(start, { method: "POST", headers: { Origin: ORIGIN, "Sec-Fetch-Site": "same-origin" } }), "no session", "saml_sign_in_required");
  await refused(await dispatch(start), "GET without a session", "saml_sign_in_required");
  await refused(await dispatch(start, { method: "PUT", headers: { Cookie: user, Origin: ORIGIN } }), "PUT", "saml_method_not_allowed");
  assert.equal((await auditRows("saml_idp_assertion", s.id)).length, 0, "no assertion issued or attempted");
});

test("request signatures: SigAlg without Signature, SHA-1 on Redirect, a POST signature over another ID or Issuer, no Destination, an XML signature inside a Redirect", async () => {
  const spKey = makeCertificate({ cn: "Strict SP" });
  const s = await freshSp({ wantRequestsSigned: true, certificates: [spKey.certPem] });
  // A second SP pinning the same certificate (one SP key for two entity IDs).
  const twin = await freshSp({ wantRequestsSigned: true, certificates: [spKey.certPem] });
  const signingIdp = samlify.IdentityProvider({ metadata: (await idpFromMetadata()).metadata.replace('WantAuthnRequestsSigned="false"', 'WantAuthnRequestsSigned="true"') });
  const signer = serviceProvider(s.entity, s.acs, { authnRequestsSigned: true, privateKey: spKey.privateKey, signingCert: spKey.certPem,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" });
  const redirect = () => signer.createLoginRequest(signingIdp, "redirect").context;
  await refused(await redirectLogin(redirect().replace(/&Signature=[^&]+/, "")), "SigAlg without Signature", "saml_bad_signature");
  await refused(await redirectLogin(redirect().replace(/SigAlg=[^&]+/, "SigAlg=" + encodeURIComponent("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))), "SHA-1 SigAlg", "saml_weak_algorithm");
  const postXml = () => Buffer.from(signer.createLoginRequest(signingIdp, "post").context, "base64").toString();
  const post = xml => postLogin({ SAMLRequest: Buffer.from(xml).toString("base64") });
  const idOf = xml => / ID="([^"]+)"/.exec(xml)[1];
  let xml = postXml();
  assert.match(await refused(await post(xml.replace(' ID="' + idOf(xml) + '"', ' ID="_other' + idOf(xml).slice(1) + '"')), "root ID changed", "saml_bad_signature"), /cover the whole request/);
  xml = postXml();
  assert.match(await refused(await post(xml.replaceAll(idOf(xml), "_other" + idOf(xml).slice(1))), "ID and Reference changed", "saml_bad_signature"), /signature is invalid/);
  xml = postXml();
  await refused(await post(xml.replace(">" + s.entity + "<", ">" + twin.entity + "<")), "Issuer changed to another SP with the same key", "saml_bad_signature");
  // Hand-signed HTTP-Redirect requests (the SP's key) for shapes samlify does not produce.
  const { createSign } = await import("node:crypto");
  const signedRedirect = inner => {
    const query = "SAMLRequest=" + encodeURIComponent(deflateRawSync(inner).toString("base64")) + "&SigAlg=" + encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    return SSO + "?" + query + "&Signature=" + encodeURIComponent(createSign("RSA-SHA256").update(query).sign(spKey.privateKey, "base64"));
  };
  const bare = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_h${randomKey().replace(/-/g, "")}" Version="2.0" IssueInstant="${new Date().toISOString()}"><saml:Issuer>${s.entity}</saml:Issuer></samlp:AuthnRequest>`;
  await refused(await redirectLogin(signedRedirect(bare)), "signed without Destination", "saml_destination_mismatch");
  assert.match(await refused(await redirectLogin(signedRedirect(postXml())), "XML signature inside a Redirect", "saml_invalid_request"), /signed in the query/);
  // The same well-formed request with Destination is accepted, so each refusal above is its own.
  const withDestination = bare.replace(' Version="2.0"', ' Destination="' + SSO + '" Version="2.0"');
  assert.equal((await form(await continueWith(await redirectLogin(signedRedirect(withDestination)), user, { confirm: false }))).action, s.acs);
});

test("hostile display name, email and RelayState are escaped end to end; two SPs get different persistent NameIDs", async () => {
  const name = '</saml:AttributeValue><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue>"\'&<script>alert(1)</script>';
  const email = 'x"><img src=x onerror=alert(1)>@example.test';
  const relayState = '"><script>alert(2)</script>&amp;<!--';
  const cookie = await seedUser("hostile", { name, email });
  const s = await freshSp({ name: "<img src=x onerror=alert(3)>", nameIdFormat: "email" }, { grantJane: false });
  await grant(s.id, "hostile", "viewer");
  const url = new URL(s.sp.createLoginRequest(s.idp, "redirect").context);
  url.searchParams.set("RelayState", relayState);
  const sso = await redirectLogin(url.href, cookie);
  const resume = resumeCookie(sso);
  const confirmPage = await continueWith(sso, cookie, { confirm: false });
  const confirmHtml = await confirmPage.text();
  for (const raw of ["<img src=x", "<script>alert", 'x"><img']) assert.ok(!confirmHtml.includes(raw), "confirmation page escapes " + raw);
  assert.ok(confirmHtml.includes("&lt;img src=x onerror=alert(3)&gt;") && confirmHtml.includes("x&quot;&gt;&lt;img src=x onerror=alert(1)&gt;@example.test"));
  const page = await confirmPost(resume, cookie, confirmationToken(confirmHtml));
  const posted = await form(page);
  for (const raw of ["<img src=x", "<script>alert", "<!--"]) assert.ok(!posted.html.includes(raw), "auto-POST page escapes " + raw);
  assertOnlyAutoPostScript(posted.html, posted.csp);
  assert.equal(posted.RelayState, relayState, "RelayState is returned exactly");
  const { extract } = await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: posted.SAMLResponse, RelayState: posted.RelayState } });
  assert.equal(extract.nameID, email);
  assert.equal(extract.attributes.email, email);
  assert.equal(extract.attributes.displayName, name, "the name arrives as text, not markup");
  assert.equal(extract.attributes.role, "viewer", "no injected role attribute");
  assert.equal((xmlOf(posted.SAMLResponse).match(/<saml:Attribute Name="role"/g) ?? []).length, 1);
  // Persistent NameIDs are pairwise: the same user, two SPs, two unrelated identifiers.
  const a = await freshSp(), b = await freshSp();
  const nameId = async sp => (await sp.sp.parseLoginResponse(sp.idp, "post", { body: { SAMLResponse: (await form(await continueWith(await redirectLogin(sp.sp.createLoginRequest(sp.idp, "redirect").context), user))).SAMLResponse } })).extract.nameID;
  const [first, second] = [await nameId(a), await nameId(b)];
  assert.match(first, /^[A-Za-z0-9_-]{32}$/);
  assert.match(second, /^[A-Za-z0-9_-]{32}$/);
  assert.notEqual(first, second);
  assert.equal(await nameId(a), first, "stable per SP");
});

test("rate limit (429) and size limits (413, 414) at runtime", async () => {
  // 120 SSO requests per client IP and minute. Start early in a minute so the window does not roll over mid-test.
  const ms = Date.now() % 60_000;
  if (ms > 45_000) await new Promise(r => setTimeout(r, 60_000 - ms + 50));
  const ip = "10.250.0." + Math.floor(Math.random() * 250);
  for (let i = 0; i < 120; i++) {
    const r = await dispatch(SSO + "?RelayState=x", { headers: { "cf-connecting-ip": ip } });
    assert.equal(r.status, 400, "request " + i + " is answered, not limited");
  }
  await refused(await dispatch(SSO + "?RelayState=x", { headers: { "cf-connecting-ip": ip } }), "121st request", "saml_rate_limited");
  const limited = await dispatch(SSO + "?RelayState=x", { headers: { "cf-connecting-ip": ip } });
  assert.equal(limited.status, 429);
  assert.equal((await dispatch(SSO + "?RelayState=x", { headers: { "cf-connecting-ip": ip + "1" } })).status, 400, "other clients are not affected");
  const s = await freshSp();
  const long = await redirectLogin(manual(s.entity, "", undefined, "&RelayState=" + "a".repeat(17_000)));
  await refused(long, "query over 16 KiB", "saml_unreadable");
  assert.equal(long.status, 414);
  const big = await dispatch(SSO, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "SAMLRequest=" + "a".repeat(200_001) });
  await refused(big, "form over 200 KB", "saml_unreadable");
  assert.equal(big.status, 413);
});

test("rotation gates: one next key, retire a next key, the exact 24 h boundary, previous retired first, no active key, 3072/4096-bit keys", { timeout: 120_000 }, async () => {
  await resetKeys();
  const keys = async () => (await ok(await dispatch(ORIGIN + "/studio/api/saml-idp", { headers: { Cookie: admin } }))).keys;
  const activate = sha256 => studio({ op: "key.activate", sha256, confirm: "CONFIRM ACTIVATE SAML IDP KEY" });
  const retire = sha256 => studio({ op: "key.retire", sha256, confirm: "CONFIRM RETIRE SAML IDP KEY" });
  const refusedWith = async (response, pattern) => { assert.equal(response.status, 409); assert.match((await response.json()).error, pattern); };
  const first = (await keys()).find(k => k.status === "active");
  const next = await ok(await studio({ ...GENERATE, bits: 3072 }));
  assert.deepEqual([next.status, next.bits], ["next", 3072]);
  await refusedWith(await studio(GENERATE), /next key is already published/);
  // A next key can be retired (rotation cancelled): it leaves the metadata and loses its private key.
  assert.equal((await ok(await retire(next.sha256))).status, "retired");
  assert.equal((await idpFromMetadata()).certificates, 1);
  assert.equal((await db.prepare("SELECT private_key FROM nathan_saml_idp_keys WHERE id=?").bind(next.id).first()).private_key, null);
  // The overlap boundary: 86399 s is too early, 86400 s is enough (start early in a second so it does not tick over).
  const big = await ok(await studio({ ...GENERATE, bits: 4096 }));
  assert.deepEqual([big.status, big.bits], ["next", 4096]);
  if (Date.now() % 1000 > 300) await new Promise(r => setTimeout(r, 1050 - Date.now() % 1000));
  await run("UPDATE nathan_saml_idp_keys SET created_at=? WHERE id=?", Math.floor(Date.now() / 1000) - 86399, big.id);
  await refusedWith(await activate(big.sha256), /24 hours/);
  await run("UPDATE nathan_saml_idp_keys SET created_at=? WHERE id=?", Math.floor(Date.now() / 1000) - 86400, big.id);
  assert.equal((await ok(await activate(big.sha256))).status, "active");
  assert.equal((await keys()).find(k => k.status === "previous").sha256, first.sha256);
  // The 4096-bit key signs responses the SP accepts.
  const s = await freshSp();
  const signed = await form(await continueWith(await redirectLogin(s.sp.createLoginRequest(s.idp, "redirect").context), user));
  await s.sp.parseLoginResponse(s.idp, "post", { body: { SAMLResponse: signed.SAMLResponse } });
  // The next activation waits until the previous key is retired.
  const third = await ok(await studio(GENERATE));
  await run("UPDATE nathan_saml_idp_keys SET created_at=created_at-90000 WHERE id=?", third.id);
  await refusedWith(await activate(third.sha256), /Retire the previous key first/);
  await ok(await retire(first.sha256));
  assert.equal((await ok(await activate(third.sha256))).status, "active");
  // No active key (for example after a manual repair): the overlap gate still applies to a fresh next
  // key; once it has passed, activation makes it the only key and creates no previous key.
  await ok(await retire(big.sha256));
  const lone = await ok(await studio(GENERATE));
  await run("UPDATE nathan_saml_idp_keys SET status='retired', private_key=NULL WHERE id=?", third.id);
  assert.equal((await dispatch(ORIGIN + "/saml/idp/metadata")).status, 404, "without an active key no metadata is served");
  await refusedWith(await activate(lone.sha256), /24 hours/);
  await run("UPDATE nathan_saml_idp_keys SET created_at=created_at-90000 WHERE id=?", lone.id);
  assert.equal((await ok(await activate(lone.sha256))).status, "active");
  assert.deepEqual((await keys()).filter(k => k.status !== "retired").map(k => k.status), ["active"]);
  assert.equal((await idpFromMetadata()).certificates, 1);
});
