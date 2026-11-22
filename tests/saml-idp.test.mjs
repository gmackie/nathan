/**
 * NATH-12 unit tests: Nathan's SAML IdP protocol module in Node. Signed responses are verified by
 * an independent SP library (samlify's ServiceProvider); tampering must break them.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { X509Certificate, createPublicKey } from "node:crypto";
import * as samlify from "samlify";
import { XMLValidator } from "fast-xml-parser";
import { generateSigningKey, importSigningKey, certificateSpki } from "../src/auth/saml-idp-keys.mjs";
import { sealConfigSecret, openConfigSecret, generateConfigKey } from "../src/auth/config-crypto.mjs";
import {
  parseBindingParameters, REDIRECT_PARAMETERS, decodeRedirectRequest, decodePostRequest, parseAuthnRequest, buildSignedResponse,
  buildIdpMetadata, validateServiceProvider, parseSpMetadata, checkAcsUrl, verifyPostSignature, verifyRedirectSignature, NAMEID,
  AC_UNSPECIFIED, xmlEscape, SamlRequestError
} from "../src/auth/saml-idp-protocol.mjs";
import { makeCertificate } from "./fixtures/x509.mjs";
import { readBoundedText } from "../src/auth/bounded-body.mjs";
import { deflateRawSync } from "node:zlib";

samlify.setSchemaValidator({ async validate(xml) { if (XMLValidator.validate(xml) === true) return "ok"; throw Error("invalid xml"); } });

const IDP = "https://login.example.com/saml/idp";
const SSO = "https://login.example.com/saml/idp/sso";
const SP_ENTITY = "https://grafana.example.com/saml/metadata";
const ACS = "https://grafana.example.com/saml/acs";
const isAppId = v => typeof v === "string" && /^[a-z][a-z0-9-]{0,62}$/.test(v);
let key;
const signingKey = async () => key ??= await generateSigningKey({ subject: "Nathan SAML IdP login.example.com" });

function serviceProvider(over = {}) {
  return samlify.ServiceProvider({
    entityID: SP_ENTITY, wantAssertionsSigned: true, authnRequestsSigned: false,
    assertionConsumerService: [{ Binding: samlify.Constants.namespace.binding.post, Location: ACS }], ...over
  });
}
async function response(over = {}) {
  const k = await signingKey();
  return buildSignedResponse({
    idpEntityId: IDP, spEntityId: SP_ENTITY, acsUrl: ACS, inResponseTo: "_req1",
    nameId: { format: NAMEID.persistent, value: "opaque-123" },
    attributes: [{ name: "email", values: ["jane@example.com"] }, { name: "roles", values: ["admin", "viewer"] }],
    authnInstant: Date.now() - 1000, authnContext: AC_UNSPECIFIED, signResponse: false,
    key: await importSigningKey(k.pkcs8), certificate: k.certificate, ...over
  });
}
const idpFor = certs => samlify.IdentityProvider({ metadata: buildIdpMetadata({ entityId: IDP, ssoUrl: SSO, certificates: certs }) });

test("generated IdP keys: RSA 2048, a self-signed SHA-256 certificate Node can parse and verify, sealed with purpose-bound AAD", async () => {
  const k = await signingKey();
  const x509 = new X509Certificate(Buffer.from(k.certificate, "base64"));
  assert.equal(x509.publicKey.asymmetricKeyDetails.modulusLength, 2048);
  assert.ok(x509.verify(x509.publicKey), "self-signature verifies");
  assert.match(x509.subject, /CN=Nathan SAML IdP login\.example\.com/);
  assert.deepEqual(createPublicKey({ key: Buffer.from(certificateSpki(k.certificate)), format: "der", type: "spki" }).export({ format: "jwk" }),
    x509.publicKey.export({ format: "jwk" }));
  const master = generateConfigKey();
  const sealed = await sealConfigSecret("saml-idp-key:v1:k1", k.pkcs8, master);
  assert.ok(!sealed.includes(k.pkcs8.slice(0, 40)));
  assert.equal(await openConfigSecret("saml-idp-key:v1:k1", sealed, master), k.pkcs8);
  await assert.rejects(openConfigSecret("saml-idp-key:v1:k2", sealed, master), "ciphertext is bound to its key id");
  await assert.rejects(generateSigningKey({ bits: 1024, subject: "x" }), /2048/);
});

test("an independent SP library (samlify) validates Nathan's signed assertion, with and without a signed Response", async () => {
  const k = await signingKey();
  for (const signResponse of [false, true]) {
    const { response: SAMLResponse } = await response({ signResponse });
    const { extract } = await serviceProvider().parseLoginResponse(idpFor([k.certificate]), "post", { body: { SAMLResponse } });
    assert.equal(extract.nameID, "opaque-123");
    assert.equal(extract.issuer, IDP);
    assert.deepEqual(extract.audience, SP_ENTITY);
    assert.equal(extract.response.inResponseTo, "_req1");
    assert.equal(extract.attributes.email, "jane@example.com");
    assert.deepEqual(extract.attributes.roles, ["admin", "viewer"]);
    const xml = Buffer.from(SAMLResponse, "base64").toString();
    assert.match(xml, /xmldsig-more#rsa-sha256/);
    assert.match(xml, /xmlenc#sha256/);
    assert.match(xml, /xml-exc-c14n#/);
    assert.equal((xml.match(/<ds:Signature /g) ?? []).length, signResponse ? 2 : 1);
  }
});

test("tampering with a signed assertion, or a foreign key, breaks validation at the SP", async () => {
  const k = await signingKey();
  const { response: SAMLResponse } = await response();
  const xml = Buffer.from(SAMLResponse, "base64").toString();
  const tampered = [
    xml.replace("opaque-123", "opaque-999"),
    xml.replace("jane@example.com", "mallory@example.com"),
    xml.replace(/NotOnOrAfter="[^"]+"/, 'NotOnOrAfter="2099-01-01T00:00:00Z"')
  ];
  for (const t of tampered) {
    assert.notEqual(t, xml);
    await assert.rejects(serviceProvider().parseLoginResponse(idpFor([k.certificate]), "post", { body: { SAMLResponse: Buffer.from(t).toString("base64") } }));
  }
  const other = await generateSigningKey({ subject: "Other" });
  await assert.rejects(serviceProvider().parseLoginResponse(idpFor([other.certificate]), "post", { body: { SAMLResponse } }));
});

test("rotation overlap: an SP that loaded metadata with the active and next certificates accepts responses signed by either", async () => {
  const k = await signingKey(), next = await generateSigningKey({ subject: "Next" });
  const idp = idpFor([k.certificate, next.certificate]);
  for (const signer of [k, next]) {
    const { response: SAMLResponse } = await response({ key: await importSigningKey(signer.pkcs8), certificate: signer.certificate });
    const { extract } = await serviceProvider().parseLoginResponse(idp, "post", { body: { SAMLResponse } });
    assert.equal(extract.nameID, "opaque-123");
  }
});

test("assertion content: audience, recipient, destination, bearer confirmation and a 5-minute window", async () => {
  const now = Date.parse("2026-11-21T10:00:00Z");
  const { response: r } = await response({ now, authnInstant: now - 60e3 });
  const xml = Buffer.from(r, "base64").toString();
  assert.match(xml, /<saml:Audience>https:\/\/grafana\.example\.com\/saml\/metadata<\/saml:Audience>/);
  assert.match(xml, /Recipient="https:\/\/grafana\.example\.com\/saml\/acs"/);
  assert.match(xml, /Destination="https:\/\/grafana\.example\.com\/saml\/acs"/);
  assert.match(xml, /cm:bearer/);
  assert.match(xml, /NotBefore="2026-11-21T09:59:00Z" NotOnOrAfter="2026-11-21T10:04:00Z"/);
  assert.match(xml, /SPNameQualifier="https:\/\/grafana\.example\.com\/saml\/metadata"/);
  assert.match(xml, new RegExp(AC_UNSPECIFIED));
  assert.equal(xmlEscape('a<b>&"\'\u0001'), "a&lt;b&gt;&amp;&quot;&apos;");
});

test("binding parameters: one parser, duplicates, unknown names and non-canonical encoding are refused", () => {
  const ok = parseBindingParameters("SAMLRequest=abc%2B&RelayState=x+y", REDIRECT_PARAMETERS);
  assert.deepEqual(ok.get("SAMLRequest"), { raw: "abc%2B", value: "abc+" });
  assert.equal(ok.get("RelayState").value, "x y");
  const code = raw => { try { parseBindingParameters(raw, REDIRECT_PARAMETERS); return null; } catch (e) { return e.code; } };
  assert.equal(code("SAMLRequest=a&SAMLRequest=b"), "saml_duplicate_parameter");
  assert.equal(code("SAMLRequest=a&SAMLReq%75est=b"), "saml_duplicate_parameter", "an encoded name is the same name");
  assert.equal(code("SAMLRequest=a&SAMLResp%onse=b"), "saml_noncanonical_encoding");
  assert.equal(code("SAMLRequest=a&&RelayState=b"), "saml_noncanonical_encoding");
  assert.equal(code("SAMLRequest"), "saml_noncanonical_encoding");
  assert.equal(code("SAMLRequest=a&foo=b"), "saml_unknown_parameter");
  assert.equal(code("SAMLRequest=%FF"), "saml_noncanonical_encoding");
});

const authnRequest = ({ id = "_r" + crypto.randomUUID().replace(/-/g, ""), issuer = SP_ENTITY, instant = new Date().toISOString(), extra = "", attrs = "" } = {}) =>
  `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${instant}" Destination="${SSO}" AssertionConsumerServiceURL="${ACS}"${attrs}><saml:Issuer>${issuer}</saml:Issuer>${extra}</samlp:AuthnRequest>`;

test("AuthnRequest parsing: fields, freshness, DTDs, weak algorithms, duplicate IDs and Subjects", async () => {
  const parsed = parseAuthnRequest(authnRequest({ id: "_abc", attrs: ' ForceAuthn="true"' }));
  assert.equal(parsed.id, "_abc"); assert.equal(parsed.issuer, SP_ENTITY); assert.equal(parsed.acsUrl, ACS);
  assert.equal(parsed.forceAuthn, true); assert.equal(parsed.isPassive, false); assert.equal(parsed.destination, SSO);
  const code = xml => { try { parseAuthnRequest(xml); return null; } catch (e) { assert.ok(e instanceof SamlRequestError); return e.code; } };
  assert.equal(code(authnRequest({ instant: new Date(Date.now() - 8 * 60e3).toISOString() })), "saml_stale_request");
  assert.equal(code(authnRequest({ instant: new Date(Date.now() + 3 * 60e3).toISOString() })), "saml_stale_request");
  assert.equal(code('<!DOCTYPE x [<!ENTITY a "b">]>' + authnRequest()), "saml_unreadable");
  assert.equal(code(authnRequest({ extra: '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></ds:SignedInfo></ds:Signature>' })), "saml_weak_algorithm");
  assert.equal(code(authnRequest({ extra: '<samlp:Extensions><x ID="_dup" xmlns="urn:x"/></samlp:Extensions>', id: "_dup" })), "saml_invalid_request");
  assert.equal(code(authnRequest({ extra: "<saml:Subject><saml:NameID>victim</saml:NameID></saml:Subject>" })), "saml_invalid_request");
  assert.equal(code(authnRequest({ extra: "<saml:Issuer>second</saml:Issuer>" })), "saml_invalid_request");
  assert.equal(code(authnRequest({ attrs: ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"' })), "saml_unsupported_binding");
  assert.equal(code("<x/>"), "saml_invalid_request");
  assert.equal(code("<samlp:AuthnRequest"), "saml_unreadable");
});

test("HTTP-Redirect decoding is strict and bounded; POST decoding tolerates line breaks only", async () => {
  const xml = authnRequest();
  assert.equal(await decodeRedirectRequest(deflateRawSync(xml).toString("base64")), xml);
  await assert.rejects(decodeRedirectRequest("not base64!"), /base64/);
  await assert.rejects(decodeRedirectRequest(deflateRawSync("<a>" + "x".repeat(70000) + "</a>").toString("base64")), /too large/);
  const b64 = Buffer.from(xml).toString("base64");
  assert.equal(decodePostRequest(b64.match(/.{1,76}/g).join("\r\n")), xml);
  assert.throws(() => decodePostRequest(b64 + " "), /base64/);
});

test("signed AuthnRequests from a real SP library verify (Redirect and POST); tampering and foreign keys fail", async () => {
  const k = await signingKey();
  const spCert = makeCertificate({ cn: "SP" });
  const sp = serviceProvider({ authnRequestsSigned: true, privateKey: spCert.privateKey, signingCert: spCert.certPem,
    requestSignatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" });
  // Nathan's metadata says WantAuthnRequestsSigned="false" (it is enforced per SP); this SP was told to sign.
  const idp = samlify.IdentityProvider({ metadata: buildIdpMetadata({ entityId: IDP, ssoUrl: SSO, certificates: [k.certificate] })
    .replace('WantAuthnRequestsSigned="false"', 'WantAuthnRequestsSigned="true"') });
  const { context } = sp.createLoginRequest(idp, "redirect");
  const query = new URL(context).search.slice(1);
  const params = parseBindingParameters(query, REDIRECT_PARAMETERS);
  assert.equal(await verifyRedirectSignature(params, [spCert.certB64]), true);
  assert.equal(await verifyRedirectSignature(params, [makeCertificate().certB64]), false);
  const forged = parseBindingParameters(query.replace(/SAMLRequest=[^&]+/, "SAMLRequest=" + encodeURIComponent(deflateRawSync(authnRequest()).toString("base64"))), REDIRECT_PARAMETERS);
  assert.equal(await verifyRedirectSignature(forged, [spCert.certB64]), false);
  const unsigned = parseBindingParameters(query.replace(/&Signature=[^&]+/, ""), REDIRECT_PARAMETERS);
  await assert.rejects(verifyRedirectSignature(unsigned, [spCert.certB64]), e => e.code === "saml_signature_required");

  const post = sp.createLoginRequest(idp, "post");
  const xml = Buffer.from(post.context, "base64").toString();
  const signedBytes = verifyPostSignature(xml, [spCert.certB64]);
  assert.ok(signedBytes && !signedBytes.includes("Signature>"), "returns the signed request without the signature");
  assert.equal(parseAuthnRequest(signedBytes).issuer, SP_ENTITY);
  assert.equal(verifyPostSignature(xml, [makeCertificate().certB64]), null);
  assert.equal(verifyPostSignature(xml.replace(ACS, "https://evil.example.com/acs"), [spCert.certB64]), null);
  assert.throws(() => verifyPostSignature(authnRequest(), [spCert.certB64]), e => e.code === "saml_signature_required");
});

test("SP registration validation: exact HTTPS ACS URLs, bound app, attribute sources, signed-request certificates", async () => {
  const base = { id: "grafana", name: "Grafana", entityId: SP_ENTITY, appId: "grafana", acsUrls: [ACS] };
  const sp = await validateServiceProvider(base, { idpEntityId: IDP, isAppId });
  assert.equal(sp.nameIdFormat, "persistent");
  assert.equal(sp.wantRequestsSigned, false);
  assert.equal(sp.allowIdpInitiated, false);
  for (const bad of ["http://grafana.example.com/acs", "https://*.example.com/acs", "https://grafana.example.com/acs#x", "https://user:pw@grafana.example.com/acs",
    "https://GRAFANA.example.com/acs", "https://localhost/acs", "https://10.0.0.1/acs", "https://grafana.example.com/a cs"])
    assert.throws(() => checkAcsUrl(bad), undefined, bad);
  assert.equal(checkAcsUrl("https://acme.my.salesforce.com/?so=00D000000000001"), "https://acme.my.salesforce.com/?so=00D000000000001", "queries are allowed");
  assert.equal(checkAcsUrl("https://acme.my.salesforce.com?so=00D000000000001"), "https://acme.my.salesforce.com?so=00D000000000001",
    "Salesforce's spelling without the root slash is kept verbatim (matching is exact)");
  assert.throws(() => checkAcsUrl("https://acme.my.salesforce.com/a/../b"), /canonical/);
  assert.throws(() => checkAcsUrl("https://acme.my.salesforce.com:443/acs"), /canonical/);
  const reject = async (over, pattern) => assert.rejects(validateServiceProvider({ ...base, ...over }, { idpEntityId: IDP, isAppId }), pattern);
  await reject({ appId: undefined }, /application/);
  await reject({ entityId: IDP }, /own entity ID/);
  await reject({ acsUrls: [] }, /ACS/);
  await reject({ acsUrls: [ACS, ACS] }, /unique/);
  await reject({ nameIdFormat: "transient" }, /NameID/);
  await reject({ attributes: [{ name: "x", source: "password" }] }, /source/);
  await reject({ attributes: [{ name: "a<b", source: "email" }] }, /attribute name/);
  await reject({ wantRequestsSigned: true }, /certificate/);
  await reject({ certificates: [makeCertificate({ hash: "sha1" }).certPem] }, /SHA-1/);
  await reject({ defaultRelayState: "/home" }, /IdP-initiated/);
  assert.deepEqual(sp.acsIndexes, [0], "hand-entered ACS URLs are numbered in order");
  assert.deepEqual((await validateServiceProvider({ ...base, acsUrls: [ACS, ACS + "2"], acsIndexes: [1, 7] }, { idpEntityId: IDP, isAppId })).acsIndexes, [1, 7]);
  await reject({ acsUrls: [ACS, ACS + "2"], acsIndexes: [1] }, /index/);
  await reject({ acsUrls: [ACS, ACS + "2"], acsIndexes: [1, 1] }, /index/);
  await reject({ acsIndexes: [65536] }, /index/);
  await reject({ acsIndexes: ["1"] }, /index/);
  const signed = await validateServiceProvider({ ...base, wantRequestsSigned: true, certificates: [makeCertificate().certPem] }, { idpEntityId: IDP, isAppId });
  assert.equal(signed.certificates.length, 1);
});

test("SP metadata import: HTTP-POST ACS URLs in default/index order, signing certificates, no DTDs", async () => {
  const cert = makeCertificate();
  const md = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${SP_ENTITY}"><md:SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${cert.certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>${NAMEID.email}</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://grafana.example.com/art" index="0"/><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://grafana.example.com/second" index="2"/><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${ACS}" index="1" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>`;
  const parsed = await parseSpMetadata(md);
  assert.equal(parsed.entityId, SP_ENTITY);
  assert.deepEqual(parsed.acsUrls, [ACS, "https://grafana.example.com/second"]);
  assert.deepEqual(parsed.acsIndexes, [1, 2], "each URL keeps its metadata index");
  assert.equal(parsed.wantRequestsSigned, true);
  assert.deepEqual(parsed.certificates, [cert.certB64]);
  assert.equal(parsed.nameIdFormat, "email");
  await assert.rejects(parseSpMetadata('<!DOCTYPE x SYSTEM "file:///etc/passwd">' + md), /DTD/);
  await assert.rejects(parseSpMetadata(md.replace(/SPSSODescriptor/g, "IDPSSODescriptor")), /SPSSODescriptor/);
});

test("0018 is the only 0018 migration, is packaged with the release and enforces key and SP invariants", () => {
  const migrations = readdirSync("migrations").filter(f => f.endsWith(".sql")).sort();
  assert.deepEqual(migrations.filter(f => f.startsWith("0018")), ["0018_saml_idp.sql"]);
  for (const script of ["scripts/pack-release.mjs", "scripts/verify-release.mjs"])
    assert.match(readFileSync(script, "utf8"), /0018_saml_idp\.sql/, script);
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of migrations) db.exec(readFileSync("migrations/" + file, "utf8"));
  const key = (id, status, pk = "sealed") => db.prepare("INSERT INTO nathan_saml_idp_keys(id,status,bits,certificate,sha256,not_before,not_after,private_key,created_by) VALUES (?,?,2048,'c',?, 'a','b',?,'admin')").run(id, status, id, pk);
  key("k1", "active");
  assert.throws(() => key("k2", "active"), /UNIQUE/, "one active key");
  key("k3", "next");
  assert.throws(() => key("k4", "retired"), /CHECK/, "a retired key keeps no private key");
  assert.throws(() => key("k5", "previous", null), /CHECK|NOT NULL/, "a published key needs its private key");
  db.exec("INSERT INTO nathan_applications(id,hostname) VALUES ('grafana','grafana.example.com')");
  const sp = (id, signed, certs) => db.prepare("INSERT INTO nathan_saml_service_providers(id,name,entity_id,app_id,acs_urls,acs_indexes,want_requests_signed,certificates,created_by,updated_by) VALUES (?,?,?,?,?,'[]',?,?,'a','a')")
    .run(id, id, "urn:" + id, "grafana", "[]", signed, certs);
  sp("a", 0, "[]");
  assert.equal(db.prepare("SELECT enabled, name_id_format AS f, allow_idp_initiated AS i FROM nathan_saml_service_providers WHERE id='a'").get().enabled, 0, "disabled by default");
  assert.throws(() => sp("b", 1, "[]"), /CHECK/, "signed requests need a certificate");
  assert.throws(() => db.prepare("INSERT INTO nathan_saml_service_providers(id,name,entity_id,app_id,acs_urls,acs_indexes,created_by,updated_by) VALUES ('c','c','urn:c','missing','[]','[]','a','a')").run(), /FOREIGN KEY|constraint/i);
  assert.throws(() => db.prepare("INSERT INTO nathan_saml_service_providers(id,name,entity_id,app_id,acs_urls,created_by,updated_by) VALUES ('d','d','urn:d','grafana','[]','a','a')").run(), /NOT NULL/, "ACS indexes are always stored");
});

test("bounded body reads count bytes, not characters, and stop at the limit without Content-Length", async () => {
  const twoByte = "é".repeat(100);
  const streamed = (text, pulled = { bytes: 0 }) => new Request("https://login.example.com/x", { method: "POST", duplex: "half",
    body: new ReadableStream({ pull(c) { const b = new TextEncoder().encode(text); pulled.bytes += b.length; c.enqueue(b); } }) });
  assert.equal(await readBoundedText(new Request("https://login.example.com/x", { method: "POST", body: twoByte }), 200), twoByte);
  assert.equal(await readBoundedText(new Request("https://login.example.com/x", { method: "POST", body: twoByte }), 199), null, "200 bytes even though only 100 characters");
  const pulled = { bytes: 0 };
  assert.equal(await readBoundedText(streamed("a".repeat(65536), pulled), 200_000), null, "an endless stream is cut off");
  assert.ok(pulled.bytes <= 200_000 + 2 * 65536, "read stops right after the limit: " + pulled.bytes);
  const declared = new Request("https://login.example.com/x", { method: "POST", body: "x", headers: { "Content-Length": "999999" } });
  assert.equal(await readBoundedText(declared, 1000), null, "a declared length over the limit is refused before reading");
  assert.equal(await readBoundedText(new Request("https://login.example.com/x"), 10), "", "no body reads as empty");
});

test("signature wrapping against an independent SP library: only the signed Assertion counts, moved or stripped signatures fail", async () => {
  // samlify's XSD schema validation is stubbed with a well-formedness check (top of this file), so
  // these results come from samlify's signature, wrapping, recipient and InResponseTo checks only.
  const k = await signingKey();
  const idp = idpFor([k.certificate]);
  const xml = Buffer.from((await response()).response, "base64").toString();
  const parse = x => serviceProvider().parseLoginResponse(idp, "post", { body: { SAMLResponse: Buffer.from(x).toString("base64") } });
  const assertion = /<saml:Assertion[^]*<\/saml:Assertion>/.exec(xml)[0];
  const signature = /<ds:Signature[^]*<\/ds:Signature>/.exec(assertion)[0];
  const evil = assertion.replace(signature, "").replace("opaque-123", "victim").replace("jane@example.com", "mallory@example.com").replace(/ ID="[^"]+"/, ' ID="_evil"');
  // A second, unsigned Assertion before or after the signed one: samlify reads the signed one only.
  for (const forged of [xml.replace(assertion, evil + assertion), xml.replace(assertion, assertion + evil)]) {
    const { extract } = await parse(forged);
    assert.equal(extract.nameID, "opaque-123", "the unsigned Assertion's subject is never used");
    assert.equal(extract.attributes.email, "jane@example.com");
  }
  await assert.rejects(parse(xml.replace(signature, "")), /FAILED_TO_VERIFY_SIGNATURE/, "stripped signature");
  await assert.rejects(parse(xml.replace(signature, "").replace("<samlp:Status>", signature + "<samlp:Status>")), /ERR_POTENTIAL_WRAPPING_ATTACK/, "signature moved to the Response");
  await assert.rejects(parse(xml.replace(assertion, evil.replace("</saml:Issuer>", "</saml:Issuer>" + signature) + assertion.replace(signature, ""))),
    /ERR_POTENTIAL_WRAPPING_ATTACK/, "signature moved into the forged Assertion");
  await assert.rejects(parse(xml.replace(assertion, evil.replace("</saml:Assertion>", "<saml:Advice>" + assertion + "</saml:Advice></saml:Assertion>"))),
    /FAILED_TO_VERIFY_SIGNATURE/, "signed Assertion wrapped inside the forged one");
  // Edited attributes of the unsigned Response element.
  const responseAttr = (name, value) => xml.replace(new RegExp("(<samlp:Response[^>]* " + name + '=")[^"]+'), "$1" + value);
  await assert.rejects(parse(responseAttr("Destination", "https://evil.example.com/acs")), /ERR_RECIPIENT_MISMATCH/);
  await assert.rejects(parse(responseAttr("InResponseTo", "_other")), /ERR_INRESPONSETO_MISMATCH/);
  await assert.rejects(parse(xml.replace("status:Success", "status:Requester")), /ERR_FAILED_STATUS/);
  // The unsigned Response's Issuer and IssueInstant are not covered by the Assertion signature:
  // samlify accepts the edit but reports the signed Assertion's issuer. Sign the Response too
  // ("Also sign the Response") for SPs that read Response-level values.
  const issuerEdited = xml.replace(/(<samlp:Response[^>]*>)<saml:Issuer>[^<]+/, "$1<saml:Issuer>https://evil.example.com");
  assert.equal((await parse(issuerEdited)).extract.issuer, IDP);
  const both = Buffer.from((await response({ signResponse: true })).response, "base64").toString();
  await assert.rejects(parse(both.replace(/(<samlp:Response[^>]*>)<saml:Issuer>[^<]+/, "$1<saml:Issuer>https://evil.example.com")), /FAILED_TO_VERIFY_SIGNATURE/);
  await assert.rejects(parse(both.replace(/(<samlp:Response[^>]* IssueInstant=")[^"]+/, "$12020-01-01T00:00:00Z")), /FAILED_TO_VERIFY_SIGNATURE/);
});

test("3072- and 4096-bit IdP keys: valid certificates whose responses an SP accepts", async () => {
  for (const bits of [3072, 4096]) {
    const k = await generateSigningKey({ bits, subject: "Nathan SAML IdP " + bits });
    assert.equal(k.bits, bits);
    const x509 = new X509Certificate(Buffer.from(k.certificate, "base64"));
    assert.equal(x509.publicKey.asymmetricKeyDetails.modulusLength, bits);
    assert.ok(x509.verify(x509.publicKey));
    assert.deepEqual(createPublicKey({ key: Buffer.from(certificateSpki(k.certificate)), format: "der", type: "spki" }).export({ format: "jwk" }),
      x509.publicKey.export({ format: "jwk" }));
    const { response: SAMLResponse } = await response({ key: await importSigningKey(k.pkcs8), certificate: k.certificate });
    assert.equal((await serviceProvider().parseLoginResponse(idpFor([k.certificate]), "post", { body: { SAMLResponse } })).extract.nameID, "opaque-123");
  }
});

test("certificate DER reading: one-, two- and three-byte long-form lengths; longer, indefinite, truncated or trailing input refused", async () => {
  const k = await signingKey();
  const spki = certificateSpki(k.certificate);
  const tlv = (tag, body) => {
    const n = body.length;
    const head = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
    return Buffer.concat([Buffer.from([tag, ...head]), Buffer.from(body)]);
  };
  const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
  const name = cn => seq(tlv(0x31, seq(tlv(0x06, Buffer.from([0x55, 0x04, 0x03])), tlv(0x0c, Buffer.from(cn)))));
  const alg = seq(tlv(0x06, Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b])), Buffer.from([0x05, 0x00]));
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, Buffer.from([1])), alg,
    name("x".repeat(200)),                                         // 0x81 length
    seq(tlv(0x17, Buffer.from("260101000000Z")), tlv(0x17, Buffer.from("290101000000Z"))),
    name("y".repeat(300)),                                         // 0x82 length
    Buffer.from(spki),
    tlv(0xa3, tlv(0x04, Buffer.alloc(70_000, 1))));                // 0x83 length (and so are the TBS and the certificate)
  const der = seq(tbs, alg, tlv(0x03, Buffer.alloc(257)));
  assert.deepEqual([der[0], der[1]], [0x30, 0x83]);
  assert.ok(der.includes(Buffer.from([0x0c, 0x81, 200])) && der.includes(Buffer.from([0x0c, 0x82, 0x01, 0x2c])));
  assert.deepEqual(Buffer.from(certificateSpki(der.toString("base64"))), Buffer.from(spki), "the key is found behind every length form");
  const outerLength = der.subarray(2, 5);
  const refuse = (bytes, pattern) => assert.throws(() => certificateSpki(Buffer.from(bytes).toString("base64")), pattern);
  refuse(Buffer.concat([Buffer.from([0x30, 0x84, 0x00]), outerLength, der.subarray(5)]), /Unsupported certificate length/);
  refuse(Buffer.concat([Buffer.from([0x30, 0x80]), der.subarray(5)]), /Unsupported certificate length/);
  refuse(der.subarray(0, der.length - 1), /Truncated certificate/);
  refuse(Buffer.concat([der, Buffer.from([0])]), /Not a certificate/);
  refuse(Buffer.from([0x30, 0x82, 0x01]), /Truncated|Unsupported/);
});
