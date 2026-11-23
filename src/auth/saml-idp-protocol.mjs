/**
 * NATH-12: SAML 2.0 identity-provider protocol for Nathan. Pure and runtime independent (WebCrypto,
 * @xmldom/xmldom, xml-crypto): the same code runs in workerd and in Node tests. D1, sessions and
 * HTTP live in src/auth/saml-idp.ts.
 *
 * Lessons from inbound SAML (NATH-10, docs/threat-model.md T24) that shape this file:
 * - One parser. Binding parameters are read by parseBindingParameters only, from the raw query or
 *   the raw form body, and the values it returns are the ones processed. Duplicates, unknown names,
 *   malformed %-escapes and empty pairs are refused, so no second parser can disagree.
 * - A signed POST AuthnRequest is processed from the bytes the signature covers (xml-crypto's
 *   signed reference), never from the surrounding document, and its Reference must point at the
 *   root element whose ID is unique in the document.
 * - No DTDs, SHA-1/MD5 anywhere refused, sizes capped before decoding and after inflating.
 * - No custom XML canonicalization: signatures are computed and checked by xml-crypto with
 *   exclusive c14n; Nathan only supplies a WebCrypto RSA-SHA256 signer.
 */
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import { weakSamlAlgorithm } from "./saml-policy.mjs";
import { certificateFromInput, MAX_METADATA_BYTES } from "./saml-metadata.mjs";
import { importCertificateKey, toBase64, fromBase64 } from "./saml-idp-keys.mjs";

export const NS = Object.freeze({
  protocol: "urn:oasis:names:tc:SAML:2.0:protocol",
  assertion: "urn:oasis:names:tc:SAML:2.0:assertion",
  metadata: "urn:oasis:names:tc:SAML:2.0:metadata",
  ds: "http://www.w3.org/2000/09/xmldsig#"
});
export const BINDING = Object.freeze({
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
});
export const NAMEID = Object.freeze({
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
  entity: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
});
/** AuthnContextClassRef when Nathan holds no verified authentication-method evidence. */
export const AC_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
/** AuthnContextClassRef for a session created by a verified passkey assertion (same meaning as nathan_acr). */
export const AC_PASSKEY = "urn:nathan:acr:passkey";
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIGNATURE_HASHES = Object.freeze({
  [RSA_SHA256]: "SHA-256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "SHA-384",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "SHA-512"
});
const DIGESTS = new Set(["http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512"]);
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/** Request freshness: IssueInstant at most 5 minutes old, with 2 minutes of clock skew. */
export const REQUEST_MAX_AGE_MS = 5 * 60e3;
export const CLOCK_SKEW_MS = 2 * 60e3;
/** Assertion validity window: NotBefore = now - 60 s, NotOnOrAfter = now + 240 s (5 minutes in total). */
export const ASSERTION_BEFORE_MS = 60e3;
export const ASSERTION_AFTER_MS = 240e3;
export const MAX_QUERY_BYTES = 16384;
export const MAX_FORM_BYTES = 200_000;
export const MAX_REQUEST_XML_BYTES = 65536;
export const MAX_RELAY_STATE = 1024;

export class SamlRequestError extends Error {
  /** @param {string} code @param {string} message @param {number} [status] */
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}
/** @returns {never} */
const refuse = (code, message, status) => { throw new SamlRequestError(code, message, status); };

/** Nathan's IdP values for one origin. The entityID is https://<host>/saml/idp. */
export function idpValues(issuer) {
  const origin = new URL(issuer).origin;
  return { entityId: origin + "/saml/idp", ssoUrl: origin + "/saml/idp/sso", metadataUrl: origin + "/saml/idp/metadata" };
}

// ------------------------------------------------------------------------------- binding parameters

const MALFORMED_ESCAPE = /%(?![0-9A-Fa-f]{2})/;
function formDecode(text) {
  try { return decodeURIComponent(text.replace(/\+/g, " ")); }
  catch { return refuse("saml_noncanonical_encoding", "SAML message rejected: invalid percent-encoding"); }
}

/**
 * The single parser for SAML binding parameters (HTTP-Redirect query or HTTP-POST form body).
 * Returns name -> { raw, value }: `raw` is the still-encoded value exactly as received (the
 * HTTP-Redirect signature covers it), `value` its decoding. Refuses anything another parser could
 * read differently: malformed %-escapes, empty or nameless pairs, duplicates and unknown names.
 * @param {string} raw query string without "?" or form body
 * @param {readonly string[]} allowed
 * @returns {Map<string,{raw:string,value:string}>}
 */
export function parseBindingParameters(raw, allowed) {
  const params = new Map();
  if (typeof raw !== "string" || raw === "") return params;
  if (MALFORMED_ESCAPE.test(raw)) refuse("saml_noncanonical_encoding", "SAML message rejected: malformed percent-encoding");
  for (const pair of raw.split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 1) refuse("saml_noncanonical_encoding", "SAML message rejected: every parameter needs a name and a value");
    const name = formDecode(pair.slice(0, eq)), encoded = pair.slice(eq + 1);
    if (!allowed.includes(name)) refuse("saml_unknown_parameter", "SAML message rejected: unexpected parameter");
    if (params.has(name)) refuse("saml_duplicate_parameter", "SAML message rejected: " + name + " appears more than once");
    params.set(name, { raw: encoded, value: formDecode(encoded) });
  }
  return params;
}

const STRICT_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
/** @returns {Uint8Array} */
function strictBase64(value, what) {
  if (typeof value !== "string" || !value || value.length % 4 || !STRICT_BASE64.test(value))
    refuse("saml_unreadable", what + " is not valid base64");
  try { return fromBase64(value); } catch { return refuse("saml_unreadable", what + " is not valid base64"); }
}
/** @returns {string} */
const utf8 = bytes => {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { return refuse("saml_unreadable", "SAMLRequest is not UTF-8 XML"); }
};

/** HTTP-Redirect: base64 of raw DEFLATE. Inflated output is capped (no decompression bombs). */
export async function decodeRedirectRequest(value) {
  const compressed = strictBase64(value, "SAMLRequest");
  const stream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const reader = stream.getReader(), chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value: chunk } = await reader.read();
      if (done) break;
      size += chunk.length;
      if (size > MAX_REQUEST_XML_BYTES) { await reader.cancel().catch(() => {}); refuse("saml_unreadable", "SAMLRequest is too large"); }
      chunks.push(chunk);
    }
  } catch (e) {
    if (e instanceof SamlRequestError) throw e;
    refuse("saml_unreadable", "SAMLRequest could not be inflated");
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return utf8(out);
}

/** HTTP-POST: base64 (line breaks tolerated) of the XML. */
export function decodePostRequest(value) {
  const bytes = strictBase64(String(value ?? "").replace(/[\r\n]/g, ""), "SAMLRequest");
  if (bytes.length > MAX_REQUEST_XML_BYTES) refuse("saml_unreadable", "SAMLRequest is too large");
  return utf8(bytes);
}

/** RelayState is opaque to Nathan: bounded and free of control characters, echoed back verbatim. */
export function checkRelayState(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > MAX_RELAY_STATE || /[\x00-\x1f\x7f]/.test(value))
    refuse("saml_invalid_request", "RelayState is too long or contains control characters");
  return value;
}

// ------------------------------------------------------------------------------- AuthnRequest

const ID_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,255}$/;
/** @returns {any[]} */
const elementChildren = el => Array.from(el.childNodes || []).filter(n => /** @type {any} */ (n).nodeType === 1);
const childrenNamed = (el, ns, name) => elementChildren(el).filter(n => n.namespaceURI === ns && n.localName === name);

function parseXml(xml) {
  if (typeof xml !== "string" || !xml.trim()) refuse("saml_unreadable", "Empty SAML message");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) refuse("saml_unreadable", "SAML messages must not contain a DTD");
  const weak = weakSamlAlgorithm(xml);
  if (weak && /^weak algorithm/.test(weak)) refuse("saml_weak_algorithm", "SAML request rejected: SHA-1/MD5 signatures and digests are not accepted");
  if (weak) refuse("saml_unreadable", "Unreadable SAML message");
  let failed = false, doc;
  try {
    doc = new DOMParser({ onError: level => { if (level !== "warning") failed = true; } }).parseFromString(xml, "application/xml");
  } catch { failed = true; }
  if (failed || !doc?.documentElement) refuse("saml_unreadable", "Unreadable SAML message");
  return /** @type {any} */ (doc);
}

/** Every ID-like attribute value in the document must be unique (signature-wrapping defense). */
function assertUniqueIds(root) {
  const seen = new Set(), stack = [root];
  while (stack.length) {
    const el = stack.pop();
    for (const name of ["ID", "Id", "id"]) {
      if (!el.hasAttribute(name)) continue;
      const v = el.getAttribute(name);
      if (seen.has(v)) refuse("saml_invalid_request", "SAML request rejected: duplicate ID");
      seen.add(v);
    }
    stack.push(...elementChildren(el));
  }
}
/** @returns {boolean} */
const bool = (el, name) => {
  if (!el.hasAttribute(name)) return false;
  const v = el.getAttribute(name);
  if (v === "true" || v === "1") return true;
  if (v === "false" || v === "0") return false;
  return refuse("saml_invalid_request", name + " must be a boolean");
};

/**
 * Parses and checks one AuthnRequest. Returns its fields; nothing else from the message is used.
 * @param {string} xml @param {{ now?: number }} [options]
 */
export function parseAuthnRequest(xml, { now = Date.now() } = {}) {
  const doc = parseXml(xml);
  const root = doc.documentElement;
  if (root.namespaceURI !== NS.protocol || root.localName !== "AuthnRequest")
    refuse("saml_invalid_request", "SAML message is not an AuthnRequest");
  assertUniqueIds(root);
  if (root.getAttribute("Version") !== "2.0") refuse("saml_invalid_request", "Only SAML 2.0 AuthnRequests are accepted");
  const id = root.getAttribute("ID");
  if (!ID_PATTERN.test(id || "")) refuse("saml_invalid_request", "AuthnRequest ID is missing or invalid");
  const instant = root.getAttribute("IssueInstant") || "";
  const issued = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(instant) ? Date.parse(instant) : NaN;
  if (!Number.isFinite(issued)) refuse("saml_invalid_request", "AuthnRequest IssueInstant is missing or not UTC");
  if (issued < now - REQUEST_MAX_AGE_MS - CLOCK_SKEW_MS || issued > now + CLOCK_SKEW_MS)
    refuse("saml_stale_request", "AuthnRequest is too old or issued in the future; start the sign-in again from the application");
  const issuers = childrenNamed(root, NS.assertion, "Issuer");
  if (issuers.length !== 1) refuse("saml_invalid_request", "AuthnRequest must have exactly one Issuer");
  const issuerFormat = issuers[0].getAttribute("Format");
  if (issuerFormat && issuerFormat !== NAMEID.entity) refuse("saml_invalid_request", "AuthnRequest Issuer must be an entity ID");
  const issuer = (issuers[0].textContent || "").trim();
  if (!issuer || issuer.length > 1024) refuse("saml_invalid_request", "AuthnRequest Issuer is missing");
  if (childrenNamed(root, NS.assertion, "Subject").length) refuse("saml_invalid_request", "AuthnRequests naming a Subject are not supported");
  const acsUrl = root.hasAttribute("AssertionConsumerServiceURL") ? root.getAttribute("AssertionConsumerServiceURL") : null;
  const indexText = root.hasAttribute("AssertionConsumerServiceIndex") ? root.getAttribute("AssertionConsumerServiceIndex") : null;
  if (acsUrl !== null && indexText !== null) refuse("saml_invalid_request", "AuthnRequest names both an ACS URL and an ACS index");
  if (indexText !== null && !(/^\d{1,5}$/.test(indexText) && Number(indexText) <= MAX_ACS_INDEX))
    refuse("saml_invalid_request", "AssertionConsumerServiceIndex is invalid");
  const binding = root.getAttribute("ProtocolBinding");
  if (binding && binding !== BINDING.post) refuse("saml_unsupported_binding", "Nathan delivers responses with the HTTP-POST binding only");
  const policies = childrenNamed(root, NS.protocol, "NameIDPolicy");
  if (policies.length > 1) refuse("saml_invalid_request", "AuthnRequest has more than one NameIDPolicy");
  const nameIdFormat = policies[0]?.getAttribute("Format") || null;
  return {
    id: /** @type {string} */ (id), issuer, issueInstant: instant,
    destination: root.hasAttribute("Destination") ? root.getAttribute("Destination") : null,
    acsUrl, acsIndex: indexText === null ? null : Number(indexText),
    forceAuthn: bool(root, "ForceAuthn"), isPassive: bool(root, "IsPassive"),
    nameIdFormat, signed: childrenNamed(root, NS.ds, "Signature").length > 0
  };
}

// ------------------------------------------------------------------------------- request signatures

export const REDIRECT_PARAMETERS = Object.freeze(["SAMLRequest", "RelayState", "SigAlg", "Signature"]);
export const POST_PARAMETERS = Object.freeze(["SAMLRequest", "RelayState"]);

/**
 * HTTP-Redirect signature (SAML bindings §3.4.4.1): RSA over the octets
 * "SAMLRequest=<raw>[&RelayState=<raw>]&SigAlg=<raw>" exactly as received. Returns true when one
 * of the SP's pinned certificates verifies it; throws for a missing, malformed or weak signature.
 * @param {Map<string,{raw:string,value:string}>} params @param {string[]} certificates base64 DER
 */
export async function verifyRedirectSignature(params, certificates) {
  const sigAlg = params.get("SigAlg"), signature = params.get("Signature"), request = params.get("SAMLRequest");
  if (!sigAlg || !signature || !request) return refuse("saml_signature_required", "The service provider must sign its AuthnRequests");
  if (/(sha1|md5)$/i.test(sigAlg.value)) refuse("saml_weak_algorithm", "SAML request rejected: SHA-1/MD5 signatures are not accepted");
  const hash = SIGNATURE_HASHES[sigAlg.value];
  if (!hash) refuse("saml_bad_signature", "Unsupported AuthnRequest signature algorithm");
  const bytes = strictBase64(signature.value, "Signature");
  const relay = params.get("RelayState");
  const octets = new TextEncoder().encode("SAMLRequest=" + request.raw +
    (relay ? "&RelayState=" + relay.raw : "") + "&SigAlg=" + sigAlg.raw);
  for (const cert of certificates) {
    try {
      const key = await importCertificateKey(cert, hash);
      if (await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, bytes, octets)) return true;
    } catch { /* try the next pinned certificate */ }
  }
  return false;
}

const pem = b64 => "-----BEGIN CERTIFICATE-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";

/**
 * Enveloped XML signature of a POSTed AuthnRequest. The signature must be a direct child of the
 * root, with exactly one Reference to "#<root ID>", only enveloped-signature and exclusive c14n
 * transforms, and SHA-256 or stronger. Returns the signed bytes (the canonical root element
 * without the signature) when a pinned certificate verifies it, else null. The caller processes
 * those bytes, never the outer document.
 * @param {string} xml @param {string[]} certificates
 * @returns {string|null}
 */
export function verifyPostSignature(xml, certificates) {
  const root = parseXml(xml).documentElement;
  const signatures = childrenNamed(root, NS.ds, "Signature");
  if (signatures.length !== 1) refuse("saml_signature_required", "The service provider must sign its AuthnRequests");
  const sig = signatures[0];
  const references = Array.from(sig.getElementsByTagNameNS(NS.ds, "Reference"));
  const id = root.getAttribute("ID");
  if (references.length !== 1 || references[0].getAttribute("URI") !== "#" + id)
    refuse("saml_bad_signature", "The AuthnRequest signature must cover the whole request");
  const transforms = Array.from(references[0].getElementsByTagNameNS(NS.ds, "Transform")).map(t => t.getAttribute("Algorithm"));
  if (!transforms.every(t => t === ENVELOPED || t === EXC_C14N)) refuse("saml_bad_signature", "Unsupported signature transform");
  const method = sig.getElementsByTagNameNS(NS.ds, "SignatureMethod")[0]?.getAttribute("Algorithm") || "";
  const digest = references[0].getElementsByTagNameNS(NS.ds, "DigestMethod")[0]?.getAttribute("Algorithm") || "";
  if (!SIGNATURE_HASHES[method] || !DIGESTS.has(digest)) refuse("saml_bad_signature", "Unsupported signature or digest algorithm");
  for (const cert of certificates) {
    const verifier = new SignedXml({ publicCert: pem(cert), getCertFromKeyInfo: () => null });
    try {
      verifier.loadSignature(sig);
      if (verifier.checkSignature(xml)) {
        const signed = verifier.getSignedReferences();
        if (signed.length === 1) return signed[0];
      }
    } catch { /* try the next pinned certificate */ }
  }
  return null;
}

// ------------------------------------------------------------------------------- responses

/** XML text and attribute escaping; characters XML 1.0 cannot carry are dropped. */
export function xmlEscape(value) {
  return String(value)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
const iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
const randomId = () => "_" + [...crypto.getRandomValues(new Uint8Array(20))].map(b => b.toString(16).padStart(2, "0")).join("");

/** xml-crypto signer backed by a non-extractable WebCrypto RSA key (computeSignatureAsync only). */
class WebCryptoRsaSha256 {
  getSignature() { throw Error("Nathan signs SAML messages asynchronously"); }
  async getSignatureAsync(signedInfo, key) {
    const data = typeof signedInfo === "string" ? new TextEncoder().encode(signedInfo) : signedInfo;
    return toBase64(new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data)));
  }
  verifySignature() { throw Error("Signing only"); }
  getAlgorithmName() { return RSA_SHA256; }
}

async function sign(xml, { elementXpath, issuerXpath, key, certificate }) {
  const signer = new SignedXml({
    privateKey: key, signatureAlgorithm: RSA_SHA256, canonicalizationAlgorithm: EXC_C14N,
    getKeyInfoContent: () => "<ds:X509Data><ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data>"
  });
  /** @type {any} */ (signer).SignatureAlgorithms = { [RSA_SHA256]: WebCryptoRsaSha256 };
  signer.addReference({ xpath: elementXpath, digestAlgorithm: SHA256, transforms: [ENVELOPED, EXC_C14N] });
  await signer.computeSignatureAsync(xml, { prefix: "ds", location: { reference: issuerXpath, action: "after" } });
  return signer.getSignedXml();
}

const ATTRIBUTE_URI = /^[a-z][a-z0-9+.-]*:/i;

/**
 * Builds and signs a SAML Response for one SP: the Assertion is always signed (RSA-SHA256,
 * SHA-256 digest, exclusive c14n), the Response too when the SP asks for it. Returns base64.
 * @param {{ idpEntityId: string, spEntityId: string, acsUrl: string, inResponseTo: string|null,
 *   nameId: { format: string, value: string }, attributes: { name: string, values: string[] }[],
 *   authnInstant: number, authnContext: string, signResponse: boolean, key: CryptoKey,
 *   certificate: string, now?: number }} input
 */
export async function buildSignedResponse(input) {
  const now = input.now ?? Date.now();
  const issued = iso(now), notBefore = iso(now - ASSERTION_BEFORE_MS), notOnOrAfter = iso(now + ASSERTION_AFTER_MS);
  const responseId = randomId(), assertionId = randomId();
  const irt = input.inResponseTo ? ' InResponseTo="' + xmlEscape(input.inResponseTo) + '"' : "";
  const idp = xmlEscape(input.idpEntityId), sp = xmlEscape(input.spEntityId), acs = xmlEscape(input.acsUrl);
  const qualifiers = input.nameId.format === NAMEID.persistent ? ' NameQualifier="' + idp + '" SPNameQualifier="' + sp + '"' : "";
  const attributes = input.attributes.filter(a => a.values.length).map(a =>
    '<saml:Attribute Name="' + xmlEscape(a.name) + '" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:' +
    (ATTRIBUTE_URI.test(a.name) ? "uri" : "basic") + '">' +
    a.values.map(v => "<saml:AttributeValue>" + xmlEscape(v) + "</saml:AttributeValue>").join("") + "</saml:Attribute>").join("");
  const assertion =
    '<saml:Assertion xmlns:saml="' + NS.assertion + '" ID="' + assertionId + '" Version="2.0" IssueInstant="' + issued + '">' +
    "<saml:Issuer>" + idp + "</saml:Issuer>" +
    '<saml:Subject><saml:NameID Format="' + input.nameId.format + '"' + qualifiers + ">" + xmlEscape(input.nameId.value) + "</saml:NameID>" +
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData' + irt +
    ' NotOnOrAfter="' + notOnOrAfter + '" Recipient="' + acs + '"/></saml:SubjectConfirmation></saml:Subject>' +
    '<saml:Conditions NotBefore="' + notBefore + '" NotOnOrAfter="' + notOnOrAfter + '"><saml:AudienceRestriction><saml:Audience>' +
    sp + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>" +
    '<saml:AuthnStatement AuthnInstant="' + iso(input.authnInstant) + '"><saml:AuthnContext><saml:AuthnContextClassRef>' +
    xmlEscape(input.authnContext) + "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>" +
    (attributes ? "<saml:AttributeStatement>" + attributes + "</saml:AttributeStatement>" : "") +
    "</saml:Assertion>";
  let xml =
    '<samlp:Response xmlns:samlp="' + NS.protocol + '" xmlns:saml="' + NS.assertion + '" ID="' + responseId + '" Version="2.0" IssueInstant="' +
    issued + '" Destination="' + acs + '"' + irt + ">" +
    "<saml:Issuer>" + idp + '</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    assertion + "</samlp:Response>";
  const signing = { key: input.key, certificate: input.certificate };
  xml = await sign(xml, { ...signing, elementXpath: "//*[local-name(.)='Assertion' and @ID='" + assertionId + "']",
    issuerXpath: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']" });
  if (input.signResponse)
    xml = await sign(xml, { ...signing, elementXpath: "/*[local-name(.)='Response' and @ID='" + responseId + "']",
      issuerXpath: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']" });
  return { response: toBase64(new TextEncoder().encode(xml)), responseId, assertionId };
}

/** IdP metadata: signing certificates (active first, then the next and previous keys) and both SSO bindings. */
export function buildIdpMetadata({ entityId, ssoUrl, certificates }) {
  const keys = certificates.map(c =>
    '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="' + NS.ds + '"><ds:X509Data><ds:X509Certificate>' + c +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>").join("");
  return '<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="' + NS.metadata + '" entityID="' + xmlEscape(entityId) + '">' +
    '<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="' + NS.protocol + '">' + keys +
    "<md:NameIDFormat>" + NAMEID.persistent + "</md:NameIDFormat><md:NameIDFormat>" + NAMEID.email + "</md:NameIDFormat>" +
    '<md:SingleSignOnService Binding="' + BINDING.redirect + '" Location="' + xmlEscape(ssoUrl) + '"/>' +
    '<md:SingleSignOnService Binding="' + BINDING.post + '" Location="' + xmlEscape(ssoUrl) + '"/>' +
    "</md:IDPSSODescriptor></md:EntityDescriptor>";
}

// ------------------------------------------------------------------------------- SP registration

export const SP_ID = /^[a-z][a-z0-9-]{1,62}$/;
export const ATTRIBUTE_SOURCES = Object.freeze(["email", "name", "roles", "groups", "permissions", "persistent_id"]);
export const MAX_ACS_URLS = 8;
/** AssertionConsumerService index is an xs:unsignedShort in SAML metadata. */
export const MAX_ACS_INDEX = 65535;
const isAcsIndex = v => Number.isInteger(v) && v >= 0 && v <= MAX_ACS_INDEX;
const MAX_ATTRIBUTES = 16;
const MAX_SP_CERTIFICATES = 3;

/** An exact, canonical HTTPS ACS URL. Queries are allowed (Salesforce uses ?so=); wildcards are not. */
export function checkAcsUrl(value) {
  if (typeof value !== "string" || !value || value.length > 1024 || /[\s\x00-\x1f\x7f*]/.test(value))
    throw Error("ACS URL must be an exact https URL without wildcards");
  let url;
  try { url = new URL(value); } catch { throw Error("ACS URL is not a valid URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || value.includes("#"))
    throw Error("ACS URL must use https, without credentials or fragment");
  // Exact string matching follows, so only one spelling per URL is accepted: the canonical one, or
  // the canonical one without the root "/" before a query (Salesforce's https://x.my.salesforce.com?so=...).
  if (url.href !== value && !(url.pathname === "/" && url.search && value === url.origin + url.search))
    throw Error("ACS URL must be written in canonical form: " + url.href);
  // The same DNS host test the auto-post page's form-action applies (src/ui/headers.ts), so a stored
  // ACS URL can always be posted to: no "_", no trailing dot.
  if (!url.hostname.includes(".") || /^(localhost|\d+\.\d+\.\d+\.\d+|\[.*\])$/i.test(url.hostname)
    || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(url.hostname))
    throw Error("ACS URL must use a public DNS hostname");
  return value;
}
/** @param {unknown} value @param {string|null} idpEntityId @returns {string} */
export function checkEntityId(value, idpEntityId) {
  if (typeof value !== "string" || !value.trim() || value.length > 1024 || /[\x00-\x1f\x7f<>"]/.test(value))
    throw Error("SP entity ID is missing or contains unsupported characters");
  if (value.trim() !== value) throw Error("SP entity ID must not start or end with whitespace");
  if (value === idpEntityId) throw Error("SP entity ID must not be Nathan's own entity ID");
  return value;
}
const flag = (value, name) => {
  if (value === undefined || value === null) return false;
  if (typeof value !== "boolean") throw Error("Invalid " + name + ": expected true or false");
  return value;
};

/**
 * Validates an administrator's SP registration. Throws an admin-readable Error.
 * @param {any} input @param {{ idpEntityId: string, isAppId: (v: unknown) => boolean }} context
 */
export async function validateServiceProvider(input, { idpEntityId, isAppId }) {
  if (!input || typeof input !== "object") throw Error("Invalid service provider");
  if (typeof input.id !== "string" || !SP_ID.test(input.id)) throw Error("Invalid SP ID: lowercase letters, digits and dashes");
  if (typeof input.name !== "string" || !input.name.trim() || input.name.length > 100 || /[\x00-\x1f\x7f]/.test(input.name))
    throw Error("Invalid SP name");
  const entityId = checkEntityId(input.entityId, idpEntityId);
  if (!isAppId(input.appId)) throw Error("Invalid application: every service provider is bound to one Nathan application");
  if (!Array.isArray(input.acsUrls) || !input.acsUrls.length || input.acsUrls.length > MAX_ACS_URLS)
    throw Error("Give 1 to " + MAX_ACS_URLS + " ACS URLs");
  const acsUrls = input.acsUrls.map(checkAcsUrl);
  if (new Set(acsUrls).size !== acsUrls.length) throw Error("ACS URLs must be unique");
  // Each URL's AssertionConsumerServiceIndex: the SP metadata's index values, or 0, 1, ... in the
  // order given when entered by hand. Requests naming an index are resolved by these values.
  const acsIndexes = input.acsIndexes ?? acsUrls.map((_, i) => i);
  if (!Array.isArray(acsIndexes) || acsIndexes.length !== acsUrls.length || !acsIndexes.every(isAcsIndex))
    throw Error("Give one ACS index (0 to " + MAX_ACS_INDEX + ") per ACS URL, or none");
  if (new Set(acsIndexes).size !== acsIndexes.length) throw Error("ACS indexes must be unique");
  const nameIdFormat = input.nameIdFormat ?? "persistent";
  if (nameIdFormat !== "persistent" && nameIdFormat !== "email") throw Error("Invalid NameID format: persistent or email");
  const attributes = input.attributes ?? [];
  if (!Array.isArray(attributes) || attributes.length > MAX_ATTRIBUTES) throw Error("At most " + MAX_ATTRIBUTES + " attributes");
  const names = new Set();
  const mapped = attributes.map(a => {
    if (!a || typeof a.name !== "string" || !/^[\x21-\x7e]{1,256}$/.test(a.name) || /[<>&"']/.test(a.name))
      throw Error("Invalid attribute name");
    if (!ATTRIBUTE_SOURCES.includes(a.source)) throw Error("Invalid attribute source: " + ATTRIBUTE_SOURCES.join(", "));
    if (names.has(a.name)) throw Error("Attribute names must be unique");
    names.add(a.name);
    return { name: a.name, source: a.source };
  });
  const wantRequestsSigned = flag(input.wantRequestsSigned, "wantRequestsSigned");
  const certs = input.certificates ?? [];
  if (!Array.isArray(certs) || certs.length > MAX_SP_CERTIFICATES) throw Error("At most " + MAX_SP_CERTIFICATES + " SP signing certificates");
  /** @type {{der:string,sha256:string,notAfter:string}[]} */
  const certificates = [];
  for (const c of certs) {
    const checked = await certificateFromInput(c);
    if (!certificates.some(x => x.sha256 === checked.sha256)) certificates.push({ der: checked.der, sha256: checked.sha256, notAfter: checked.notAfter });
  }
  if (wantRequestsSigned && !certificates.length) throw Error("Add the SP's signing certificate to require signed AuthnRequests");
  const allowIdpInitiated = flag(input.allowIdpInitiated, "allowIdpInitiated");
  let defaultRelayState = input.defaultRelayState ?? null;
  if (defaultRelayState === "") defaultRelayState = null;
  if (defaultRelayState !== null) {
    try { checkRelayState(defaultRelayState); } catch { throw Error("Default RelayState is too long or contains control characters"); }
    if (!allowIdpInitiated) throw Error("A default RelayState is only used for IdP-initiated sign-in");
  }
  return { id: input.id, name: input.name.trim(), entityId, appId: input.appId, acsUrls, acsIndexes, nameIdFormat, attributes: mapped,
    wantRequestsSigned, certificates, signResponse: flag(input.signResponse, "signResponse"),
    requirePasskey: flag(input.requirePasskey, "requirePasskey"), allowIdpInitiated, defaultRelayState };
}

/**
 * Reads SP metadata to pre-fill a registration. Nothing from it is stored directly: the
 * administrator reviews the values, and create/update validate them again. No DTD, ≤ 100 KiB.
 */
export async function parseSpMetadata(xml, { now = Date.now() } = {}) {
  if (typeof xml !== "string" || !xml.trim()) throw Error("Paste the SP metadata XML");
  if (new TextEncoder().encode(xml).length > MAX_METADATA_BYTES) throw Error("SP metadata is too large (limit " + MAX_METADATA_BYTES + " bytes)");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw Error("SP metadata must not contain a DTD (DOCTYPE/ENTITY)");
  let failed = false, doc;
  try { doc = new DOMParser({ onError: level => { if (level !== "warning") failed = true; } }).parseFromString(xml.trim(), "application/xml"); }
  catch { failed = true; }
  const root = /** @type {any} */ (doc)?.documentElement;
  if (failed || !root) throw Error("SP metadata is not well-formed XML");
  if (root.namespaceURI !== NS.metadata || root.localName !== "EntityDescriptor")
    throw Error("SP metadata must have a single SAML 2.0 EntityDescriptor root element");
  const entityId = root.getAttribute("entityID") || "";
  const descriptors = childrenNamed(root, NS.metadata, "SPSSODescriptor");
  if (descriptors.length !== 1) throw Error("SP metadata must contain exactly one SPSSODescriptor");
  const sp = descriptors[0];
  if (!(sp.getAttribute("protocolSupportEnumeration") || "").split(/\s+/).includes(NS.protocol))
    throw Error("SPSSODescriptor does not support the SAML 2.0 protocol");
  const warnings = [];
  const services = childrenNamed(sp, NS.metadata, "AssertionConsumerService");
  const post = services.filter(s => s.getAttribute("Binding") === BINDING.post);
  if (services.length > post.length) warnings.push("Ignored ACS endpoints that do not use the HTTP-POST binding.");
  post.sort((a, b) => Number(b.getAttribute("isDefault") === "true") - Number(a.getAttribute("isDefault") === "true") ||
    Number(a.getAttribute("index") || 0) - Number(b.getAttribute("index") || 0));
  const acsUrls = [], declared = [];
  for (const s of post) {
    const location = s.getAttribute("Location") || "";
    try { checkAcsUrl(location); } catch (e) { warnings.push("Skipped ACS URL: " + /** @type {Error} */ (e).message); continue; }
    if (acsUrls.includes(location)) continue;
    acsUrls.push(location);
    const text = s.getAttribute("index");
    declared.push(text !== null && /^\d{1,5}$/.test(text) && isAcsIndex(Number(text)) ? Number(text) : null);
  }
  if (!acsUrls.length) throw Error("SP metadata has no usable HTTPS HTTP-POST AssertionConsumerService");
  if (acsUrls.length > MAX_ACS_URLS) throw Error("SP metadata lists more than " + MAX_ACS_URLS + " ACS URLs");
  // Keep each endpoint's metadata index; a missing, invalid or repeated one gets the lowest free number.
  const acsIndexes = [];
  declared.forEach((index, i) => {
    if (index !== null && !acsIndexes.includes(index)) { acsIndexes.push(index); return; }
    let free = 0;
    while (acsIndexes.includes(free) || declared.slice(i + 1).includes(free)) free++;
    warnings.push("ACS URL " + acsUrls[i] + " has no usable unique index in the metadata; Nathan numbers it " + free + ".");
    acsIndexes.push(free);
  });
  const certificates = [];
  for (const key of childrenNamed(sp, NS.metadata, "KeyDescriptor")) {
    const use = key.getAttribute("use");
    if (use && use !== "signing") continue;
    for (const c of Array.from(key.getElementsByTagNameNS(NS.ds, "X509Certificate"))) {
      const b64 = (/** @type {any} */ (c).textContent || "").replace(/\s+/g, "");
      try { const checked = await certificateFromInput(b64, { now }); if (!certificates.includes(checked.der)) certificates.push(checked.der); }
      catch (e) { warnings.push("Skipped SP signing certificate: " + /** @type {Error} */ (e).message); }
    }
  }
  const formats = childrenNamed(sp, NS.metadata, "NameIDFormat").map(n => (n.textContent || "").trim());
  const requestsSigned = sp.getAttribute("AuthnRequestsSigned") === "true" || sp.getAttribute("AuthnRequestsSigned") === "1";
  if (requestsSigned && !certificates.length) warnings.push("The SP signs AuthnRequests but its metadata has no usable signing certificate.");
  return {
    entityId: checkEntityId(entityId, null), acsUrls, acsIndexes,
    nameIdFormat: formats.length && formats.every(f => f === NAMEID.email) ? "email" : "persistent",
    wantRequestsSigned: requestsSigned && certificates.length > 0, certificates: certificates.slice(0, MAX_SP_CERTIFICATES), warnings
  };
}
