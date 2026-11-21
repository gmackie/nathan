/**
 * Validation and normalization of SAML identity-provider metadata for
 * Nathan's inbound enterprise SAML connections. Runtime-independent: runs in
 * Node tests and in workerd. Nathan stores only the normalized values and
 * hands the Better Auth SSO plugin a canonical metadata document rebuilt from
 * them, never the administrator-supplied XML.
 */
import { DOMParser } from "@xmldom/xmldom";
import { fetchNoRedirect } from "../shared/security.mjs";

/** Matches @better-auth/sso's default saml.maxMetadataSize. */
export const MAX_METADATA_BYTES = 102400;
export const EXPIRY_WARNING_DAYS = 30;
const MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
const REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const DAY = 86400e3;

// ---------------------------------------------------------------- X.509 / DER

function readTlv(bytes, offset) {
  if (offset + 2 > bytes.length) throw Error("Truncated certificate");
  const tag = bytes[offset];
  let len = bytes[offset + 1], head = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3 || offset + 2 + n > bytes.length) throw Error("Unsupported certificate length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[offset + 2 + i];
    head += n;
  }
  const start = offset + head, end = start + len;
  if (end > bytes.length) throw Error("Truncated certificate");
  return { tag, start, end, next: end };
}
function children(bytes, node) {
  const out = [];
  for (let at = node.start; at < node.end;) { const c = readTlv(bytes, at); out.push(c); at = c.next; }
  return out;
}
function oidString(bytes, node) {
  if (node.tag !== 0x06) throw Error("Expected OID");
  const b = bytes.subarray(node.start, node.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let value = 0;
  for (let i = 1; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(value); value = 0; }
  }
  return parts.join(".");
}
function timeValue(bytes, node) {
  const s = new TextDecoder().decode(bytes.subarray(node.start, node.end));
  const m = node.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
    : node.tag === 0x18 ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : null;
  if (!m) throw Error("Unsupported certificate validity encoding");
  let year = Number(m[1]);
  if (node.tag === 0x17) year += year >= 50 ? 1900 : 2000;
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}
const SIGNATURE_ALGORITHMS = {
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.10": "RSASSA-PSS"
};
const WEAK_SIGNATURE_ALGORITHMS = {
  "1.2.840.113549.1.1.5": "SHA-1", "1.2.840.113549.1.1.4": "MD5", "1.2.840.113549.1.1.2": "MD2",
  "1.3.14.3.2.29": "SHA-1", "1.2.840.10040.4.3": "SHA-1 (DSA)", "1.2.840.10045.4.1": "SHA-1 (ECDSA)"
};
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0").toUpperCase()).join(":");
function base64ToBytes(b64) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length % 4) throw Error("Certificate is not valid base64");
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
class PolicyError extends Error {}

/**
 * Parses a DER X.509 certificate (base64, no PEM armour) and enforces Nathan's
 * signing-certificate policy: RSA keys of at least 2048 bits signed with SHA-2,
 * currently within their validity period.
 */
export async function inspectCertificate(b64, { now = Date.now() } = {}) {
  let bytes, sigAlg, notBefore, notAfter, bits;
  try {
    bytes = base64ToBytes(b64);
    const cert = readTlv(bytes, 0);
    if (cert.tag !== 0x30 || cert.end !== bytes.length) throw Error("not a certificate");
    const [tbsNode, algNode] = children(bytes, cert);
    let tbs = children(bytes, tbsNode);
    if (tbs[0].tag === 0xa0) tbs = tbs.slice(1);
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    const [, , , validity, , spki] = tbs;
    sigAlg = oidString(bytes, children(bytes, algNode)[0]);
    const [nb, na] = children(bytes, validity);
    notBefore = timeValue(bytes, nb); notAfter = timeValue(bytes, na);
    const [keyAlg, keyBits] = children(bytes, spki);
    if (oidString(bytes, children(bytes, keyAlg)[0]) !== "1.2.840.113549.1.1.1")
      throw new PolicyError("Only RSA signing certificates are supported");
    // BIT STRING: one unused-bits byte, then RSAPublicKey ::= SEQUENCE { modulus, exponent }.
    const rsa = readTlv(bytes, keyBits.start + 1);
    const modulus = children(bytes, rsa)[0];
    let m = bytes.subarray(modulus.start, modulus.end);
    while (m.length && m[0] === 0) m = m.subarray(1);
    bits = m.length ? (m.length - 1) * 8 + (32 - Math.clz32(m[0])) : 0;
  } catch (e) {
    if (e instanceof PolicyError) throw Error(e.message);
    throw Error("Signing certificate could not be parsed as an X.509 certificate");
  }
  if (WEAK_SIGNATURE_ALGORITHMS[sigAlg])
    throw Error("Signing certificate uses a " + WEAK_SIGNATURE_ALGORITHMS[sigAlg] + " signature; SHA-1 and weaker are rejected");
  if (!SIGNATURE_ALGORITHMS[sigAlg]) throw Error("Signing certificate uses an unsupported signature algorithm (" + sigAlg + ")");
  if (bits < 2048) throw Error("Signing certificate RSA key is " + bits + " bits; at least 2048 bits are required");
  if (now < notBefore) throw Error("Signing certificate is not yet valid (valid from " + new Date(notBefore).toISOString() + ")");
  if (now >= notAfter) throw Error("Signing certificate expired on " + new Date(notAfter).toISOString());
  return {
    der: b64, sha256: hex(await crypto.subtle.digest("SHA-256", bytes)), bits,
    signatureAlgorithm: SIGNATURE_ALGORITHMS[sigAlg],
    notBefore: new Date(notBefore).toISOString(), notAfter: new Date(notAfter).toISOString(),
    expiringSoon: notAfter - now < EXPIRY_WARNING_DAYS * DAY
  };
}

/** Accepts a PEM or bare base64 certificate pasted by an administrator. */
export async function certificateFromInput(input, options) {
  if (typeof input !== "string" || input.length > 16384) throw Error("Certificate must be a PEM or base64 string");
  const body = input.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  if (!body) throw Error("Certificate is empty");
  return inspectCertificate(body, options);
}

// ------------------------------------------------------------------- metadata

function httpsUrl(value, what) {
  let url;
  try { url = new URL(value); } catch { throw Error(what + " is not a valid URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash)
    throw Error(what + " must be an HTTPS URL without credentials or fragment");
  return url.href;
}
function checkEntityID(value) {
  if (typeof value !== "string" || !value.trim()) throw Error("IdP metadata is missing the entityID");
  if (value.length > 1024 || /[\x00-\x1f\x7f<>"]/.test(value)) throw Error("IdP entityID contains unsupported characters");
  return value.trim();
}
const directChildren = (el, ns, name) =>
  Array.from(el.childNodes || []).filter(n => n.nodeType === 1 && n.namespaceURI === ns && n.localName === name);

/**
 * Parses pasted IdP metadata XML and returns the normalized connection values
 * plus warnings. Throws an Error with an administrator-readable message.
 */
export async function parseIdpMetadata(xml, { now = Date.now(), maxBytes = MAX_METADATA_BYTES } = {}) {
  if (typeof xml !== "string" || !xml.trim()) throw Error("Paste the IdP metadata XML");
  if (new TextEncoder().encode(xml).length > maxBytes) throw Error("IdP metadata is too large (limit " + maxBytes + " bytes)");
  // No DTDs at all: rules out entity expansion and external entity tricks.
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw Error("IdP metadata must not contain a DTD (DOCTYPE/ENTITY)");
  const errors = [];
  let doc;
  try {
    doc = new DOMParser({ onError: (level, msg) => { if (level !== "warning") errors.push(msg); } })
      .parseFromString(xml.trim(), "application/xml");
  } catch { throw Error("IdP metadata is not well-formed XML"); }
  const root = doc?.documentElement;
  if (errors.length || !root) throw Error("IdP metadata is not well-formed XML");
  if (root.namespaceURI !== MD || root.localName !== "EntityDescriptor")
    throw Error("IdP metadata must have a single SAML 2.0 EntityDescriptor root element");
  const warnings = [];
  const entityID = checkEntityID(root.getAttribute("entityID"));
  const validUntil = root.getAttribute("validUntil");
  if (validUntil) {
    const t = Date.parse(validUntil);
    if (Number.isNaN(t)) throw Error("IdP metadata validUntil is not a valid timestamp");
    if (t <= now) throw Error("IdP metadata expired (validUntil " + validUntil + ")");
  }
  for (const sig of directChildren(root, DS, "Signature")) {
    const method = sig.getElementsByTagNameNS(DS, "SignatureMethod")[0]?.getAttribute("Algorithm") || "";
    const digests = Array.from(sig.getElementsByTagNameNS(DS, "DigestMethod")).map(d => d.getAttribute("Algorithm") || "");
    if (/sha1$/i.test(method) || digests.some(d => /sha1$/i.test(d)))
      throw Error("IdP metadata is signed with SHA-1; SHA-1 signatures are rejected");
    warnings.push("Metadata signature not verified; Nathan pins the signing certificates listed instead. Confirm their fingerprints with your IdP administrator.");
  }
  const idps = directChildren(root, MD, "IDPSSODescriptor");
  if (idps.length !== 1) throw Error("IdP metadata must contain exactly one IDPSSODescriptor");
  const idp = idps[0];
  if (!(idp.getAttribute("protocolSupportEnumeration") || "").split(/\s+/).includes(PROTOCOL))
    throw Error("IDPSSODescriptor does not support the SAML 2.0 protocol");

  const sso = directChildren(idp, MD, "SingleSignOnService")
    .filter(s => [REDIRECT, POST].includes(s.getAttribute("Binding")));
  if (!sso.length) throw Error("IdP metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService");
  let ssoRedirectUrl = null, ssoPostUrl = null;
  for (const s of sso) {
    const url = httpsUrl(s.getAttribute("Location") || "", "SingleSignOnService Location");
    if (s.getAttribute("Binding") === REDIRECT) ssoRedirectUrl ??= url; else ssoPostUrl ??= url;
  }
  if (!ssoRedirectUrl)
    throw Error("IdP metadata needs an HTTP-Redirect SingleSignOnService; Nathan sends AuthnRequests with the HTTP-Redirect binding");

  const ders = [];
  for (const key of directChildren(idp, MD, "KeyDescriptor")) {
    const use = key.getAttribute("use");
    if (use && use !== "signing") continue;
    for (const c of Array.from(key.getElementsByTagNameNS(DS, "X509Certificate"))) {
      const b64 = (c.textContent || "").replace(/\s+/g, "");
      if (b64 && !ders.includes(b64)) ders.push(b64);
    }
  }
  if (!ders.length) throw Error("IdP metadata has no signing certificate");
  if (ders.length > 4) throw Error("IdP metadata lists more than four signing certificates");
  const certificates = [];
  for (const der of ders) certificates.push(await inspectCertificate(der, { now }));
  for (const c of certificates)
    if (c.expiringSoon) warnings.push("Signing certificate " + c.sha256.slice(0, 23) + "… expires on " + c.notAfter + "; add the IdP's next certificate before then.");
  return { entityID, ssoRedirectUrl, ssoPostUrl, certificates, warnings };
}

const xmlEscape = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * Builds the canonical metadata document handed to the Better Auth SSO plugin
 * from already validated values. Certificates are base64 DER.
 */
export function buildIdpMetadata({ entityID, ssoRedirectUrl, ssoPostUrl, certificates }) {
  checkEntityID(entityID);
  const redirect = httpsUrl(ssoRedirectUrl, "SSO URL");
  const post = ssoPostUrl ? httpsUrl(ssoPostUrl, "SSO POST URL") : null;
  if (!Array.isArray(certificates) || !certificates.length || certificates.some(c => !/^[A-Za-z0-9+/]+={0,2}$/.test(c)))
    throw Error("At least one base64 signing certificate is required");
  const keys = certificates.map(c =>
    `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="${DS}"><ds:X509Data><ds:X509Certificate>${c}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`).join("");
  return `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="${MD}" entityID="${xmlEscape(entityID)}">` +
    `<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="${PROTOCOL}">${keys}` +
    `<md:SingleSignOnService Binding="${REDIRECT}" Location="${xmlEscape(redirect)}"/>` +
    (post ? `<md:SingleSignOnService Binding="${POST}" Location="${xmlEscape(post)}"/>` : "") +
    `</md:IDPSSODescriptor></md:EntityDescriptor>`;
}

/** Nathan's per-connection service-provider values for the IdP administrator. */
export function spValues(issuerOrigin, providerId) {
  const origin = new URL(issuerOrigin).origin;
  const metadataUrl = origin + "/api/auth/sso/saml2/sp/metadata?providerId=" + encodeURIComponent(providerId);
  return { entityId: metadataUrl, acsUrl: origin + "/api/auth/sso/saml2/sp/acs/" + encodeURIComponent(providerId), metadataUrl };
}

function assertPublicHost(url) {
  const host = url.hostname.toLowerCase();
  const ipLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[") || /^[0-9a-f:]+$/.test(host);
  if (ipLiteral || !host.includes(".") || /(^|\.)(localhost|local|internal|intranet|lan|home\.arpa|corp|test|invalid)$/.test(host))
    throw Error("Metadata URL must use a public DNS hostname");
}
const tooLarge = maxBytes => Error("IdP metadata is too large (limit " + maxBytes + " bytes)");

/**
 * Fetches IdP metadata over HTTPS without following redirects, with a body
 * size cap and a timeout. Tests mock globalThis.fetch, so they run this exact path.
 */
export async function fetchIdpMetadata(input, { timeoutMs = 5000, maxBytes = MAX_METADATA_BYTES } = {}) {
  let url;
  try { url = new URL(input); } catch { throw Error("Metadata URL is not a valid URL"); }
  if (url.protocol !== "https:" || url.username || url.password) throw Error("Metadata URL must be HTTPS without credentials");
  assertPublicHost(url);
  const controller = new AbortController();
  const timedOut = () => Error("Metadata fetch timed out after " + timeoutMs + " ms");
  const timer = setTimeout(() => controller.abort(timedOut()), timeoutMs);
  try {
    const init = { headers: { Accept: "application/samlmetadata+xml, application/xml, text/xml" }, signal: controller.signal };
    let response;
    try {
      response = await fetchNoRedirect(url.href, init);
    } catch (e) {
      if (controller.signal.aborted) throw timedOut();
      throw /redirect/i.test(String(e?.message)) ? Error("Metadata URL answered with a redirect; paste the final HTTPS URL") : Error("Metadata fetch failed");
    }
    if (!response.ok) throw Error("Metadata URL returned HTTP " + response.status);
    if (Number(response.headers.get("content-length") || 0) > maxBytes) throw tooLarge(maxBytes);
    const reader = response.body?.getReader();
    if (!reader) return "";
    const chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { await reader.cancel().catch(() => {}); throw tooLarge(maxBytes); }
      chunks.push(value);
    }
    const all = new Uint8Array(total); let at = 0;
    for (const c of chunks) { all.set(c, at); at += c.byteLength; }
    return new TextDecoder().decode(all);
  } catch (e) {
    if (controller.signal.aborted) throw timedOut();
    throw e;
  } finally { clearTimeout(timer); }
}
