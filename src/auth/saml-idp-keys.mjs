/**
 * NATH-12: Nathan's SAML IdP signing keys. Runtime independent (WebCrypto only): runs in workerd
 * and in Node tests. The RSA key pair is generated here, the private key leaves this module only
 * as PKCS#8 for sealing under NATHAN_CONFIG_KEY (config-crypto.mjs, purpose-bound AAD), and the
 * public half is published as a self-signed X.509 certificate, which is what SAML metadata carries.
 *
 * The certificate is plain DER assembled from fixed structures (no parsing of untrusted input), and
 * Nathan's own certificate policy (inspectCertificate) re-checks it before it is stored.
 */
import { inspectCertificate } from "./saml-metadata.mjs";

export const KEY_SIZES = Object.freeze([2048, 3072, 4096]);
export const CERTIFICATE_DAYS = 3 * 365;
const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

// ------------------------------------------------------------------------------- DER encoding

function tlv(tag, body) {
  const len = body.length;
  const head = len < 0x80 ? [len] : len < 0x100 ? [0x81, len] : len < 0x10000 ? [0x82, len >> 8, len & 0xff]
    : [0x83, len >> 16, (len >> 8) & 0xff, len & 0xff];
  const out = new Uint8Array(1 + head.length + len);
  out[0] = tag; out.set(head, 1); out.set(body, 1 + head.length);
  return out;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
const seq = (...parts) => tlv(0x30, concat(...parts));
const set = (...parts) => tlv(0x31, concat(...parts));
function oid(dotted) {
  const [a, b, ...rest] = dotted.split(".").map(Number);
  const bytes = [40 * a + b];
  for (const n of rest) {
    const chunk = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift((v & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return tlv(0x06, Uint8Array.from(bytes));
}
function positiveInteger(bytes) {
  let b = Uint8Array.from(bytes);
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
  if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
  return tlv(0x02, b);
}
function time(ms) {
  const d = new Date(ms), iso = d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";
  const text = new TextEncoder();
  return d.getUTCFullYear() < 2050 ? tlv(0x17, text.encode(iso.slice(2))) : tlv(0x18, text.encode(iso));
}
function commonName(cn) {
  return seq(set(seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)))));
}
export const toBase64 = bytes => { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };
export const fromBase64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

// ------------------------------------------------------------------------------- DER reading

function readTlv(bytes, offset) {
  if (offset + 2 > bytes.length) throw Error("Truncated certificate");
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
  return { tag: bytes[offset], offset, start, end };
}
function childrenOf(bytes, node) {
  const out = [];
  for (let at = node.start; at < node.end;) { const c = readTlv(bytes, at); out.push(c); at = c.end; }
  return out;
}

/** The DER SubjectPublicKeyInfo of a base64 DER certificate, for WebCrypto importKey("spki"). */
export function certificateSpki(b64) {
  const bytes = fromBase64(b64);
  const cert = readTlv(bytes, 0);
  if (cert.tag !== 0x30 || cert.end !== bytes.length) throw Error("Not a certificate");
  let tbs = childrenOf(bytes, childrenOf(bytes, cert)[0]);
  if (tbs[0]?.tag === 0xa0) tbs = tbs.slice(1);
  const spki = tbs[5];
  if (!spki || spki.tag !== 0x30) throw Error("Certificate has no public key");
  return bytes.slice(spki.offset, spki.end);
}

/** A WebCrypto RSA public key (RSASSA-PKCS1-v1_5) from a base64 DER certificate. */
export function importCertificateKey(b64, hash = "SHA-256") {
  return crypto.subtle.importKey("spki", certificateSpki(b64), { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
}

// ------------------------------------------------------------------------------- generation

/**
 * Generates an RSA signing key and its self-signed certificate (SHA-256 with RSA).
 * @param {{ bits?: number, subject: string, now?: number, days?: number }} options
 * @returns {Promise<{ pkcs8: string, certificate: string, sha256: string, bits: number, notBefore: string, notAfter: string }>}
 *   `pkcs8` is base64 DER: seal it immediately, never return it.
 */
export async function generateSigningKey({ bits = 2048, subject, now = Date.now(), days = CERTIFICATE_DAYS }) {
  if (!KEY_SIZES.includes(bits)) throw Error("Key size must be 2048, 3072 or 4096 bits");
  if (typeof subject !== "string" || !subject || subject.length > 64 || /[^\x20-\x7e]/.test(subject)) throw Error("Invalid certificate subject");
  const pair = await crypto.subtle.generateKey({ ...RSA, modulusLength: bits, publicExponent: Uint8Array.of(1, 0, 1) }, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] &= 0x7f; serial[0] |= 0x01;
  const algorithm = seq(oid(SHA256_WITH_RSA), Uint8Array.of(0x05, 0x00));
  const notBefore = now - 5 * 60e3, notAfter = now + days * 86400e3;
  const tbs = seq(
    tlv(0xa0, positiveInteger(Uint8Array.of(2))),
    positiveInteger(serial),
    algorithm,
    commonName(subject),
    seq(time(notBefore), time(notAfter)),
    commonName(subject),
    spki
  );
  const signature = new Uint8Array(await crypto.subtle.sign(RSA, pair.privateKey, tbs));
  const der = seq(tbs, algorithm, tlv(0x03, concat(Uint8Array.of(0), signature)));
  const certificate = toBase64(der);
  const checked = await inspectCertificate(certificate, { now });
  const pkcs8 = toBase64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  return { pkcs8, certificate, sha256: checked.sha256, bits: checked.bits, notBefore: checked.notBefore, notAfter: checked.notAfter };
}

/** Imports a sealed-then-opened PKCS#8 private key for signing only (not extractable). */
export function importSigningKey(pkcs8) {
  return crypto.subtle.importKey("pkcs8", fromBase64(pkcs8), RSA, false, ["sign"]);
}
