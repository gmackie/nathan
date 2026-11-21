/**
 * Test-only X.509 certificate generator. Builds self-signed RSA certificates
 * with chosen validity, key size and signature hash so SAML tests can cover
 * expired, not-yet-valid, weak-key and SHA-1 certificates without openssl.
 */
import { generateKeyPairSync, sign, randomBytes } from "node:crypto";

const tlv = (tag, body) => {
  const len = body.length;
  const head = len < 0x80 ? [len] : len < 0x100 ? [0x81, len] : len < 0x10000 ? [0x82, len >> 8, len & 0xff] : [0x83, len >> 16, (len >> 8) & 0xff, len & 0xff];
  return Buffer.concat([Buffer.from([tag, ...head]), body]);
};
const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const set = (...parts) => tlv(0x31, Buffer.concat(parts));
const nul = () => Buffer.from([0x05, 0x00]);
function oid(dotted) {
  const [a, b, ...rest] = dotted.split(".").map(Number);
  const bytes = [40 * a + b];
  for (const n of rest) {
    const chunk = [n & 0x7f];
    for (let v = n >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}
function integer(buf) {
  let b = Buffer.from(buf);
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}
function time(date) {
  const iso = date.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";
  return date.getUTCFullYear() < 2050 ? tlv(0x17, Buffer.from(iso.slice(2))) : tlv(0x18, Buffer.from(iso));
}
const name = cn => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from(cn)))));
const SIG = { sha256: "1.2.840.113549.1.1.11", sha1: "1.2.840.113549.1.1.5" };

/**
 * @returns {{privateKey:string, certPem:string, certB64:string}}
 */
export function makeCertificate({ cn = "Test IdP", bits = 2048, hash = "sha256", notBefore, notAfter } = {}) {
  const now = Date.now();
  const nb = notBefore ?? new Date(now - 24 * 3600e3);
  const na = notAfter ?? new Date(now + 365 * 24 * 3600e3);
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  const alg = seq(oid(SIG[hash]), nul());
  const tbs = seq(
    tlv(0xa0, integer(Buffer.from([2]))),
    integer(randomBytes(12)),
    alg,
    name(cn),
    seq(time(nb), time(na)),
    name(cn),
    publicKey.export({ type: "spki", format: "der" })
  );
  const signature = sign(hash, tbs, privateKey);
  const der = seq(tbs, alg, tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const certB64 = der.toString("base64");
  const certPem = "-----BEGIN CERTIFICATE-----\n" + certB64.match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";
  return { privateKey: privateKey.export({ type: "pkcs8", format: "pem" }), certPem, certB64 };
}
