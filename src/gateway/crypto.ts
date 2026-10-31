import { constantTimeEqual } from "../shared/security.mjs";
const te = new TextEncoder();
const td = new TextDecoder();
export function randomId(bytes = 32): string {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  return toBase64Url(raw);
}
function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw Error("Invalid encoding");
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
export async function sha256(value: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(value))));
}
export async function pkceChallenge(verifier: string) {
  return sha256(verifier);
}
async function key(encoded: string): Promise<CryptoKey> {
  const raw = fromBase64Url(encoded);
  if (raw.byteLength !== 32) throw new Error("SESSION_ENCRYPTION_KEY must be 32 random bytes base64url");
  const bytes = new Uint8Array(new ArrayBuffer(32));
  bytes.set(raw);
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}
export async function seal(value: unknown, secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = te.encode(JSON.stringify(value));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(secret), payload));
  const combined = new Uint8Array(iv.length + encrypted.length);
  combined.set(iv);
  combined.set(encrypted, iv.length);
  return toBase64Url(combined);
}
export async function unseal<T>(encoded: string, secret: string): Promise<T | null> {
  try {
    const bytes = fromBase64Url(encoded);
    if (bytes.length < 29 || bytes.length > 4096) return null;
    const iv = bytes.slice(0, 12);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await key(secret), bytes.slice(12));
    return JSON.parse(td.decode(plaintext)) as T;
  } catch { return null; }
}
export { constantTimeEqual };
