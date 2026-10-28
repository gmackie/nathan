/** Pure, runtime-independent security validation helpers. */
export function safeReturnPath(input) {
  if (typeof input !== "string" || !input.startsWith("/") || input.startsWith("//")
    || input.includes("\\") || /[\x00-\x1f\x7f]/.test(input) || input.length > 2048) return "/";
  try {
    const parsed = new URL(input, "https://invalid.example");
    if (parsed.origin !== "https://invalid.example") return "/";
    return parsed.pathname + parsed.search;
  } catch { return "/"; }
}
export function parseCookie(header, key) {
  if (!header || typeof header !== "string") return null;
  for (const pair of header.split(";")) {
    const index = pair.indexOf("=");
    if (index < 1) continue;
    if (pair.slice(0, index).trim() === key) return pair.slice(index + 1).trim();
  }
  return null;
}
/** @param {string} name @param {string} value @param {{ maxAge?: number, deleteCookie?: boolean }} [options] */
export function makeCookie(name, value, { maxAge, deleteCookie = false } = {}) {
  if (!/^__Host-[A-Za-z0-9_-]+$/.test(name)) throw Error("Only __Host- cookies allowed");
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw Error("Unsafe cookie value");
  return name + "=" + value + "; Path=/; Secure; HttpOnly; SameSite=Lax"
    + (deleteCookie ? "; Max-Age=0" : typeof maxAge === "number" ? "; Max-Age=" + maxAge : "");
}
export function validateIssuer(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search)
    throw new Error("OIDC issuer must be a canonical HTTPS URL");
  return url.href.replace(/\/$/, "");
}
export function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const encoder = new TextEncoder();
  const x = encoder.encode(a), y = encoder.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++)
    diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}
