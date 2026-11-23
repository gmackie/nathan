/**
 * NATH-37: the security headers for every page rendered by src/ui/render.tsx.
 * They match today's page() in src/auth/ui.ts, plus 'self' in style-src and script-src for the
 * hashed same-origin assets under /__nathan/ui/ (each one is also pinned with SRI).
 */

/** Headers renderPage owns. Page-specific extras may not set or override any of them. */
export const RESERVED_HEADERS = [
  "content-type", "cache-control", "content-security-policy", "referrer-policy", "x-content-type-options",
  "x-frame-options", "cross-origin-opener-policy", "strict-transport-security"
] as const;

/** RFC 8252 loopback hosts; the same set validateRedirectUri (src/shared/mcp-scopes.mjs) allows over http. */
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * One CSP form-action source: 'self', 'none', a bare https origin, or (NATH-38, for native MCP
 * clients' registered loopback callbacks) a bare http origin on a loopback host.
 */
export function formActionSource(source: string): string {
  if (source === "'self'" || source === "'none'") return source;
  let url: URL;
  try { url = new URL(source); } catch { throw Error("Invalid form-action origin"); }
  const allowed = url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname));
  if (!allowed || url.origin !== source) throw Error("form-action must be 'self', 'none', a bare https origin or a loopback http origin");
  return url.origin;
}

export interface CspOptions {
  nonce: string;
  /** Page has islands: allow nonce'd and same-origin scripts. Otherwise script-src 'none'. */
  scripts: boolean;
  /** form-action sources; defaults to 'self'. */
  formAction?: readonly string[];
}

export function contentSecurityPolicy({ nonce, scripts, formAction = ["'self'"] }: CspOptions): string {
  if (!/^[A-Za-z0-9+/]{22}==$/.test(nonce)) throw Error("Invalid CSP nonce");
  const actions = formAction.length ? formAction.map(formActionSource) : ["'none'"];
  if (actions.includes("'none'") && actions.length > 1) throw Error("form-action 'none' cannot be combined");
  return [
    "default-src 'none'",
    "connect-src 'self'",
    "img-src 'none'",
    "style-src 'self' 'nonce-" + nonce + "'",
    scripts ? "script-src 'self' 'nonce-" + nonce + "'" : "script-src 'none'",
    "form-action " + actions.join(" "),
    "base-uri 'none'",
    "frame-ancestors 'none'"
  ].join("; ");
}

export function securityHeaders(csp: CspOptions, extra?: HeadersInit): Headers {
  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": contentSecurityPolicy(csp),
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000"
  });
  if (extra) {
    for (const [name, value] of new Headers(extra)) {
      if ((RESERVED_HEADERS as readonly string[]).includes(name)) throw Error("renderPage owns the " + name + " header");
      if (name === "set-cookie") continue;
      headers.set(name, value);
    }
    // Headers iteration folds Set-Cookie; copy each cookie separately.
    for (const cookie of new Headers(extra).getSetCookie()) headers.append("Set-Cookie", cookie);
  }
  return headers;
}

/** A fresh 128-bit nonce, base64 like today's page(). */
export function newNonce(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
}
