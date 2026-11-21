/**
 * NATH-18: only the identity Worker may use the per-connection SCIM Durable Object.
 *
 * Trust boundary: the NathanScimDirectory namespace must be bound by the identity Worker alone
 * (docs/scim.md). A Durable Object class can also be bound from another Worker in the same account
 * (a cross-script `durable_objects` binding with `script_name`), which would give that Worker the
 * staged directory, the change outbox and the administrator operations. As a second line, every
 * request to the object must carry this caller proof: an HMAC derived from BETTER_AUTH_SECRET, which
 * the object's own env holds (Durable Objects run with their defining Worker's env) and a foreign
 * Worker does not. The proof never leaves Cloudflare: it travels only on stub.fetch to the object.
 */
import type { AuthEnv } from "../env";

export const SCIM_CALLER_HEADER = "X-Nathan-SCIM-Caller";
let cached: { secret: string; proof: Promise<string> } | null = null;

async function derive(secret: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("nathan:scim-directory-caller:v1")));
  let raw = ""; for (const b of mac) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function proofFor(env: AuthEnv): Promise<string> {
  const secret = env.BETTER_AUTH_SECRET;
  if (typeof secret !== "string" || secret.length < 32) return Promise.reject(Error("BETTER_AUTH_SECRET missing"));
  if (!cached || cached.secret !== secret) cached = { secret, proof: derive(secret) };
  return cached.proof;
}

/** Adds the caller proof to a request the identity Worker sends to the SCIM Durable Object. */
export async function scimCallerHeaders(env: AuthEnv, headers: HeadersInit = {}): Promise<Headers> {
  const out = new Headers(headers);
  out.set(SCIM_CALLER_HEADER, await proofFor(env));
  return out;
}

/** Inside the Durable Object: whether the request came from the identity Worker. Fails closed. */
export async function isScimCaller(env: AuthEnv, request: Request): Promise<boolean> {
  const given = request.headers.get(SCIM_CALLER_HEADER);
  if (!given) return false;
  let expected: string;
  try { expected = await proofFor(env); } catch { return false; }
  if (given.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < given.length; i++) diff |= given.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}
