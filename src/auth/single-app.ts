/**
 * NATH-52: single-app sign-in. The pinned app calls these methods over the
 * NathanVerifier service binding and draws its own form. The identity hostname
 * stays the instance's IdP management UI.
 *
 * Only AUTH_MODE=single-app answers. The methods drive the hosted email
 * sign-in with a server-derived browser handle, so the app never sees a flow
 * id, session cookie, token, or admin role. An email-code session still
 * cannot administer.
 */
import { sha256 } from "../gateway/crypto";
import { normalizeEmail } from "./admission-policy.mjs";
import { emailEnabled, emailSignIn } from "./email-sign-in";
import type { AuthEnv } from "./env";

export function singleAppMode(env: { AUTH_MODE?: string } | null | undefined): boolean {
  return env?.AUTH_MODE === "single-app";
}

export type SingleAppBegin = { ok: true } | { ok: false; error: "unavailable" | "invalid" | "rate_limited" };
export type SingleAppFinish =
  | { ok: true; sub: string; email: string; name: string | null }
  | { ok: false; error: "unavailable" | "invalid" | "rate_limited" };

const unavailable = (): { ok: false; error: "unavailable" } => ({ ok: false, error: "unavailable" });
const invalid = (): { ok: false; error: "invalid" } => ({ ok: false, error: "invalid" });
const limited = (): { ok: false; error: "rate_limited" } => ({ ok: false, error: "rate_limited" });

const COOKIE = "__Host-nathan-email";

function clientIp(value: unknown): string {
  if (typeof value !== "string") return "unknown";
  const ip = value.trim();
  if (!ip || ip.length > 64 || !/^[0-9a-fA-F:.]+$/.test(ip)) return "unknown";
  return ip;
}

function refusal(status: number): { ok: false; error: "unavailable" | "invalid" | "rate_limited" } | null {
  if (status === 202 || status === 200) return null;
  if (status === 429 || status === 403) return limited();
  if (status === 400) return invalid();
  return unavailable();
}

/** Same browser handle on begin and finish, without handing the app a cookie. */
async function browserHandle(env: AuthEnv, email: string): Promise<string> {
  const secret = env.BETTER_AUTH_SECRET || env.NATHAN_CONFIG_KEY;
  if (!secret) throw Error("single-app sign-in has no server secret");
  return sha256("nathan-single-app:" + secret + ":" + email);
}

function hostedRequest(env: AuthEnv, action: "request" | "verify", body: object, ip: string, browser: string): Request {
  const origin = new URL(env.NATHAN_ISSUER).origin;
  const path = action === "request" ? "/sign-in/email/request" : "/sign-in/email/verify";
  return new Request(origin + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin,
      "cf-connecting-ip": ip,
      cookie: COOKIE + "=" + browser,
    },
    body: JSON.stringify(body),
  });
}

/** Same generic answer as the hosted page: it does not say whether a code was mailed. */
export async function beginEmailSignIn(env: AuthEnv, input: { email?: unknown; ip?: unknown }, ctx: ExecutionContext): Promise<SingleAppBegin> {
  if (!singleAppMode(env) || !emailEnabled(env)) return unavailable();
  const email = normalizeEmail(input?.email);
  if (!email) return invalid();
  try {
    const browser = await browserHandle(env, email);
    const response = await emailSignIn(hostedRequest(env, "request", { email }, clientIp(input?.ip), browser), env, ctx, "request");
    return refusal(response.status) ?? { ok: true };
  } catch {
    return unavailable();
  }
}

/**
 * A correct code returns the person, and nothing else. The Nathan session the
 * code creates stays on the identity worker; the app makes its own session.
 */
export async function finishEmailSignIn(env: AuthEnv, input: { email?: unknown; code?: unknown; ip?: unknown }, ctx: ExecutionContext): Promise<SingleAppFinish> {
  if (!singleAppMode(env) || !emailEnabled(env)) return unavailable();
  const email = normalizeEmail(input?.email);
  const code = typeof input?.code === "string" ? input.code.replace(/\s/g, "") : "";
  if (!email || !/^\d{6}$/.test(code)) return invalid();
  try {
    const browser = await browserHandle(env, email);
    // requestEmail hashes [browser, normalized email, oauth query]. Single-app has no OAuth query.
    const flowId = await sha256(JSON.stringify([browser, email, null]));
    const response = await emailSignIn(hostedRequest(env, "verify", { flowId, code }, clientIp(input?.ip), browser), env, ctx, "verify");
    const early = refusal(response.status);
    if (early || response.status !== 200) return early ?? unavailable();
    const row = await env.DB.prepare('SELECT id, email, name FROM "user" WHERE email=?').bind(email).first<{ id: string; email: string; name: string | null }>();
    if (!row?.id || row.email !== email) return unavailable();
    return { ok: true, sub: row.id, email: row.email, name: typeof row.name === "string" ? row.name : null };
  } catch {
    return unavailable();
  }
}
