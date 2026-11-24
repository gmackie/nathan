/**
 * NATH-52: single-app sign-in. The app worker calls these methods over the
 * NathanVerifier service binding and draws its own form. The hosted pages on
 * the identity hostname stay the instance's IdP management UI.
 *
 * Only an instance with AUTH_MODE=single-app answers. The methods reuse the
 * email-code routes, so the same guards, limits and admission apply. The
 * answer never includes a session cookie, a token, or an admin role. An
 * email-code session still cannot administer.
 */
import { createAuth } from "./instance";
import type { AuthEnv } from "./env";
import type { Background } from "./email-otp";
import { emailOtpEnabled } from "./email-otp-policy.mjs";
import { loadSocialCredentials } from "./provider-store";

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

function clientIp(value: unknown): string {
  if (typeof value !== "string") return "unknown";
  const ip = value.trim();
  if (!ip || ip.length > 64 || !/^[0-9a-fA-F:.]+$/.test(ip)) return "unknown";
  return ip;
}

function address(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim();
  if (!email || email.length > 320 || !/^[^@\s]+@[^@\s]+$/.test(email)) return null;
  return email;
}

async function postEmailOtp(env: AuthEnv, background: Background | undefined, path: string, body: unknown, ip: string): Promise<Response> {
  const issuer = new URL(env.NATHAN_ISSUER);
  const auth = createAuth(env, await loadSocialCredentials(env), background);
  return auth.handler(new Request(issuer.origin + "/api/auth" + path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: issuer.origin,
      "cf-connecting-ip": ip,
    },
    body: JSON.stringify(body),
  }));
}

function refusal(status: number): { ok: false; error: "unavailable" | "invalid" | "rate_limited" } | null {
  if (status === 429 || status === 403) return limited();
  if (status === 200) return null;
  if (status === 400) return invalid();
  return unavailable();
}

/** Same generic answer as the hosted page: it does not say whether a code was mailed. */
export async function beginEmailSignIn(env: AuthEnv, input: { email?: unknown; ip?: unknown }, background?: Background): Promise<SingleAppBegin> {
  if (!singleAppMode(env) || !emailOtpEnabled(env)) return unavailable();
  const email = address(input?.email);
  if (!email) return invalid();
  try {
    const response = await postEmailOtp(env, background, "/email-otp/send-verification-otp", { email, type: "sign-in" }, clientIp(input?.ip));
    return refusal(response.status) ?? (response.status === 200 ? { ok: true } : unavailable());
  } catch {
    return unavailable();
  }
}

/**
 * A correct code returns the person, and nothing else. The Nathan session the
 * code creates stays on the identity worker; the app makes its own session.
 */
export async function finishEmailSignIn(env: AuthEnv, input: { email?: unknown; code?: unknown; ip?: unknown }, background?: Background): Promise<SingleAppFinish> {
  if (!singleAppMode(env) || !emailOtpEnabled(env)) return unavailable();
  const email = address(input?.email);
  const code = typeof input?.code === "string" ? input.code.replace(/\s/g, "") : "";
  if (!email || !/^\d{6}$/.test(code)) return invalid();
  try {
    const response = await postEmailOtp(env, background, "/sign-in/email-otp", { email, otp: code }, clientIp(input?.ip));
    const early = refusal(response.status);
    if (early) return early;
    const payload = await response.json().catch(() => null) as { user?: { id?: unknown; email?: unknown; name?: unknown; emailVerified?: unknown } } | null;
    const user = payload?.user;
    const sub = typeof user?.id === "string" ? user.id : "";
    const verifiedEmail = typeof user?.email === "string" ? user.email : "";
    if (!sub || !verifiedEmail || user?.emailVerified === false) return unavailable();
    return { ok: true, sub, email: verifiedEmail, name: typeof user?.name === "string" ? user.name : null };
  } catch {
    return unavailable();
  }
}
