import { symmetricEncrypt, symmetricDecrypt } from "better-auth/crypto";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { randomId, sha256 } from "../gateway/crypto";
import { isAllowedUnsafeRequest, makeCookie, parseCookie } from "../shared/security.mjs";
import { normalizeEmail } from "./admission-policy.mjs";
import { readBoundedText } from "./bounded-body.mjs";
import { createAuth } from "./instance";
import { sendSignInEmail, type EmailClient } from "./email";
import { EMAIL_ATTEMPTS, EMAIL_TTL, emailTarget, type EmailFlow } from "./email-sign-in-policy";
import { consumeAddressLimit, reserveProofAttempt, releaseProofAttempt, auditRefusedProof } from "./email-otp-policy.mjs";
import { allowRequests } from "./request-limit";
import type { AuthEnv } from "./env";

const COOKIE = "__Host-nathan-email";
const FACTOR_COOKIE = "__Secure-nathan.two_factor";
const HANDLE = /^[A-Za-z0-9_-]{43}$/;
const DIGITS = /^\d{6}$/;
type Input = { email?: unknown; oauth_query?: unknown; code?: unknown; flowId?: unknown; totp?: unknown };
const reply = (status: number, body: object, headers = new Headers()) => {
  headers.set("Cache-Control", "no-store");
  return Response.json(body, { status, headers });
};
const invalid = () => reply(400, { error: "This code or link is invalid or expired. Request a new email." });
export const emailEnabled = (env: AuthEnv) => env.ENABLE_EMAIL_OTP === "true" && Boolean(env.RESEND_API_KEY && env.EMAIL_FROM);

async function oauthClient(env: AuthEnv, query: string): Promise<EmailClient | null> {
  if (!await verifyOAuthQueryParams(query, env.BETTER_AUTH_SECRET)) return null;
  const ids = new URLSearchParams(query).getAll("client_id");
  if (ids.length !== 1) return null;
  return env.DB.prepare('SELECT name,metadata FROM "oauthClient" WHERE clientId=? AND COALESCE(disabled,0)=0').bind(ids[0]).first<EmailClient>();
}

async function issue(env: AuthEnv, browser: string, flowId: string, email: string, query: string | null, client: EmailClient | null) {
  const eligible = await emailTarget(env.DB, email);
  const id = await sha256(browser + "." + flowId);
  const flow: EmailFlow = { id, generation: randomId(), email, invitation_id: eligible?.invitation_id ?? null,
    subject_id: eligible?.subject_id ?? null, oauth_query: query, second_factor: null };
  const insert = "INSERT INTO nathan_email_sign_ins(id,generation,subject_id,email,invitation_id,oauth_query,expires_at) VALUES (?,?,?,?,?,?,?) ";
  const values = [id, flow.generation, flow.subject_id, email, flow.invitation_id, query, Math.floor(Date.now() / 1000) + EMAIL_TTL];
  // Keep an existing delivered generation usable while its replacement is in flight.
  const first = await env.DB.prepare(insert + "ON CONFLICT(email) DO NOTHING").bind(...values).run();
  const auth = createAuth(env, undefined, { browser, flow });
  const proof = await auth.api.createVerificationOTP({ body: { email, type: "sign-in" } });
  if (eligible) {
    const digits = proof.slice(-6);
    const link = new URL("/sign-in/email", env.NATHAN_ISSUER);
    link.hash = flowId + "." + digits;
    await sendSignInEmail(env, email, digits, link.href, client);
  }
  if (!first.meta.changes) {
    await env.DB.prepare(insert + "ON CONFLICT(email) DO UPDATE SET id=excluded.id,generation=excluded.generation,subject_id=excluded.subject_id," +
      "invitation_id=excluded.invitation_id,oauth_query=excluded.oauth_query,expires_at=excluded.expires_at,attempts=0,second_factor=NULL")
      .bind(...values).run();
  }
}

async function requestEmail(request: Request, env: AuthEnv, ctx: ExecutionContext, body: Input) {
  const email = normalizeEmail(body.email);
  const query = body.oauth_query ?? null;
  if (query !== null && (typeof query !== "string" || !query)) return invalid();
  const client = query ? await oauthClient(env, query) : null;
  if (query && !client) return invalid();
  const prior = parseCookie(request.headers.get("Cookie"), COOKIE);
  const browser = prior && HANDLE.test(prior) ? prior : randomId();
  // A tab can only complete its original address and signed authorization. A throttled resend
  // leaves the tab's previously delivered proof usable and reveals no account-dependent state.
  const flowId = await sha256(JSON.stringify([browser, email, query]));
  // Account lookup and Resend run after the neutral reply. The cookie and IP/address counters
  // have the same shape and behavior for unknown, blocked and eligible addresses.
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  if (await allowRequests(env, "email-send-ip", ip, 10, 600) && email && (await consumeAddressLimit(env.DB, "send", email)).allowed) {
    ctx.waitUntil(issue(env, browser, flowId, email, query, client).catch(() => {
      console.error("Hosted email sign-in delivery failed");
    }));
  }
  return reply(202, { flowId, message: "If you can sign in with this address, check your email for a code and link." },
    new Headers({ "Set-Cookie": makeCookie(COOKIE, browser, { maxAge: EMAIL_TTL }) }));
}

async function verify(request: Request, env: AuthEnv, body: Input) {
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  if (!await allowRequests(env, "email-verify-ip", ip, 20, 600)) return invalid();
  const browser = parseCookie(request.headers.get("Cookie"), COOKIE);
  const isFactor = body.totp !== undefined;
  const digits = isFactor ? body.totp : body.code;
  if (!browser || !HANDLE.test(browser) || typeof body.flowId !== "string" || !HANDLE.test(body.flowId) || typeof digits !== "string" || !DIGITS.test(digits)) return invalid();
  const id = await sha256(browser + "." + body.flowId);
  const flow = await env.DB.prepare("UPDATE nathan_email_sign_ins SET attempts=attempts+1 " +
    "WHERE id=? AND expires_at>unixepoch() AND attempts<? RETURNING id,generation,subject_id,email,invitation_id,oauth_query,second_factor")
    .bind(id, EMAIL_ATTEMPTS).first<EmailFlow>();
  if (!flow || Boolean(flow.second_factor) !== isFactor) return invalid();
  if (!(await consumeAddressLimit(env.DB, "verify", flow.email)).allowed) return invalid();
  if (flow.oauth_query && !await oauthClient(env, flow.oauth_query)) return invalid();
  const start = await reserveProofAttempt(env.DB);
  if (start === null) return invalid();
  try {
    const result = await redeem(request, env, flow, browser, digits, isFactor);
    // A failed refund conservatively costs one slot. The completed, audited session is still deliverable.
    if (result.ok) await releaseProofAttempt(env.DB, start).catch(() => {});
    else await auditRefusedProof(env.DB);
    return result;
  } finally {
    // Better Auth can fail after inserting a session, including in an OAuth after-hook.
    // A pending primary-factor session or a losing completion has no caller.
    if (flow.issuedSessionId) await env.DB.prepare('DELETE FROM "session" WHERE id=?').bind(flow.issuedSessionId).run();
  }
}

async function redeem(request: Request, env: AuthEnv, flow: EmailFlow, browser: string, digits: string, isFactor: boolean) {
  const auth = createAuth(env, undefined, { browser, flow });
  const headers = new Headers(request.headers);
  // Complete exactly this pending sign-in, even if a different user is already signed in.
  headers.delete("Cookie");
  headers.set("Accept", "application/json");
  const options = () => ({ request: new Request(request.url, { method: "POST", headers }), headers, asResponse: true as const });
  const oauth = flow.oauth_query ? { oauth_query: flow.oauth_query } : {};
  let response: Response;
  if (isFactor) {
    // The raw Better Auth challenge stays server-side so the primary proof cannot be
    // completed outside the hosted admission and session-evidence hooks.
    const pending = await symmetricDecrypt({ key: browser, data: flow.second_factor! });
    headers.set("Cookie", FACTOR_COOKIE + "=" + pending);
    response = await auth.api.verifyTOTP({ ...options(), body: { code: digits, trustDevice: false, ...oauth } });
  } else {
    const eligible = await emailTarget(env.DB, flow.email);
    // Dummy, revoked and replaced targets take the same credential-verification path. Their
    // proof cannot possibly match, even if someone guesses the digits of an undelivered mail.
    const otp = eligible && eligible.invitation_id === flow.invitation_id && eligible.subject_id === flow.subject_id ? browser + "." + flow.generation + "." + digits : "unavailable";
    response = await auth.api.signInEmailOTP({ ...options(), body: { email: flow.email, otp, ...oauth } });
  }
  if (!response.ok) return invalid();
  const result = await response.json() as { url?: string; twoFactorRedirect?: boolean };
  const outgoing = new Headers();
  const cookies = response.headers.getSetCookie();
  if (result.twoFactorRedirect) {
    const cookie = cookies.find(c => c.startsWith(FACTOR_COOKIE + "="));
    const pending = cookie && parseCookie(cookie, FACTOR_COOKIE);
    if (!pending) return invalid();
    const sealed = await symmetricEncrypt({ key: browser, data: pending });
    const saved = await env.DB.prepare("UPDATE nathan_email_sign_ins SET second_factor=?, attempts=0 WHERE id=? AND generation=? AND second_factor IS NULL AND expires_at>unixepoch()")
      .bind(sealed, flow.id, flow.generation).run();
    if (!saved.meta.changes) return invalid();
    return reply(200, { twoFactorRedirect: true }, outgoing);
  }
  // Return a session only after winning the final claim, including for simultaneous TOTP submissions.
  if (flow.oauth_query) {
    if (!result.url) return invalid();
    const continuation = new URL(result.url, env.NATHAN_ISSUER);
    if (continuation.searchParams.has("error") ||
        (continuation.origin === new URL(env.NATHAN_ISSUER).origin && continuation.pathname === "/error")) return invalid();
  }
  const sessionId = flow.issuedSessionId;
  if (!sessionId) return invalid();
  const [, audit] = await env.DB.batch([
    env.DB.prepare("DELETE FROM nathan_email_sign_ins WHERE id=? AND generation=? AND expires_at>unixepoch() " +
      'AND EXISTS(SELECT 1 FROM session s JOIN "user" u ON u.id=s.userId WHERE s.id=? AND u.email=nathan_email_sign_ins.email ' +
      "AND COALESCE(u.twoFactorEnabled,0)=EXISTS(SELECT 1 FROM twoFactor WHERE userId=u.id AND COALESCE(verified,1)=1) " +
      "AND (COALESCE(u.twoFactorEnabled,0)=0 OR (?=1 AND second_factor IS NOT NULL)))").bind(flow.id, flow.generation, sessionId, Number(isFactor)),
    env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) " +
      "SELECT ?,user_id,'email_otp_sign_in',session_id,'succeeded' FROM nathan_email_otp_sessions WHERE session_id=? AND changes()=1")
      .bind(crypto.randomUUID(), sessionId)
  ]);
  if (audit.meta.changes !== 1) return invalid();
  delete flow.issuedSessionId;
  for (const cookie of cookies) outgoing.append("Set-Cookie", cookie);
  return reply(200, { url: result.url || "/" }, outgoing);
}

export async function emailSignIn(request: Request, env: AuthEnv, ctx: ExecutionContext, action: "request" | "verify") {
  if (!emailEnabled(env)) return reply(404, { error: "Email sign-in unavailable" });
  if (request.method !== "POST") return reply(405, { error: "POST required" });
  if (!isAllowedUnsafeRequest(request.method, request.headers.get("Origin"), new URL(env.NATHAN_ISSUER).origin, request.headers.get("Sec-Fetch-Site")))
    return reply(403, { error: "Cross-origin request denied" });
  if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json") return reply(415, { error: "JSON required" });
  const raw = await readBoundedText(request, 16384);
  if (raw === null) return reply(413, { error: "Request too large" });
  let body: Input;
  try { body = JSON.parse(raw); } catch { return invalid(); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return invalid();
  try { return action === "request" ? await requestEmail(request, env, ctx, body) : await verify(request, env, body); }
  catch { return invalid(); }
}
