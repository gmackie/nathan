/**
 * NATH-49: passwordless email sign-in with Better Auth's first-party `emailOTP` plugin, wired into
 * Nathan's rules. The policy (limits, admission of the recipient, the email text) is in
 * ./email-otp-policy.mjs; this file connects it to Better Auth:
 * - emailOtpPlugins: the plugin, only when ENABLE_EMAIL_OTP=true (sign-in codes, hashed, 10 minutes,
 *   3 attempts). Mail goes only through ./email.ts.
 * - emailOtpRequestGuard (hooks.before): fails closed without Resend, accepts only the fields the
 *   hosted page sends, and applies the per-address limits (per-IP limits are Better Auth's).
 * - emailOtpAudit (hooks.after): audits sign-ins and refusals without addresses or codes.
 * - emailOtpPromotionGuard (databaseHooks.user.update.before): Better Auth's email-OTP sign-in into
 *   an existing unverified account verifies it; Nathan runs admission first, as a verification link
 *   would (./admission.ts), and drops the unproven profile.
 * New accounts go through the one admission guard (admissionUserCreateGuard, method "email-otp").
 */
import { emailOTP } from "better-auth/plugins";
import { APIError } from "better-auth/api";
import type { AuthEnv } from "./env";
import { sendSignInCode } from "./email";
import {
  EMAIL_OTP, SEND_PATH, VERIFY_PATH, FAILURE_BUDGET, emailOtpEnabled, emailDeliveryConfigured, requestProblem, consumeAddressLimit,
  mayReceiveSignInCode, codeSignInRefusal, inVerifiedSsoDomain, failureBudgetExhausted, recordFailure
} from "./email-otp-policy.mjs";
import { normalizeEmail, admitOnVerification, auditAdmission, NOT_ADMITTED } from "./admission-policy.mjs";

/** Runs work after the response (ExecutionContext.waitUntil); absent in tests and server-side calls. */
export type Background = (promise: Promise<unknown>) => void;

const AUDIT = "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) ";
/** One audit row per action, target and outcome per minute (refusal floods); never an address or a code. */
async function auditThrottled(env: AuthEnv, action: string, target: string, outcome: string) {
  await env.DB.prepare(AUDIT + "SELECT ?,'system:email-otp',?,?,? WHERE NOT EXISTS (SELECT 1 FROM nathan_security_audit " +
    "WHERE action=? AND target=? AND outcome=? AND created_at>=unixepoch()-60)")
    .bind(crypto.randomUUID(), action, target, outcome, action, target, outcome).run();
}

/**
 * Mails a code when the address may receive one (see mayReceiveSignInCode). Errors are logged by
 * status only, never with the address or code, and never change the answer the requester gets.
 */
async function deliverSignInCode(env: AuthEnv, email: string, otp: string) {
  try {
    if (!await mayReceiveSignInCode(env.DB, env, email)) return;
    await sendSignInCode(env, email, otp);
  } catch (error) {
    const status = error instanceof Error ? /delivery failed: (\d{3})$/.exec(error.message)?.[1] : undefined;
    console.error("Email sign-in code not delivered" + (status ? " (Resend " + status + ")" : ""));
  }
}

export function emailOtpPlugins(env: AuthEnv, background?: Background) {
  if (!emailOtpEnabled(env)) return [];
  return [emailOTP({
    expiresIn: EMAIL_OTP.expiresIn,
    allowedAttempts: EMAIL_OTP.allowedAttempts,
    otpLength: EMAIL_OTP.otpLength,
    // A database read of the verification table never yields a usable code.
    storeOTP: "hashed",
    // Every send makes a new code (no reuse of an unexpired one, which "hashed" cannot recover anyway).
    resendStrategy: "rotate",
    // Account creation is not disabled here: Nathan's admission guard decides it (invitation-only
    // refuses an address without an open invitation; self-service admits it).
    disableSignUp: false,
    async sendVerificationOTP({ email, otp, type }) {
      // Only sign-in codes are ever mailed (the guard refuses other types first).
      if (type !== "sign-in") return;
      // Off the response path, so the answer takes the same time whether or not a code is mailed.
      const task = deliverSignInCode(env, email, otp);
      if (background) background(task);
      else await task;
    }
  })];
}

/** Better Auth's own wrong-code answer. Nathan's refusals after a code check use it, so they reveal nothing. */
const invalidCode = () => new APIError("BAD_REQUEST", { code: "INVALID_OTP", message: "Invalid OTP" });
const tooMany = (retryAfter: number) => new APIError("TOO_MANY_REQUESTS",
  { code: "TOO_MANY_REQUESTS", message: "Too many requests. Please try again later." }, { "X-Retry-After": String(retryAfter) });
/** Code failures that count against the instance-wide budget. */
const CODE_FAILURES = new Set(["INVALID_OTP", "OTP_EXPIRED", "TOO_MANY_ATTEMPTS"]);

/** hooks.before for the two email-OTP routes. Throws the refusal; returns nothing otherwise. */
export async function emailOtpRequestGuard(env: AuthEnv, ctx: any) {
  const path = ctx?.path;
  if (path !== SEND_PATH && path !== VERIFY_PATH) return;
  if (!emailOtpEnabled(env)) return;
  if (path === SEND_PATH && !emailDeliveryConfigured(env))
    throw new APIError("SERVICE_UNAVAILABLE", { code: "EMAIL_SIGN_IN_UNAVAILABLE", message: "Email sign-in is not available on this server." });
  // Same-origin only (the hosted page). Better Auth also accepts only JSON bodies here.
  const headers: Headers | undefined = ctx.request?.headers ?? ctx.headers;
  const origin = headers?.get("origin");
  if ((origin && origin !== new URL(env.NATHAN_ISSUER).origin) || headers?.get("sec-fetch-site") === "cross-site")
    throw new APIError("FORBIDDEN", { code: "CROSS_ORIGIN_REQUEST", message: "Cross-origin request denied" });
  const problem = requestProblem(path, ctx.body);
  if (problem) throw new APIError("BAD_REQUEST", { code: "INVALID_REQUEST", message: problem });
  const kind = path === SEND_PATH ? "send" : "verify";
  if (kind === "verify") {
    const wait = await failureBudgetExhausted(env.DB);
    if (wait) {
      await auditThrottled(env, "email_otp_rate_limited", "instance-failure-budget", "refused").catch(() => {});
      throw tooMany(wait);
    }
  }
  const limit = await consumeAddressLimit(env.DB, kind, normalizeEmail(ctx.body.email)!);
  if (!limit.allowed) {
    await auditThrottled(env, "email_otp_rate_limited", kind, "refused").catch(() => {});
    throw tooMany(limit.retryAfter!);
  }
}

/**
 * hooks.after for the verify route. A sign-in: records the session as an email-code session (it
 * never administers) and audits it; if either write fails the session is deleted and the request
 * fails (closed). A refused code: counted against the instance budget and audited (one row a minute
 * per error code, with the hour's failure count).
 */
export async function emailOtpAudit(env: AuthEnv, ctx: any) {
  if (ctx?.path !== VERIFY_PATH) return;
  const created = ctx.context?.newSession;
  if (created?.session?.id && created.user?.id) {
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO nathan_email_otp_sessions(session_id,user_id) VALUES (?,?)").bind(created.session.id, created.user.id),
        env.DB.prepare(AUDIT + "VALUES (?,?,'email_otp_sign_in',?,'succeeded')").bind(crypto.randomUUID(), created.user.id, created.session.id)
      ]);
    } catch {
      await env.DB.prepare('DELETE FROM "session" WHERE "id"=?').bind(created.session.id).run().catch(() => {});
      throw new APIError("SERVICE_UNAVAILABLE", { code: "SIGN_IN_NOT_RECORDED", message: "Sign-in could not be completed. Try again." });
    }
    return;
  }
  const returned = ctx.context?.returned;
  if (returned && typeof returned === "object" && Number(returned.statusCode) >= 400) {
    const code = typeof returned.body?.code === "string" && /^[A-Z_]{1,64}$/.test(returned.body.code) ? returned.body.code : "rejected";
    let count = 0;
    if (CODE_FAILURES.has(code)) count = await recordFailure(env.DB).catch(() => 0);
    if (count === FAILURE_BUDGET.max)
      await env.DB.prepare(AUDIT + "VALUES (?,'system:email-otp','email_otp_failure_budget_exhausted',?,'refused')")
        .bind(crypto.randomUUID(), String(count) + " refused codes this hour").run().catch(() => {});
    await auditThrottled(env, "email_otp_sign_in", code + (count ? " failures_this_hour=" + count : ""), "rejected").catch(() => {});
  }
}

/**
 * databaseHooks.user.create.before, ahead of admission: an address inside a verified enterprise SSO
 * domain never gets an account by email code (its people sign in through their IdP). Reached only
 * with a correct code, which is never mailed to such an address; answered as a wrong code.
 */
export async function emailOtpUserCreateGuard(env: AuthEnv, user: any, ctx: any) {
  if (ctx?.path !== VERIFY_PATH) return;
  let refused = true;
  try { refused = await inVerifiedSsoDomain(env.DB, user?.email); } catch { /* fail closed */ }
  if (refused) throw invalidCode();
}

/**
 * databaseHooks.session.create.before for the verify route, after Better Auth accepted the code: no
 * session for an account that may not sign in by code (codeSignInRefusal) or that is still
 * unverified. The answer is the wrong-code answer, so it says nothing about the account.
 */
export async function emailOtpSessionGuard(env: AuthEnv, session: any, ctx: any) {
  if (ctx?.path !== VERIFY_PATH) return;
  let refusal: string | null = "error";
  try {
    const user = await env.DB.prepare('SELECT "emailVerified" AS verified FROM "user" WHERE "id"=? LIMIT 1')
      .bind(session?.userId ?? "").first<{ verified: number }>();
    refusal = !user ? "unknown" : Number(user.verified) !== 1 ? "unverified" : await codeSignInRefusal(env.DB, { userId: session.userId });
  } catch { /* fail closed */ }
  if (!refusal) return;
  await auditThrottled(env, "email_otp_sign_in", "refused:" + refusal, "rejected").catch(() => {});
  throw invalidCode();
}

/**
 * databaseHooks.user.update.before. Better Auth's email-OTP sign-in into an existing unverified
 * account deletes its unproven logins and sessions and marks it verified. For a provisional
 * password sign-up (nathan_admission_pending) that is the moment it claims its invitation, so
 * Nathan runs the same admission as the verification link and refuses without one. The name and
 * image were set by whoever created the unverified account, not the address owner: they are cleared.
 */
export async function emailOtpPromotionGuard(env: AuthEnv, data: any, ctx: any) {
  if (ctx?.path !== VERIFY_PATH || data?.emailVerified !== true) return;
  const email = normalizeEmail(ctx.body?.email);
  if (!email) throw new APIError("BAD_REQUEST", { code: "INVALID_REQUEST", message: "Invalid request" });
  const refuse = (): never => { throw new APIError("UNPROCESSABLE_ENTITY", { code: NOT_ADMITTED.code, message: NOT_ADMITTED.message }); };
  let decision: { pending: boolean; admitted?: boolean; via?: string };
  try {
    const user = await env.DB.prepare('SELECT "id" AS id FROM "user" WHERE lower("email")=? AND "emailVerified"=0 LIMIT 1')
      .bind(email).first<{ id: string }>();
    if (!user) return;
    // An account that may not sign in by code is not promoted either (answered as a wrong code).
    if (await codeSignInRefusal(env.DB, { userId: user.id })) throw invalidCode();
    decision = await admitOnVerification(env.DB, env, { userId: user.id, email, method: "email-otp" });
  } catch (error) {
    if (error instanceof APIError) throw error;
    refuse();
  }
  if (decision!.pending) {
    if (!decision!.admitted) {
      await auditAdmission(env.DB, "email-otp", "refused_at_verification").catch(() => {});
      refuse();
    }
    await auditAdmission(env.DB, "email-otp", "admitted_" + decision!.via!.replace("-", "_"));
  }
  return { data: { ...data, name: "", image: null } };
}
