/**
 * NATH-49: passwordless email sign-in (a one-time code by email) through Better Auth's first-party
 * `emailOTP` plugin. The pure rules and the D1 statements behind them, in plain JS so they are
 * unit-tested in Node and bundled into the Worker. src/auth/email-otp.ts wires them into Better Auth.
 *
 * - Off unless the instance sets ENABLE_EMAIL_OTP=true; offered only while Resend is configured
 *   (RESEND_API_KEY and EMAIL_FROM). Sending fails closed (503) without them.
 * - Sign-in codes only: every other emailOTP route (email verification, password reset, email
 *   change, the code-check oracle) is disabled, and the send route accepts only type "sign-in".
 * - A code is 6 digits, lives 10 minutes, is stored hashed, and allows 3 attempts; then it is gone.
 * - Rate limits per IP (Better Auth's rate limiter) and per address (the same `rateLimit` table,
 *   keyed by a hash of the address) on sending and on verifying.
 * - The send route answers the same way for every address. In invitation-only mode a code is only
 *   mailed to an address that could sign in (an account, an open invitation or the installer's
 *   first administrator); nothing is mailed otherwise, and the answer does not say so.
 * - Account creation goes through Nathan's admission guard (method "email-otp"): the code proves the
 *   address, so it may claim an open invitation, and in self-service mode it creates the account.
 * - Administrator accounts never sign in by email code: an emailed code must not become a way into
 *   Identity Studio (Standard-profile instances do not require a passkey step-up). They are treated
 *   like an address that cannot sign in: no mail, and any code fails like a wrong one.
 * - Sessions it creates carry no nathan_amr / nathan_acr evidence (an emailed code is neither a
 *   passkey nor phishing-resistant MFA), so they never count as admin assurance or raise AAL.
 */
import { normalizeEmail, admissionMode, openInvitation, isBootstrapAdmission } from "./admission-policy.mjs";

export const EMAIL_OTP = Object.freeze({
  /** Code lifetime in seconds. */
  expiresIn: 600,
  /** Wrong guesses a code survives; the next attempt (even the right code) invalidates it. */
  allowedAttempts: 3,
  otpLength: 6
});

/** Better Auth paths: the two the hosted page uses. */
export const SEND_PATH = "/email-otp/send-verification-otp";
export const VERIFY_PATH = "/sign-in/email-otp";
/** Every other emailOTP route. Disabled on every instance (also when the flag is off), so none can be reached. */
export const DISABLED_EMAIL_OTP_PATHS = Object.freeze([
  "/email-otp/check-verification-otp",
  "/email-otp/verify-email",
  "/email-otp/request-password-reset",
  "/email-otp/reset-password",
  "/forget-password/email-otp",
  "/email-otp/request-email-change",
  "/email-otp/change-email"
]);

/**
 * Rate limits. Per IP: Better Auth's rate limiter (key = IP + path, database storage). Per address:
 * the same table under a hashed key. Windows stay at or under the longest Better Auth window so its
 * pruning of old rows never resets a running per-address window early.
 */
export const IP_LIMITS = Object.freeze({
  [SEND_PATH]: Object.freeze({ window: 600, max: 10 }),
  [VERIFY_PATH]: Object.freeze({ window: 600, max: 20 })
});
export const ADDRESS_LIMITS = Object.freeze({
  send: Object.freeze({ window: 600, max: 3 }),
  verify: Object.freeze({ window: 600, max: 5 })
});

/** Request fields each route accepts. Sign-in never takes a profile (name, image) or other user fields. */
export const ALLOWED_FIELDS = Object.freeze({
  [SEND_PATH]: Object.freeze(["email", "type"]),
  [VERIFY_PATH]: Object.freeze(["email", "otp", "oauth_query"])
});

/** The instance setting (off by default). */
export function emailOtpEnabled(env) {
  return env?.ENABLE_EMAIL_OTP === "true";
}
/** Whether mail can be sent at all. Without it the method is not offered and sending is refused. */
export function emailDeliveryConfigured(env) {
  return typeof env?.RESEND_API_KEY === "string" && env.RESEND_API_KEY.length > 0 &&
    typeof env?.EMAIL_FROM === "string" && env.EMAIL_FROM.length > 0;
}
/** Shown on the hosted sign-in page only when it can actually work. */
export function emailOtpOffered(env) {
  return emailOtpEnabled(env) && emailDeliveryConfigured(env);
}

/**
 * Checks a request body before Better Auth handles it. Returns null when it is acceptable, else a
 * fixed reason (never echoing input). The send route takes only type "sign-in".
 */
export function requestProblem(path, body) {
  const allowed = ALLOWED_FIELDS[path];
  if (!allowed) return null;
  if (!body || typeof body !== "object" || Array.isArray(body)) return "Invalid request";
  if (Object.keys(body).some(key => !allowed.includes(key))) return "Unsupported field";
  if (!normalizeEmail(body.email)) return "Enter a valid email address";
  if (path === SEND_PATH && body.type !== "sign-in") return "Only sign-in codes are available";
  if (path === VERIFY_PATH) {
    if (typeof body.otp !== "string" || !/^\d{6}$/.test(body.otp)) return "Enter the 6-digit code from the email";
    if (body.oauth_query !== undefined && typeof body.oauth_query !== "string") return "Invalid request";
  }
  return null;
}

const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
/** The per-address rate-limit key: a hash, so the `rateLimit` table never holds an address. */
export async function addressLimitKey(kind, email) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("nathan-email-otp:" + email));
  return "nathan-email-otp:" + kind + ":" + hex(digest);
}

/**
 * Counts one request against a per-address limit in Better Auth's `rateLimit` table, atomically (one
 * statement), with Better Auth's semantics: the count restarts once `window` seconds have passed
 * since the last allowed request; a refused request does not extend the window.
 * Returns { allowed, retryAfter } (seconds).
 */
export async function consumeAddressLimit(db, kind, email, rule = ADDRESS_LIMITS[kind], now = Date.now()) {
  const key = await addressLimitKey(kind, email);
  const windowMs = rule.window * 1000;
  const row = await db.prepare(
    'INSERT INTO "rateLimit"("id","key","count","lastRequest") VALUES (?1,?2,1,?3) ' +
    'ON CONFLICT("key") DO UPDATE SET ' +
    '"count"=CASE WHEN ?3-"lastRequest">=?4 THEN 1 ELSE "count"+1 END, ' +
    '"lastRequest"=CASE WHEN ?3-"lastRequest">=?4 OR "count"<?5 THEN ?3 ELSE "lastRequest" END ' +
    'RETURNING "count" AS count, "lastRequest" AS lastRequest'
  ).bind(crypto.randomUUID(), key, now, windowMs, rule.max).first();
  const count = Number(row?.count);
  if (Number.isFinite(count) && count <= rule.max) return { allowed: true, retryAfter: null };
  const last = Number(row?.lastRequest);
  return { allowed: false, retryAfter: Math.max(1, Math.ceil(((Number.isFinite(last) ? last : now) + windowMs - now) / 1000)) };
}

/**
 * An administrator account (Better Auth admin role, an administrator grant, or the installer's bound
 * first administrator). Email codes never sign these in.
 */
export async function isAdministratorAccount(db, email) {
  const address = normalizeEmail(email);
  if (!address) return false;
  const row = await db.prepare(
    'SELECT 1 AS admin FROM "user" u WHERE lower(u."email")=? AND (coalesce(u."role",\'user\')=\'admin\' ' +
    "OR EXISTS (SELECT 1 FROM nathan_admin_grants g WHERE g.user_id=u.\"id\") " +
    "OR EXISTS (SELECT 1 FROM nathan_bootstrap_status b WHERE b.admin_user_id=u.\"id\")) LIMIT 1"
  ).bind(address).first();
  return Boolean(row);
}

/**
 * Whether a sign-in code may be mailed to an address: an existing account that is not an administrator, the
 * installer's first administrator, self-service mode, or an open invitation. Invitation-only mode
 * mails nothing to anyone else, so Nathan sends no mail on behalf of strangers. Fails closed.
 */
export async function mayReceiveSignInCode(db, env, email) {
  const address = normalizeEmail(email);
  if (!address) return false;
  const user = await db.prepare('SELECT 1 AS found FROM "user" WHERE lower("email")=? LIMIT 1').bind(address).first();
  if (user) return !(await isAdministratorAccount(db, address));
  // The address will be proven by the code, so the bootstrap check runs as if it were.
  if (await isBootstrapAdmission(db, env, address, true)) return true;
  if (await admissionMode(db) === "self-service") return true;
  return Boolean(await openInvitation(db, address));
}

/** The email: short, with the code and the host that asked for it. Never logged. */
export function signInCodeMail({ code, host, appName }) {
  const name = typeof appName === "string" && appName.trim() ? appName.trim().slice(0, 64) : "Nathan";
  if (typeof code !== "string" || !/^\d{4,10}$/.test(code)) throw Error("Invalid sign-in code");
  if (typeof host !== "string" || !/^[a-z0-9.-]{1,253}(:\d{1,5})?$/i.test(host)) throw Error("Invalid host");
  return {
    // The code stays out of the subject, which mail providers and previews show and keep more widely.
    subject: "Your " + name + " sign-in code",
    text: "Your sign-in code for " + host + " is:\n\n" + code + "\n\n" +
      "It expires in " + Math.round(EMAIL_OTP.expiresIn / 60) + " minutes. Enter it only on " + host + ".\n" +
      "If you did not try to sign in, ignore this email. Nobody from " + name + " will ask you for this code."
  };
}
