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
 * - Rate limits per IP (Better Auth's rate limiter), per address (10 minutes and a day, hashed keys)
 *   on sending and verifying, and an instance-wide hourly budget of refused codes.
 * - The send route answers the same way for every address. In invitation-only mode a code is only
 *   mailed to an address that could sign in (an account, an open invitation or the installer's
 *   first administrator); nothing is mailed otherwise, and the answer does not say so.
 * - Account creation goes through Nathan's admission guard (method "email-otp"): the code proves the
 *   address, so it may claim an open invitation, and in self-service mode it creates the account.
 * - Accounts with something stronger never sign in by email code (codeSignInRefusal): administrators,
 *   accounts with TOTP or a passkey, directory and enterprise SSO accounts and verified SSO domains.
 *   They get no mail, and a code attempt fails exactly like a wrong code (Better Auth checks the code
 *   first; Nathan refuses the session), so the answers say nothing about the account.
 * - Sessions created by a code are recorded (nathan_email_otp_sessions) and never administer.
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
 * Rate limits. Per IP: Better Auth's rate limiter (key = IP + path, database storage). Per address
 * and instance-wide: Nathan's own fixed-window counters (nathan_email_otp_limits, migration 0019),
 * keyed by a SHA-256 hash, so no table holds an address and Better Auth's pruning never resets them.
 */
export const IP_LIMITS = Object.freeze({
  [SEND_PATH]: Object.freeze({ window: 600, max: 10 }),
  [VERIFY_PATH]: Object.freeze({ window: 600, max: 20 })
});
export const ADDRESS_LIMITS = Object.freeze({
  send: Object.freeze({ window: 600, max: 3 }),
  "send-day": Object.freeze({ window: 86400, max: 10 }),
  verify: Object.freeze({ window: 600, max: 5 }),
  "verify-day": Object.freeze({ window: 86400, max: 15 })
});
/**
 * Instance-wide budget of refused codes (wrong, expired, used up) per hour. Guessing spread over
 * many addresses and IPs stops here: at most this many guesses an hour reach any account.
 */
export const FAILURE_BUDGET = Object.freeze({ window: 3600, max: 500 });

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
/** A limit key: a hash, so the limits table never holds an address. */
export async function addressLimitKey(kind, email) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("nathan-email-otp:" + email));
  return "address:" + kind + ":" + hex(digest);
}
const FAILURES_KEY = "instance:failures";

/**
 * Adds `amount` to one fixed-window counter atomically (one statement) and returns the new count and
 * the seconds until the window ends. A window starts at the first request after the previous one ended.
 */
async function bump(db, key, rule, amount, nowSeconds) {
  const row = await db.prepare(
    "INSERT INTO nathan_email_otp_limits(key,count,window_start,window_seconds) VALUES (?1,?2,?3,?4) " +
    "ON CONFLICT(key) DO UPDATE SET " +
    "count=CASE WHEN ?3-window_start>=window_seconds THEN ?2 ELSE count+?2 END, " +
    "window_start=CASE WHEN ?3-window_start>=window_seconds THEN ?3 ELSE window_start END, window_seconds=?4 " +
    "RETURNING count, window_start AS start"
  ).bind(key, amount, nowSeconds, rule.window).first();
  const count = Number(row?.count), start = Number(row?.start);
  return { count: Number.isFinite(count) ? count : Infinity, retryAfter: Math.max(1, (Number.isFinite(start) ? start : nowSeconds) + rule.window - nowSeconds) };
}

/**
 * Counts one request of `kind` ("send" or "verify") for an address against its 10-minute and daily
 * limits. Returns { allowed, retryAfter } (seconds).
 */
export async function consumeAddressLimit(db, kind, email, now = Date.now()) {
  const seconds = Math.floor(now / 1000);
  let retryAfter = 0;
  for (const name of [kind, kind + "-day"]) {
    const rule = ADDRESS_LIMITS[name];
    const result = await bump(db, await addressLimitKey(name, email), rule, 1, seconds);
    if (result.count > rule.max) retryAfter = Math.max(retryAfter, result.retryAfter);
  }
  return retryAfter ? { allowed: false, retryAfter } : { allowed: true, retryAfter: null };
}
/** Whether the instance-wide budget of refused codes is used up. */
export async function failureBudgetExhausted(db, now = Date.now()) {
  const result = await bump(db, FAILURES_KEY, FAILURE_BUDGET, 0, Math.floor(now / 1000));
  return result.count >= FAILURE_BUDGET.max ? result.retryAfter : 0;
}
/** Records one refused code; returns the count in the current hour. */
export async function recordFailure(db, now = Date.now()) {
  return (await bump(db, FAILURES_KEY, FAILURE_BUDGET, 1, Math.floor(now / 1000))).count;
}
/** Deletes counters whose window has ended (scheduled). */
export async function pruneEmailOtpLimits(db) {
  await db.prepare("DELETE FROM nathan_email_otp_limits WHERE window_start+window_seconds<unixepoch()").run();
}

/** The domain part of an address, or null. */
const domainOf = email => (normalizeEmail(email)?.split("@")[1] ?? null);
/** Whether an address is inside a DNS-verified enterprise SSO domain (those people sign in through their IdP). */
export async function inVerifiedSsoDomain(db, email) {
  const domain = domainOf(email);
  if (!domain) return false;
  const rows = (await db.prepare('SELECT "domain" AS domain FROM "ssoProvider" WHERE "domainVerified"=1').all()).results ?? [];
  return rows.some(row => String(row.domain ?? "").toLowerCase().split(",").map(d => d.trim()).filter(Boolean)
    .some(d => domain === d || domain.endsWith("." + d)));
}

/**
 * Why an existing account may not sign in by email code, or null. An emailed code must not become a
 * way around something stronger the account already has:
 * - an administrator (admin role, an administrator grant, or the installer's bound first
 *   administrator): a mailbox alone never opens Identity Studio;
 * - an enrolled TOTP authenticator or passkey: the code would skip that second factor;
 * - a directory (SCIM) or enterprise SSO account, or any address in a verified SSO domain: those
 *   people sign in through their organization's IdP, with its MFA and policies.
 * Unknown users are judged by their address (the SSO domain rule). Throws on database errors.
 */
/** @param {any} db @param {{email?: string, userId?: string}} who */
export async function codeSignInRefusal(db, { email, userId }) {
  const address = normalizeEmail(email);
  const row = await db.prepare(
    'SELECT u."id" AS id, coalesce(u."role",\'user\')=\'admin\' AS admin, coalesce(u."twoFactorEnabled",0) AS totp, ' +
    "EXISTS (SELECT 1 FROM nathan_admin_grants g WHERE g.user_id=u.\"id\") AS granted, " +
    "EXISTS (SELECT 1 FROM nathan_bootstrap_status b WHERE b.admin_user_id=u.\"id\") AS root, " +
    'EXISTS (SELECT 1 FROM "twoFactor" t WHERE t."userId"=u."id" AND coalesce(t."verified",1)=1) AS factor, ' +
    'EXISTS (SELECT 1 FROM "passkey" k WHERE k."userId"=u."id") AS passkey, ' +
    "EXISTS (SELECT 1 FROM nathan_scim_users d WHERE d.user_id=u.\"id\") AS directory, " +
    'EXISTS (SELECT 1 FROM "account" a JOIN "ssoProvider" p ON p."providerId"=a."providerId" WHERE a."userId"=u."id") AS sso, ' +
    'u."email" AS email FROM "user" u WHERE ' + (userId ? 'u."id"=?' : 'lower(u."email")=?') + " LIMIT 1"
  ).bind(userId ?? address ?? "").first();
  if (row) {
    if (Number(row.admin) || Number(row.granted) || Number(row.root)) return "administrator";
    if (Number(row.totp) || Number(row.factor) || Number(row.passkey)) return "stronger-factor";
    if (Number(row.directory) || Number(row.sso)) return "organization-account";
  }
  if (await inVerifiedSsoDomain(db, row?.email ?? address)) return "organization-account";
  return null;
}

/**
 * Whether a sign-in code may be mailed to an address: an existing account that may sign in by code,
 * the installer's first administrator, self-service mode, or an open invitation. Invitation-only mode
 * mails nothing to anyone else, so Nathan sends no mail on behalf of strangers. Fails closed.
 */
export async function mayReceiveSignInCode(db, env, email) {
  const address = normalizeEmail(email);
  if (!address) return false;
  if (await codeSignInRefusal(db, { email: address })) return false;
  const user = await db.prepare('SELECT 1 AS found FROM "user" WHERE lower("email")=? LIMIT 1').bind(address).first();
  if (user) return true;
  // The address will be proven by the code, so the bootstrap check runs as if it were.
  if (await isBootstrapAdmission(db, env, address, true)) return true;
  if (await admissionMode(db) === "self-service") return true;
  return Boolean(await openInvitation(db, address));
}

/** A session created by an email code: never an administrator session (mayAdminister). */
export async function isEmailCodeSession(db, sessionId) {
  if (typeof sessionId !== "string" || !sessionId) return false;
  return Boolean(await db.prepare("SELECT 1 AS x FROM nathan_email_otp_sessions WHERE session_id=? LIMIT 1").bind(sessionId).first());
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
