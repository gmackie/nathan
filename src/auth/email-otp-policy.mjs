import { normalizeEmail } from "./admission-policy.mjs";

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
/** Reserve before checking a proof. A successful check releases its slot in the same window.
 * Concurrent verifiers share the remaining capacity; an interrupted verification costs one slot. */
export async function reserveProofAttempt(db, now = Date.now()) {
  const { window, max } = FAILURE_BUDGET;
  const row = await db.prepare(
    "INSERT INTO nathan_email_otp_limits(key,count,window_start,window_seconds) VALUES (?1,1,?2,?3) " +
    "ON CONFLICT(key) DO UPDATE SET count=CASE WHEN ?2-window_start>=window_seconds THEN 1 ELSE count+1 END, " +
    "window_start=CASE WHEN ?2-window_start>=window_seconds THEN ?2 ELSE window_start END " +
    "WHERE count<?4 OR ?2-window_start>=window_seconds RETURNING window_start"
  ).bind(FAILURES_KEY, Math.floor(now / 1000), window, max).first();
  return row?.window_start ?? null;
}

export async function releaseProofAttempt(db, start) {
  await db.prepare("UPDATE nathan_email_otp_limits SET count=count-1 WHERE key=? AND window_start=? AND count>0")
    .bind(FAILURES_KEY, start).run();
}

export async function auditRefusedProof(db) {
  await db.prepare("INSERT OR IGNORE INTO nathan_security_audit(id,actor,action,target,outcome) " +
    "VALUES ('email-otp-refusal:' || (unixepoch()/60),'system:email-otp','email_otp_sign_in','hosted','rejected')").run();
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

