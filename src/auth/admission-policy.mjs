/**
 * NATH-16: account admission. Decides whether a NEW Nathan account may be created, for every way an
 * account is created (password sign-up, social sign-in, SAML and SCIM just-in-time provisioning).
 * Admission is separate from application access (NATH-13 roles) and from administrator privilege.
 *
 * Owner decision (NATH-1): invitation-only by default, self-service optional, per installation.
 * - invitation-only: an account is created only for an address with an open invitation (created by
 *   an administrator, bound to that email, single use, expiring, revocable) that the creating method
 *   has proven (emailVerified === true). Password sign-up is the one exception: it proves nothing
 *   at creation, so it is admitted provisionally and claims the invitation only when the address is
 *   verified (admitOnVerification); until then it cannot sign in. Or for the installer's
 *   first administrator (the bootstrap email, proven by the sign-in method, while that account does
 *   not exist yet; on legacy manual installations, a verified NATHAN_ADMIN_EMAILS address);
 * - self-service: every account the sign-in method itself would create is admitted.
 * A missing or unreadable setting means invitation-only; any error refuses the account (fail closed).
 *
 * Plain JS on any D1-shaped `db`, so the same code is unit-tested in Node and bundled into the Worker.
 */

export const ADMISSION_MODES = Object.freeze(["invitation-only", "self-service"]);
export const DEFAULT_ADMISSION_MODE = "invitation-only";
export const INVITATION_DAYS = Object.freeze({ default: 7, max: 30 });
/** The refusal every sign-in path shows (Better Auth error code and message). */
export const NOT_ADMITTED = Object.freeze({
  code: "ACCOUNT_NOT_ADMITTED",
  message: "This Nathan installation creates new accounts by invitation only, and this email address has no open invitation. " +
    "Ask an administrator to invite it, then sign in again."
});

const EMAIL = /^[^\s@"<>()\[\],;:\\]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
/** The canonical form of an address, or null when it is not a usable email address. */
export function normalizeEmail(value) {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && EMAIL.test(email) ? email : null;
}

/** The installation's admission mode; anything but an explicit self-service row is invitation-only. */
export async function admissionMode(db) {
  const row = await db.prepare("SELECT mode FROM nathan_admission_settings WHERE id='primary' LIMIT 1").first();
  return row?.mode === "self-service" ? "self-service" : DEFAULT_ADMISSION_MODE;
}

/** How Better Auth is creating the account, from its endpoint context (audit and invitation record). */
export function creationMethod(ctx) {
  const path = typeof ctx?.path === "string" ? ctx.path : "";
  const id = param => (typeof ctx?.params?.[param] === "string" && /^[a-z0-9][a-z0-9-]{0,62}$/.test(ctx.params[param]) ? ctx.params[param] : "unknown");
  if (path === "/sign-in/email-otp") return "email-otp";
  if (path === "/sign-up/email") return "password";
  if (path === "/callback/:id" || path === "/oauth2/callback/:id") return "social:" + id("id");
  if (path === "/sign-in/social") return "social:id-token";
  if (path === "/sso/saml2/sp/acs/:providerId") return "saml:" + id("providerId");
  if (path.startsWith("/sso/")) return "enterprise-sso:" + id("providerId");
  return "other";
}

/**
 * The installer-approved first administrator: only with an address the sign-in method proved, and
 * only while that account does not exist yet (the installer binds it to admin_user_id afterwards).
 */
export async function isBootstrapAdmission(db, env, email, emailVerified) {
  if (emailVerified !== true) return false;
  const row = await db.prepare("SELECT admin_email, admin_user_id FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1").first();
  if (row) return !row.admin_user_id && normalizeEmail(row.admin_email) === email;
  // Legacy manual installations have no installer record: their configured administrator allowlist.
  if (env?.NATHAN_BOOTSTRAP_REQUIRED === "true") return false;
  return String(env?.NATHAN_ADMIN_EMAILS || "").split(",").map(normalizeEmail).includes(email);
}

const OPEN = "uses=0 AND revoked_at IS NULL AND expires_at>unixepoch()";
const AUDIT = "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) ";
/** The open invitation for an address, or null. */
export async function openInvitation(db, email) {
  return db.prepare("SELECT id FROM nathan_invitations WHERE email=? AND " + OPEN + " LIMIT 1").bind(email).first();
}
/** Claims the open invitation for an address (one statement, so two creations cannot share it). */
export async function claimInvitation(db, email, method, userId = null) {
  const row = await db.prepare(
    "UPDATE nathan_invitations SET uses=1, used_at=unixepoch(), used_method=?, used_by_user=? WHERE id=(SELECT id FROM nathan_invitations WHERE email=? AND " +
    OPEN + " LIMIT 1) AND " + OPEN + " RETURNING id"
  ).bind(method, userId, email).first();
  return row?.id ?? null;
}
/**
 * For callers that create the account in their own D1 batch (SCIM): claims invitation `id` for
 * `userId`, or makes the batch fail. A used, revoked or expired invitation sets uses=2, which the
 * table's CHECK rejects, so the batch (and the account it would create) is rolled back.
 */
export function claimInvitationStatement(id, method, userId) {
  return {
    sql: "UPDATE nathan_invitations SET uses=CASE WHEN " + OPEN + " THEN 1 ELSE 2 END, used_at=unixepoch(), used_method=?, used_by_user=? WHERE id=?",
    params: [method, userId, id]
  };
}

/**
 * The admission decision for one new account. `{ admitted: true, via }` with via "self-service",
 * "invitation" (the invitation is claimed), "invitation_pending" (password sign-up with an open
 * invitation: nothing is claimed; the caller records the account as provisional) or "bootstrap";
 * `{ admitted: false }` otherwise. An invitation is claimed only for an address the method proved.
 * Throws on database errors: callers refuse the account.
 */
/** @param {any} db @param {any} env @param {{email: unknown, emailVerified: boolean, method: string, invitationId?: string|null, requirePasswordInvitation?: boolean}} input */
export async function decideAdmission(db, env, { email, emailVerified, method, invitationId = null, requirePasswordInvitation = false }) {
  const address = normalizeEmail(email);
  if (!address) return { admitted: false, via: null };
  if (method === "email-otp") {
    // Migration 0019 consumes this exact invitation atomically with the Better Auth user INSERT.
    const invitation = emailVerified === true && invitationId && await openInvitation(db, address);
    return invitation && invitation.id === invitationId ? { admitted: true, via: "invitation", invitationId } : { admitted: false, via: null };
  }
  if (!(requirePasswordInvitation && method === "password")) {
    if (await isBootstrapAdmission(db, env, address, emailVerified)) return { admitted: true, via: "bootstrap" };
    if (await admissionMode(db) === "self-service") return { admitted: true, via: "self-service" };
  }
  if (method === "password") return await openInvitation(db, address) ? { admitted: true, via: "invitation_pending" } : { admitted: false, via: null };
  if (emailVerified !== true) return { admitted: false, via: null };
  const invitation = await claimInvitation(db, address, method);
  return invitation ? { admitted: true, via: "invitation", invitationId: invitation } : { admitted: false, via: null };
}

/** Marks a password sign-up as provisional (before Better Auth inserts the account). */
export async function recordPendingAdmission(db, email, method) {
  // Only an unbound mark is refreshed. A concurrent second sign-up for the same address (both pass
  // Better Auth's "user exists" check) must not unlink the account the first one created, or the
  // real invitee could no longer supersede it. A mark for a deleted account goes with it (CASCADE).
  await db.prepare("INSERT INTO nathan_admission_pending(email,user_id,method) VALUES (?,NULL,?) " +
    "ON CONFLICT(email) DO UPDATE SET method=excluded.method, created_at=unixepoch() WHERE nathan_admission_pending.user_id IS NULL")
    .bind(email, method).run();
}
/** Binds the provisional mark to the account Better Auth created. */
export async function bindPendingAdmission(db, email, userId) {
  await db.prepare("UPDATE nathan_admission_pending SET user_id=? WHERE email=? AND user_id IS NULL").bind(userId, email).run();
}
const PENDING = "SELECT email, method FROM nathan_admission_pending WHERE user_id=? OR (user_id IS NULL AND email=?) LIMIT 1";

/**
 * When an account's address is verified: `{ pending: false }` for an ordinary account. For a
 * provisional password sign-up, the admission decision now that the address is proven:
 * `{ pending: true, admitted: true, via }` (the open invitation is claimed for this account, or the
 * installation is self-service, or it is the installer's first administrator), else
 * `{ pending: true, admitted: false }` and the caller must refuse the verification.
 */
export async function admitOnVerification(db, env, { userId, email, requirePasswordInvitation = false }) {
  const address = normalizeEmail(email);
  const pending = await db.prepare(PENDING).bind(userId, address ?? "").first();
  if (!pending) return requirePasswordInvitation ? { pending: true, admitted: false } : { pending: false };
  if (!address) return { pending: true, admitted: false };
  let decision;
  if (!requirePasswordInvitation && await isBootstrapAdmission(db, env, address, true)) decision = { pending: true, admitted: true, via: "bootstrap" };
  else if (!requirePasswordInvitation && await admissionMode(db) === "self-service") decision = { pending: true, admitted: true, via: "self-service" };
  else {
    const invitation = await claimInvitation(db, address, pending.method, userId);
    decision = invitation ? { pending: true, admitted: true, via: "invitation", invitationId: invitation } : { pending: true, admitted: false };
  }
  if (decision.admitted) await db.prepare("DELETE FROM nathan_admission_pending WHERE email=?").bind(pending.email).run();
  return decision;
}

/**
 * The real invitee proved `email` (a verified provider address). If a provisional password account
 * holds that address (unverified, never signed in, no passkey) while its invitation is still open,
 * it was created by someone who could not prove the address: delete it (audited) so the invitee's
 * sign-in creates their own account. Returns the deleted user id, or null.
 */
export async function supersedeUnprovenAccount(db, email, provider = "unknown") {
  const address = normalizeEmail(email);
  if (!address) return null;
  const row = await db.prepare(
    'SELECT u."id" AS id FROM nathan_admission_pending p JOIN "user" u ON u."id"=p.user_id ' +
    'WHERE p.email=? AND lower(u."email")=? AND u."emailVerified"=0 ' +
    'AND NOT EXISTS (SELECT 1 FROM "session" s WHERE s."userId"=u."id") AND NOT EXISTS (SELECT 1 FROM "passkey" k WHERE k."userId"=u."id") ' +
    "AND EXISTS (SELECT 1 FROM nathan_invitations i WHERE i.email=p.email AND i.uses=0 AND i.revoked_at IS NULL AND i.expires_at>unixepoch()) LIMIT 1"
  ).bind(address, address).first();
  if (!row) return null;
  const deleted = await db.prepare('DELETE FROM "user" WHERE "id"=? AND "emailVerified"=0 RETURNING "id" AS id').bind(row.id).first();
  if (!deleted) return null;
  const via = /^[a-z][a-z0-9-]{0,62}$/.test(String(provider)) ? provider : "unknown";
  await db.prepare(AUDIT + "VALUES (?,'system:admission','account_superseded',?,'succeeded')")
    .bind(crypto.randomUUID(), row.id + " email=" + address + " provider=" + via).run();
  return row.id;
}

/** Audits an admission decision. Refusals are kept to one row per method and minute (sign-up floods). */
export async function auditAdmission(db, method, outcome) {
  if (outcome === "refused") {
    await db.prepare(AUDIT + "SELECT ?,'system:admission','account_admission',?,'refused' WHERE NOT EXISTS (SELECT 1 FROM nathan_security_audit " +
      "WHERE action='account_admission' AND target=? AND outcome='refused' AND created_at>=unixepoch()-60)")
      .bind(crypto.randomUUID(), method, method).run();
    return;
  }
  await db.prepare(AUDIT + "VALUES (?,'system:admission','account_admission',?,?)").bind(crypto.randomUUID(), method, outcome).run();
}
