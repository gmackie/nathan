/**
 * NATH-16: account admission in Identity Studio and in Better Auth.
 *
 * - Studio (GET/POST /studio/api/admission; administrator with completed enrollment and a fresh
 *   step-up, same-origin JSON, exact confirmation, every attempt audited): the installation's
 *   admission mode and invitations (create, list, revoke).
 * - Better Auth: admissionUserCreateGuard is the ONE databaseHooks.user.create.before guard. It runs
 *   the SAML connection guard (NATH-10) and the enterprise OIDC domain guard first, then the
 *   admission decision, for every Better Auth account creation. An invitation is claimed only for an
 *   address the method proved; a password sign-up is admitted provisionally and claims it when the
 *   address is verified (admissionBeforeEmailVerification). SCIM just-in-time creation does not go
 *   through Better Auth; it asks the same policy through admitJustInTime (src/auth/scim/lifecycle.ts).
 * - Squatting: withInviteeSupersession lets the real invitee's verified social sign-in replace a
 *   provisional password account that someone else created for the invited address; Studio's
 *   "reissue" removes an unverified account for an address and invites it again.
 */
import { APIError } from "better-auth/api";
import { managementEmail, type AuthEnv } from "./env";
import { audit } from "./admin-service";
import { samlUserCreateGuard } from "./saml-policy.mjs";
import { enterpriseOidcUserCreateGuard } from "./enterprise-oidc-policy.mjs";
import {
  ADMISSION_MODES, INVITATION_DAYS, NOT_ADMITTED, admissionMode, auditAdmission, creationMethod, decideAdmission, normalizeEmail,
  recordPendingAdmission, bindPendingAdmission, admitOnVerification, supersedeUnprovenAccount
} from "./admission-policy.mjs";

const ID = /^[0-9a-f-]{36}$/;
const appManagedAccount = "An account with this email is managed by the provisioning application. Reconcile its access in that application.";
type InvitationRow = { id: string; email: string; createdBy: string; createdAt: number; expiresAt: number; uses: number;
  usedAt: number | null; usedMethod: string | null; usedByUser: string | null; revokedAt: number | null; revokedBy: string | null; now: number };

function stateOf(row: InvitationRow) {
  if (row.uses === 1) return "used";
  if (row.revokedAt !== null) return "revoked";
  return row.expiresAt <= row.now ? "expired" : "pending";
}

/** Mode and the most recent invitations (no secrets: an invitation is bound to its email, not to a token). */
export async function admissionOverview(env: AuthEnv) {
  const [setting, invitations, upgrade] = await Promise.all([
    env.DB.prepare("SELECT mode, updated_by AS updatedBy, updated_at AS updatedAt FROM nathan_admission_settings WHERE id='primary' LIMIT 1")
      .first<{ mode: string; updatedBy: string; updatedAt: number }>(),
    env.DB.prepare("SELECT id, email, created_by AS createdBy, created_at AS createdAt, expires_at AS expiresAt, uses, used_at AS usedAt, " +
      "used_method AS usedMethod, used_by_user AS usedByUser, revoked_at AS revokedAt, revoked_by AS revokedBy, unixepoch() AS now " +
      "FROM nathan_invitations ORDER BY created_at DESC, rowid DESC LIMIT 200").all<InvitationRow>(),
    upgradeNoticeDue(env)
  ]);
  return {
    mode: setting?.mode === "self-service" ? "self-service" : "invitation-only",
    updatedBy: setting?.updatedBy ?? null, updatedAt: setting?.updatedAt ?? null,
    invitations: invitations.results.map(({ now: _now, uses: _uses, ...row }) => ({ ...row, state: stateOf({ ...row, uses: _uses, now: _now }) })),
    note: "Admission decides only whether a new account may be created. It grants no application access and no administrator rights.",
    ...(upgrade ? { upgradeNotice: UPGRADE_NOTICE } : {})
  };
}

/** Shown once to installations that had accounts before migration 0017 made them invitation-only. */
export const UPGRADE_NOTICE = "This installation had accounts before the upgrade that introduced account admission, and new accounts now " +
  "need an invitation (the default). Sign-ups that used to work are refused, and SCIM just-in-time connections create no accounts, " +
  "until you invite people or switch to self-service below. Choose a mode or dismiss this notice.";
/** True until an administrator changes the mode or dismisses the notice (both audited). */
async function upgradeNoticeDue(env: AuthEnv) {
  const row = await env.DB.prepare("SELECT 1 AS due FROM nathan_security_audit WHERE action='admission_default_invitation_only' AND target='existing-users' " +
    "AND NOT EXISTS (SELECT 1 FROM nathan_security_audit WHERE outcome='succeeded' AND action IN ('admission_mode_change','admission_upgrade_notice_dismiss')) LIMIT 1")
    .first<{ due: number }>().catch(() => null);
  return Boolean(row);
}

/** One new invitation (superseding an open one), plus extra statements in the same D1 batch. */
async function createInvitation(env: AuthEnv, email: string, days: number, actor: string, extra: D1PreparedStatement[] = []) {
  const id = crypto.randomUUID();
  await env.DB.batch([
    ...extra,
    // A new invitation supersedes an open (or expired, unused) one for the same address.
    env.DB.prepare("UPDATE nathan_invitations SET revoked_at=unixepoch(), revoked_by=? WHERE email=? AND uses=0 AND revoked_at IS NULL")
      .bind("superseded by " + actor, email),
    env.DB.prepare("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,?,unixepoch()+?)").bind(id, email, actor, days * 86400),
    env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,'invitation_create',?,'succeeded')")
      .bind(crypto.randomUUID(), actor, id)
  ]);
  const created = await env.DB.prepare("SELECT expires_at AS expiresAt FROM nathan_invitations WHERE id=?").bind(id).first<{ expiresAt: number }>();
  return { id, email, expiresAt: created!.expiresAt, state: "pending",
    note: "Tell the person to sign in with this exact email address through any enabled method. The invitation works once." };
}
function invitationInput(body: any) {
  const email = normalizeEmail(body?.email);
  const days = body?.days === undefined ? INVITATION_DAYS.default : Number(body.days);
  return email && Number.isInteger(days) && days >= 1 && days <= INVITATION_DAYS.max ? { email, days } : null;
}
type ExistingAccount = { id: string; verified: number; role: string | null; sessions: number; passkeys: number; directory: number; appProvisioned: number; logins: number };
function existingAccount(env: AuthEnv, email: string) {
  return env.DB.prepare('SELECT u."id" AS id, u."emailVerified" AS verified, u."role" AS role, ' +
    '(SELECT count(*) FROM "session" s WHERE s."userId"=u."id") AS sessions, (SELECT count(*) FROM "passkey" k WHERE k."userId"=u."id") AS passkeys, ' +
    "(SELECT count(*) FROM nathan_scim_users d WHERE d.user_id=u.\"id\") AS directory, " +
    "EXISTS(SELECT 1 FROM nathan_app_provisions p WHERE p.user_id=u.id) AS appProvisioned, " +
    '(SELECT count(*) FROM "account" a WHERE a."userId"=u."id" AND a."providerId"<>\'credential\') AS logins ' +
    'FROM "user" u WHERE lower(u."email")=? LIMIT 1').bind(email).first<ExistingAccount>();
}

/**
 * One Studio operation:
 *   { op: "mode", mode, confirm: "CONFIRM ADMISSION <mode>" }
 *   { op: "invite", email, days? }                      (1..30 days, default 7)
 *   { op: "reissue", email, days?, confirm: "CONFIRM REISSUE INVITATION <email>" }
 *        removes an unverified, never signed-in account holding the address, then invites it
 *   { op: "revoke", id, confirm: "CONFIRM REVOKE INVITATION <id>" }
 *   { op: "dismiss-upgrade-notice" }
 * Errors carry a safe message (they never echo submitted values).
 */
export async function applyAdmissionOperation(env: AuthEnv, body: any, actor: string) {
  const op = body?.op;
  if (op === "mode") {
    const mode = ADMISSION_MODES.includes(body.mode) ? body.mode as string : null;
    if (!mode) { await audit(env, actor, "admission_mode_change", "invalid", "rejected"); throw Error("Invalid admission mode"); }
    if (body.confirm !== "CONFIRM ADMISSION " + mode) {
      await audit(env, actor, "admission_mode_change", mode, "rejected");
      throw Error("Explicit confirmation required: CONFIRM ADMISSION " + mode);
    }
    await env.DB.batch([
      env.DB.prepare("INSERT INTO nathan_admission_settings(id,mode,updated_by) VALUES ('primary',?,?) " +
        "ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, updated_by=excluded.updated_by, updated_at=unixepoch()").bind(mode, actor),
      env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,'admission_mode_change',?,'succeeded')")
        .bind(crypto.randomUUID(), actor, mode)
    ]);
    return { mode, note: mode === "self-service"
      ? "Anyone who can sign in through an enabled method may now create an account. Application access still needs roles."
      : "New accounts now need an open invitation." };
  }
  if (op === "invite") {
    const input = invitationInput(body);
    if (!input) {
      await audit(env, actor, "invitation_create", "invalid", "rejected");
      throw Error("Invalid invitation: give an email address and 1 to " + INVITATION_DAYS.max + " days");
    }
    const account = await existingAccount(env, input.email);
    if (account) {
      await audit(env, actor, "invitation_create", "existing-account", "rejected");
      if (account.appProvisioned) throw Error(appManagedAccount);
      if (Number(account.verified) !== 1) throw Error("An unverified account holds this email address. To let the real person in, " +
        "reissue the invitation: it removes that unverified account (CONFIRM REISSUE INVITATION <email>)");
      throw Error("An account with this email address already exists; it needs no invitation");
    }
    return createInvitation(env, input.email, input.days, actor);
  }
  if (op === "reissue") {
    // Someone created an unverified account for an address (for example a password sign-up for an
    // invited address); remove it, audited, and invite the address again. Never a verified account,
    // an administrator, a directory-managed account, or one that has signed in or holds a passkey.
    const input = invitationInput(body);
    if (!input || body.confirm !== "CONFIRM REISSUE INVITATION " + input.email) {
      await audit(env, actor, "unverified_account_remove", "invalid", "rejected");
      throw Error("Explicit confirmation required: CONFIRM REISSUE INVITATION <email>");
    }
    const account = await existingAccount(env, input.email);
    if (!account) return createInvitation(env, input.email, input.days, actor);
    if (account.appProvisioned) {
      await audit(env, actor, "unverified_account_remove", account.id, "rejected");
      throw Error(appManagedAccount);
    }
    if (Number(account.verified) === 1 || account.role === "admin" || Number(account.sessions) || Number(account.passkeys) || Number(account.directory) || Number(account.logins)) {
      await audit(env, actor, "unverified_account_remove", account.id, "rejected");
      throw Error("An account with this email address is verified, has signed in, has a social or SSO login, or is managed by a directory; it is never removed here");
    }
    const removed = await env.DB.prepare('DELETE FROM "user" WHERE "id"=? AND "emailVerified"=0 AND coalesce("role",\'user\')<>\'admin\' ' +
      'AND NOT EXISTS (SELECT 1 FROM "session" WHERE "userId"=?) AND NOT EXISTS (SELECT 1 FROM "passkey" WHERE "userId"=?) ' +
      'AND NOT EXISTS (SELECT 1 FROM nathan_scim_users WHERE user_id=?) ' +
      'AND NOT EXISTS (SELECT 1 FROM nathan_app_provisions WHERE user_id=user.id) ' +
      // A social or SSO login means the account has been used even if its session ended (sign-out
      // and expiry delete session rows); only password-only unverified accounts are removable.
      'AND NOT EXISTS (SELECT 1 FROM "account" WHERE "userId"=? AND "providerId"<>\'credential\') RETURNING "id" AS id')
      .bind(account.id, account.id, account.id, account.id, account.id).first<{ id: string }>();
    if (!removed) {
      await audit(env, actor, "unverified_account_remove", account.id, "rejected");
      throw Error("Unknown account state; nothing removed");
    }
    const created = await createInvitation(env, input.email, input.days, actor, [
      env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,'unverified_account_remove',?,'succeeded')")
        .bind(crypto.randomUUID(), actor, account.id)
    ]);
    return { ...created, removedUser: account.id };
  }
  if (op === "dismiss-upgrade-notice") {
    await audit(env, actor, "admission_upgrade_notice_dismiss", "admission", "succeeded");
    return { dismissed: true };
  }
  if (op === "revoke") {
    const id = typeof body.id === "string" && ID.test(body.id) ? body.id : null;
    if (!id || body.confirm !== "CONFIRM REVOKE INVITATION " + id) {
      await audit(env, actor, "invitation_revoke", id ?? "invalid", "rejected");
      throw Error("Explicit confirmation required: CONFIRM REVOKE INVITATION <id>");
    }
    const changed = await env.DB.prepare("UPDATE nathan_invitations SET revoked_at=unixepoch(), revoked_by=? WHERE id=? AND uses=0 AND revoked_at IS NULL")
      .bind(actor, id).run();
    if (!changed.meta?.changes) {
      await audit(env, actor, "invitation_revoke", id, "rejected");
      throw Error("Unknown invitation, or it was already used or revoked");
    }
    await audit(env, actor, "invitation_revoke", id, "succeeded");
    return { id, state: "revoked" };
  }
  await audit(env, actor, "admission_operation", "invalid", "rejected");
  throw Error("Unknown admission operation");
}
export const ADMISSION_ERRORS = /^(Invalid|Explicit|Unknown|An account|An unverified)/;

function refuse(): never {
  // 422, not 403: Better Auth turns a 403 during password sign-up into its generic "check your
  // email" answer, which would hide the reason from the person signing up.
  throw new APIError("UNPROCESSABLE_ENTITY", { code: NOT_ADMITTED.code, message: NOT_ADMITTED.message });
}

/**
 * databaseHooks.user.create.before. Composes the SAML connection guard and the admission decision;
 * fails closed (no account) on any error. Returns the SAML guard's data changes, if any.
 */
export async function admissionUserCreateGuard(env: AuthEnv, user: any, ctx: any, invitationId: string | null = null) {
  let guard: any;
  try {
    guard = await samlUserCreateGuard(env.DB, user, ctx);
    if (guard === undefined) guard = await enterpriseOidcUserCreateGuard(env.DB, user, ctx);
  } catch {
    return false;
  }
  if (guard === false) return false;
  const merged = { ...user, ...(guard && typeof guard === "object" ? guard.data : {}) };
  const method = creationMethod(ctx);
  let decision: { admitted: boolean; via: string | null };
  try {
    decision = await decideAdmission(env.DB, env, { email: merged.email, emailVerified: merged.emailVerified === true, method, invitationId,
      requirePasswordInvitation: Boolean(env[managementEmail]) });
    // A password sign-up holds nothing yet: it is provisional until its address is verified.
    if (decision.via === "invitation_pending") await recordPendingAdmission(env.DB, normalizeEmail(merged.email), method);
  } catch {
    return false;
  }
  if (!decision.admitted) {
    await auditAdmission(env.DB, method, "refused").catch(() => {});
    refuse();
  }
  if (method !== "email-otp") await auditAdmission(env.DB, method, "admitted_" + decision.via!.replace("-", "_"));
  return guard ?? undefined;
}

/** databaseHooks.user.create.after: records which account an invitation (or a provisional sign-up) admitted. */
export async function admissionUserCreated(env: AuthEnv, user: any) {
  const email = normalizeEmail(user?.email);
  if (!email || typeof user?.id !== "string") return;
  await env.DB.prepare("UPDATE nathan_invitations SET used_by_user=? WHERE email=? AND uses=1 AND used_by_user IS NULL").bind(user.id, email).run();
  await bindPendingAdmission(env.DB, email, user.id);
}

/**
 * emailVerification.beforeEmailVerification: a provisional password account claims its invitation
 * now that the address is proven. Without one (revoked, expired, used by the real person) the
 * verification is refused, so the account stays unverified and cannot sign in. Fails closed.
 */
export async function admissionBeforeEmailVerification(env: AuthEnv, user: any) {
  let decision: { pending: boolean; admitted?: boolean; via?: string };
  try {
    decision = await admitOnVerification(env.DB, env, { userId: user?.id, email: user?.email });
  } catch {
    refuse();
  }
  if (!decision.pending) return;
  if (!decision.admitted) {
    await auditAdmission(env.DB, "password", "refused_at_verification").catch(() => {});
    refuse();
  }
  await auditAdmission(env.DB, "password", "admitted_" + decision.via!.replace("-", "_"));
}

/**
 * Social providers whose verified address replaces a provisional password account that someone
 * created for the same invited address (supersedeUnprovenAccount). It runs when the provider
 * returns the user, before Better Auth looks the address up, so the real invitee's sign-in creates
 * their own account instead of failing to link to the squatter's unverified one.
 */
const providerEmail = (id: string, profile: any) => (id === "twitter" ? profile?.data?.email : profile?.email);
export function withInviteeSupersession<T extends Record<string, any>>(env: AuthEnv, providers: T): T {
  const supersede = async (email: unknown, provider: string) => {
    if (typeof email === "string") await supersedeUnprovenAccount(env.DB, email, provider);
  };
  const out: Record<string, any> = {};
  for (const [id, options] of Object.entries(providers ?? {})) {
    if (!options || typeof options !== "object") { out[id] = options; continue; }
    const wrapped = { ...options };
    if (typeof options.getUserInfo === "function") wrapped.getUserInfo = async (token: any) => {
      const info = await options.getUserInfo(token);
      if (info?.user?.emailVerified === true) await supersede(info.user.email, id);
      return info;
    };
    if (typeof options.mapProfileToUser === "function") wrapped.mapProfileToUser = async (profile: any) => {
      const mapped = await options.mapProfileToUser(profile);
      if (mapped?.emailVerified === true) await supersede(typeof mapped.email === "string" ? mapped.email : providerEmail(id, profile), id);
      return mapped;
    };
    out[id] = wrapped;
  }
  return out as T;
}

export { admissionMode };
