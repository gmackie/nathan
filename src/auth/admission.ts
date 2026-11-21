/**
 * NATH-16: account admission in Identity Studio and in Better Auth.
 *
 * - Studio (GET/POST /studio/api/admission; administrator with completed enrollment and a fresh
 *   step-up, same-origin JSON, exact confirmation, every attempt audited): the installation's
 *   admission mode and invitations (create, list, revoke).
 * - Better Auth: admissionUserCreateGuard is the ONE databaseHooks.user.create.before guard. It runs
 *   the SAML connection guard (NATH-10) first, then the admission decision, for every Better Auth
 *   account creation. SCIM just-in-time creation does not go through Better Auth; it asks the same
 *   policy through admitJustInTime (src/auth/scim/lifecycle.ts).
 */
import { APIError } from "better-auth/api";
import type { AuthEnv } from "./env";
import { audit } from "./admin-service";
import { samlUserCreateGuard } from "./saml-policy.mjs";
import {
  ADMISSION_MODES, INVITATION_DAYS, NOT_ADMITTED, admissionMode, auditAdmission, creationMethod, decideAdmission, normalizeEmail
} from "./admission-policy.mjs";

const ID = /^[0-9a-f-]{36}$/;
type InvitationRow = { id: string; email: string; createdBy: string; createdAt: number; expiresAt: number; uses: number;
  usedAt: number | null; usedMethod: string | null; usedByUser: string | null; revokedAt: number | null; revokedBy: string | null; now: number };

function stateOf(row: InvitationRow) {
  if (row.uses === 1) return "used";
  if (row.revokedAt !== null) return "revoked";
  return row.expiresAt <= row.now ? "expired" : "pending";
}

/** Mode and the most recent invitations (no secrets: an invitation is bound to its email, not to a token). */
export async function admissionOverview(env: AuthEnv) {
  const [setting, invitations] = await Promise.all([
    env.DB.prepare("SELECT mode, updated_by AS updatedBy, updated_at AS updatedAt FROM nathan_admission_settings WHERE id='primary' LIMIT 1")
      .first<{ mode: string; updatedBy: string; updatedAt: number }>(),
    env.DB.prepare("SELECT id, email, created_by AS createdBy, created_at AS createdAt, expires_at AS expiresAt, uses, used_at AS usedAt, " +
      "used_method AS usedMethod, used_by_user AS usedByUser, revoked_at AS revokedAt, revoked_by AS revokedBy, unixepoch() AS now " +
      "FROM nathan_invitations ORDER BY created_at DESC, rowid DESC LIMIT 200").all<InvitationRow>()
  ]);
  return {
    mode: setting?.mode === "self-service" ? "self-service" : "invitation-only",
    updatedBy: setting?.updatedBy ?? null, updatedAt: setting?.updatedAt ?? null,
    invitations: invitations.results.map(({ now: _now, uses: _uses, ...row }) => ({ ...row, state: stateOf({ ...row, uses: _uses, now: _now }) })),
    note: "Admission decides only whether a new account may be created. It grants no application access and no administrator rights."
  };
}

/**
 * One Studio operation:
 *   { op: "mode", mode, confirm: "CONFIRM ADMISSION <mode>" }
 *   { op: "invite", email, days? }                      (1..30 days, default 7)
 *   { op: "revoke", id, confirm: "CONFIRM REVOKE INVITATION <id>" }
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
    const email = normalizeEmail(body.email);
    const days = body.days === undefined ? INVITATION_DAYS.default : Number(body.days);
    if (!email || !Number.isInteger(days) || days < 1 || days > INVITATION_DAYS.max) {
      await audit(env, actor, "invitation_create", "invalid", "rejected");
      throw Error("Invalid invitation: give an email address and 1 to " + INVITATION_DAYS.max + " days");
    }
    if (await env.DB.prepare('SELECT 1 AS found FROM "user" WHERE lower("email")=? LIMIT 1').bind(email).first()) {
      await audit(env, actor, "invitation_create", "existing-account", "rejected");
      throw Error("An account with this email address already exists; it needs no invitation");
    }
    const id = crypto.randomUUID();
    await env.DB.batch([
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
export const ADMISSION_ERRORS = /^(Invalid|Explicit|Unknown|An account)/;

function refuse(): never {
  // 422, not 403: Better Auth turns a 403 during password sign-up into its generic "check your
  // email" answer, which would hide the reason from the person signing up.
  throw new APIError("UNPROCESSABLE_ENTITY", { code: NOT_ADMITTED.code, message: NOT_ADMITTED.message });
}

/**
 * databaseHooks.user.create.before. Composes the SAML connection guard and the admission decision;
 * fails closed (no account) on any error. Returns the SAML guard's data changes, if any.
 */
export async function admissionUserCreateGuard(env: AuthEnv, user: any, ctx: any) {
  const saml = await samlUserCreateGuard(env.DB, user, ctx);
  if (saml === false) return false;
  const merged = { ...user, ...(saml && typeof saml === "object" ? saml.data : {}) };
  const method = creationMethod(ctx);
  let decision: { admitted: boolean; via: string | null };
  try {
    decision = await decideAdmission(env.DB, env, { email: merged.email, emailVerified: merged.emailVerified === true, method });
  } catch {
    return false;
  }
  if (!decision.admitted) {
    await auditAdmission(env.DB, method, "refused").catch(() => {});
    refuse();
  }
  await auditAdmission(env.DB, method, "admitted_" + decision.via!.replace("-", "_"));
  return saml ?? undefined;
}

/** databaseHooks.user.create.after: records which account an invitation admitted. */
export async function admissionUserCreated(env: AuthEnv, user: any) {
  const email = normalizeEmail(user?.email);
  if (!email || typeof user?.id !== "string") return;
  await env.DB.prepare("UPDATE nathan_invitations SET used_by_user=? WHERE email=? AND uses=1 AND used_by_user IS NULL").bind(user.id, email).run();
}

export { admissionMode };
