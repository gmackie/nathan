import { userBanned } from "../shared/token-claims.mjs";
import { openInvitation } from "./admission-policy.mjs";
import type { AuthEnv } from "./env";

export const EMAIL_TTL = 300;
export const EMAIL_ATTEMPTS = 5;
type EmailTarget = { subject_id: string | null; invitation_id: string | null };
export type EmailFlow = EmailTarget & {
  id: string; generation: string; email: string; oauth_query: string | null; second_factor: string | null;
};

/** A verified account, an active SCIM-provisioned account, or this particular open invitation.
 * An arbitrary unverified password signup and an unknown address in self-service mode cannot use
 * this method. A provisional invitee may prove the mailbox while their original invite is open. */
export async function emailTarget(db: D1Database, email: string): Promise<EmailTarget | null> {
  const user = await db.prepare(
    'SELECT u.id,u.emailVerified,u.banned,u.banExpires, ' +
    "EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=u.id AND link_state='deprovisioned' AND override_cause IS NULL) AS deprovisioned, " +
    "EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=u.id AND link_state='linked' AND active=1 AND deleted=0 AND link_method='jit') AS provisioned, " +
    "EXISTS(SELECT 1 FROM nathan_admission_pending WHERE email=u.email AND (user_id=u.id OR user_id IS NULL)) AS provisional, " +
    'EXISTS(SELECT 1 FROM passkey WHERE userId=u.id) OR EXISTS(SELECT 1 FROM twoFactor WHERE userId=u.id) AS hasFactors ' +
    'FROM "user" u WHERE u.email=?'
  ).bind(email).first<{ id: string; emailVerified: number; banned: number; banExpires: string | null;
    deprovisioned: number; provisioned: number; provisional: number; hasFactors: number }>();
  if (user) {
    if (userBanned(user) || user.deprovisioned) return null;
    if (user.emailVerified) return { invitation_id: null, subject_id: user.id };
    if (user.hasFactors) return null;
    if (user.provisioned) return { invitation_id: null, subject_id: user.id };
    if (!user.provisional) return null;
  }
  const invitation = await openInvitation(db, email);
  return invitation ? { invitation_id: invitation.id, subject_id: user?.id ?? null } : null;
}

/** Run inside the session.create hook, after mailbox proof and admission. This also binds a
 * session completed by TOTP to the account that proved the email in the first place. */
export async function emailSessionAllowed(env: AuthEnv, flow: EmailFlow, userId: string) {
  const user = await env.DB.prepare('SELECT email FROM "user" WHERE id=? AND emailVerified=1').bind(userId).first<{email: string}>();
  if (user?.email !== flow.email) return false;
  if (flow.subject_id && flow.subject_id !== userId) return false;
  if (!flow.invitation_id) return flow.subject_id === userId;
  return Boolean(await env.DB.prepare("SELECT 1 FROM nathan_invitations WHERE id=? AND uses=1 AND used_by_user=? AND email=?")
    .bind(flow.invitation_id, userId, flow.email).first());
}

export async function isEmailSession(db: D1Database, sessionId: string | undefined) {
  return Boolean(sessionId && await db.prepare("SELECT 1 FROM nathan_email_sessions WHERE session_id=?").bind(sessionId).first());
}
