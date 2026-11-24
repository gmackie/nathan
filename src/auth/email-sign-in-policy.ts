import { liveSession, userBanned } from "../shared/token-claims.mjs";
import { openInvitation } from "./admission-policy.mjs";
import { inVerifiedSsoDomain } from "./email-otp-policy.mjs";
import type { AuthEnv } from "./env";

export const EMAIL_TTL = 300;
export const EMAIL_ATTEMPTS = 5;
type EmailTarget = { subject_id: string | null; invitation_id: string | null };
export type EmailFlow = EmailTarget & {
  id: string; generation: string; email: string; oauth_query: string | null; second_factor: string | null;
  issuedSessionId?: string;
};

export type EmailDelivery = { sequence: number; expires_at: number };

/** Allocate the order at request time, before account lookup or provider delivery. */
export async function reserveEmailDelivery(db: D1Database, flow: EmailFlow) {
  const [order] = await db.batch([
    db.prepare("INSERT INTO nathan_email_delivery_order(email,requested,expires_at) VALUES (?,1,unixepoch()+?) " +
      "ON CONFLICT(email) DO UPDATE SET requested=requested+1,expires_at=excluded.expires_at RETURNING requested AS sequence,expires_at")
      .bind(flow.email, EMAIL_TTL),
    // An initial request has a neutral challenge during mailbox eligibility checks and delivery.
    // A pending resend leaves the previously delivered challenge usable until publication.
    db.prepare("INSERT INTO nathan_email_sign_ins(id,generation,email,oauth_query,expires_at) " +
      "SELECT ?,?,email,?,expires_at FROM nathan_email_delivery_order WHERE email=? ON CONFLICT(email) DO NOTHING")
      .bind(flow.id, flow.generation, flow.oauth_query, flow.email)
  ]);
  const delivery = order.results[0] as EmailDelivery | undefined;
  if (!delivery) throw Error("Could not reserve email delivery");
  return delivery;
}

/** Publish only an accepted delivery. The same transaction prevents an older acceptance
 * from overwriting a newer generation or reopening its already consumed challenge. */
export async function publishEmailDelivery(db: D1Database, flow: EmailFlow, delivery: EmailDelivery) {
  await db.batch([
    db.prepare("UPDATE nathan_email_delivery_order SET delivered=?1,delivered_generation=?4 " +
      "WHERE email=?2 AND delivered<?1 AND requested>=?1 AND ?3>unixepoch()")
      .bind(delivery.sequence, flow.email, delivery.expires_at, flow.generation),
    db.prepare("INSERT INTO nathan_email_sign_ins(id,generation,subject_id,email,invitation_id,oauth_query,expires_at) " +
      "SELECT ?,?,?,?,?,?,? WHERE changes()=1 ON CONFLICT(email) DO UPDATE SET id=excluded.id,generation=excluded.generation," +
      "subject_id=excluded.subject_id,invitation_id=excluded.invitation_id,oauth_query=excluded.oauth_query," +
      "expires_at=excluded.expires_at,attempts=0,second_factor=NULL")
      .bind(flow.id, flow.generation, flow.subject_id, flow.email, flow.invitation_id, flow.oauth_query, delivery.expires_at)
  ]);
}

/** A verified account, an active SCIM-provisioned account, or this particular open invitation.
 * An arbitrary unverified password signup and an unknown address in self-service mode cannot use
 * this method. A provisional invitee may prove the mailbox while their original invite is open. */
export async function emailTarget(db: D1Database, email: string): Promise<EmailTarget | null> {
  if (await inVerifiedSsoDomain(db, email)) return null;
  const matches = await db.prepare(
    'SELECT u.id,u.email,u.emailVerified,u.banned,u.banExpires,u.twoFactorEnabled, ' +
    'EXISTS(SELECT 1 FROM account a JOIN ssoProvider p ON p.providerId=a.providerId WHERE a.userId=u.id) AS enterprise, ' +
    'EXISTS(SELECT 1 FROM twoFactor WHERE userId=u.id AND COALESCE(verified,1)=1) AS enrolledTotp, ' +
    "EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=u.id AND link_state='deprovisioned' AND override_cause IS NULL) AS deprovisioned, " +
    "EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=u.id AND link_state='linked' AND active=1 AND deleted=0 AND link_method='jit') AS provisioned, " +
    "EXISTS(SELECT 1 FROM nathan_admission_pending WHERE email=u.email AND (user_id=u.id OR user_id IS NULL)) AS provisional, " +
    'EXISTS(SELECT 1 FROM passkey WHERE userId=u.id) OR EXISTS(SELECT 1 FROM twoFactor WHERE userId=u.id) AS hasFactors ' +
    'FROM "user" u WHERE u.email=? COLLATE NOCASE LIMIT 2'
  ).bind(email).all<{ id: string; email: string; emailVerified: number; banned: number; banExpires: string | null;
    deprovisioned: number; provisioned: number; provisional: number; hasFactors: number;
    enterprise: number; enrolledTotp: number; twoFactorEnabled: number | null }>();
  const [user] = matches.results;
  // Better Auth looks up normalized addresses exactly. Never create a second subject for an imported address.
  if (matches.results.length > 1 || (user && user.email !== email)) return null;
  if (user) {
    if (userBanned(user) || user.deprovisioned || user.enterprise) return null;
    // Better Auth starts its challenge from the user flag. An inconsistent enrollment
    // must never turn a verified authenticator into an email-only sign-in.
    if (Boolean(user.enrolledTotp) !== Boolean(user.twoFactorEnabled)) return null;
    if (user.emailVerified || user.provisioned) return { invitation_id: null, subject_id: user.id };
    if (user.hasFactors) return null;
    if (!user.provisional) return null;
  }
  const invitation = await openInvitation(db, email);
  return invitation ? { invitation_id: invitation.id, subject_id: user?.id ?? null } : null;
}

/** Run inside the session.create hook, after mailbox proof and admission. This also binds a
 * session completed by TOTP to the account that proved the email in the first place. */
export async function emailSessionAllowed(env: AuthEnv, flow: EmailFlow, userId: string) {
  const current = await emailTarget(env.DB, flow.email);
  if (current?.subject_id !== userId || current.invitation_id) return false;
  const active = await env.DB.prepare('SELECT 1 FROM nathan_email_sign_ins f JOIN "user" u ON u.email=f.email ' +
    'WHERE f.id=? AND f.generation=? AND f.expires_at>unixepoch() AND u.id=? AND u.emailVerified=1')
    .bind(flow.id, flow.generation, userId).first();
  if (!active) return false;
  if (flow.subject_id && flow.subject_id !== userId) return false;
  if (!flow.invitation_id) return flow.subject_id === userId;
  return Boolean(await env.DB.prepare("SELECT 1 FROM nathan_invitations WHERE id=? AND uses=1 AND used_by_user=? AND email=?")
    .bind(flow.invitation_id, userId, flow.email).first());
}

export async function isEmailSession(db: D1Database, sessionId: string | undefined) {
  return Boolean(sessionId && await db.prepare("SELECT 1 FROM nathan_email_otp_sessions WHERE session_id=?").bind(sessionId).first());
}

/** A signed admin token must still reference its original live, non-email session. */
export async function liveAdminSession(db: D1Database, userId: string, sessionId?: string) {
  if (!sessionId || sessionId.length > 256) return false;
  const row = await db.prepare('SELECT s.id,s.userId,s.expiresAt FROM "session" s WHERE s.id=? AND s.userId=? ' +
    'AND NOT EXISTS(SELECT 1 FROM nathan_email_otp_sessions e WHERE e.session_id=s.id)').bind(sessionId, userId).first();
  return liveSession(row, { userId, sessionId });
}
