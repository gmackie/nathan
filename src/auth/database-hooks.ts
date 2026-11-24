import { APIError } from "better-auth/api";
import type { AuthEnv } from "./env";
import { admissionUserCreateGuard, admissionUserCreated } from "./admission";
import { scimSessionGuard } from "./scim/session-guard";
import { claimInvitationStatement } from "./admission-policy.mjs";
import { emailTarget, emailSessionAllowed, type EmailFlow } from "./email-sign-in-policy";

const refuseEmail = () => new APIError("FORBIDDEN", { message: "Email sign-in unavailable" });

/** Better Auth has verified the OTP and removed unproven account links/sessions. Pin the
 * promotion to the account that received the mail. A provisional signup consumes its exact
 * invitation and becomes verified in one batch, so a failed write can be retried. */
async function promoteEmailSubject(env: AuthEnv, flow: EmailFlow) {
  const subject = flow.subject_id;
  const current = await emailTarget(env.DB, flow.email);
  if (!subject || current?.subject_id !== subject || current.invitation_id !== flow.invitation_id) throw refuseEmail();
  const live = "EXISTS(SELECT 1 FROM nathan_email_sign_ins WHERE id=? AND generation=? AND subject_id=? " +
    "AND email=? AND invitation_id IS ? AND expires_at>unixepoch())";
  const pin = [flow.id, flow.generation, subject, flow.email, flow.invitation_id];
  if (!flow.invitation_id) {
    const changed = await env.DB.prepare('UPDATE "user" SET emailVerified=1 WHERE id=? AND email=? AND emailVerified=0 AND ' + live +
      " AND EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=? AND link_state='linked' AND link_method='jit' AND active=1 AND deleted=0)")
      .bind(subject, flow.email, ...pin, subject).run();
    if (!changed.meta.changes) throw refuseEmail();
    return;
  }
  const claim = claimInvitationStatement(flow.invitation_id, "email-otp", subject);
  const promoted = 'SELECT 1 FROM nathan_invitations WHERE id=? AND email=? AND used_by_user=? AND uses=1 AND ' + live;
  const params = [flow.invitation_id, flow.email, subject, ...pin];
  const [, changed] = await env.DB.batch([
    env.DB.prepare(claim.sql + ' AND email=? AND EXISTS(SELECT 1 FROM "user" u JOIN nathan_admission_pending p ON p.email=u.email ' +
      'WHERE u.id=? AND u.email=? AND u.emailVerified=0 AND (p.user_id=u.id OR p.user_id IS NULL)) AND ' + live)
      .bind(...claim.params, flow.email, subject, flow.email, ...pin),
    env.DB.prepare('UPDATE "user" SET emailVerified=1,name=\'\',image=NULL WHERE id=? AND email=? AND EXISTS(' + promoted + ')').bind(subject, flow.email, ...params),
    env.DB.prepare("DELETE FROM nathan_admission_pending WHERE email=? AND EXISTS(" + promoted + ")").bind(flow.email, ...params),
    env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) " +
      "SELECT ?,'system:admission','account_admission','email-otp','admitted_invitation' WHERE EXISTS(" + promoted + ")")
      .bind(crypto.randomUUID(), ...params)
  ]);
  if (!changed.meta.changes) throw refuseEmail();
}

export function nathanDatabaseHooks(env: AuthEnv, flow?: EmailFlow) {
  // Better Auth's emailOTP promotion removes unproven credentials. Refuse an operation
  // touching a replacement subject, including deletion before the verified flag is written.
  const guardDeletion = async (record: { userId?: string }, ctx: any) => {
    if (!flow || ctx?.path !== "/sign-in/email-otp") return;
    if (record.userId !== flow.subject_id || !await env.DB.prepare(
      "SELECT 1 FROM nathan_email_sign_ins WHERE id=? AND generation=? AND subject_id=? AND expires_at>unixepoch()"
    ).bind(flow.id, flow.generation, record.userId).first()) throw refuseEmail();
  };
  return {
    user: {
      create: {
        before: async (user: any, ctx: any) => {
          const invitation = flow?.invitation_id ?? null;
          const guard = await admissionUserCreateGuard(env, user, ctx, invitation);
          if (guard === false || ctx?.path !== "/sign-in/email-otp") return guard;
          if (!flow || !invitation || flow.subject_id !== null) throw refuseEmail();
          return { data: { ...guard?.data, id: "n-email-" + flow.generation } };
        },
        after: (user: any) => admissionUserCreated(env, user)
      },
      update: { before: async (update: any, ctx: any) => {
        if (flow && ctx?.path === "/sign-in/email-otp" && update.emailVerified) await promoteEmailSubject(env, flow);
      } }
    },
    ...(flow ? { account: { delete: { before: guardDeletion } } } : {}),
    session: {
      ...(flow ? { delete: { before: guardDeletion } } : {}),
      create: {
        before: async (session: any) => {
          await scimSessionGuard(env, session);
          if (flow && !await emailSessionAllowed(env, flow, session.userId)) throw refuseEmail();
        },
        after: async (session: any) => {
          if (!flow) return;
          try {
            await env.DB.prepare("INSERT INTO nathan_email_otp_sessions(session_id,user_id,hosted) VALUES (?,?,1)").bind(session.id, session.userId).run();
            flow.issuedSessionId = session.id;
          } catch (error) {
            await env.DB.prepare('DELETE FROM "session" WHERE id=?').bind(session.id).run();
            throw error;
          }
        }
      }
    }
  };
}
