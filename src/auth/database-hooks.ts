import { APIError } from "better-auth/api";
import type { AuthEnv } from "./env";
import { admissionUserCreateGuard, admissionUserCreated } from "./admission";
import { scimSessionGuard } from "./scim/session-guard";
import { claimInvitationStatement } from "./admission-policy.mjs";
import { emailSessionAllowed, type EmailFlow } from "./email-sign-in-policy";

const refuseEmail = () => new APIError("FORBIDDEN", { message: "Email sign-in unavailable" });

/** Better Auth has verified the OTP and removed unproven account links/sessions. Pin the
 * promotion to the account that received the mail. A provisional signup consumes its exact
 * invitation and becomes verified in one batch, so a failed write can be retried. */
async function promoteEmailSubject(env: AuthEnv, flow: EmailFlow) {
  const subject = flow.subject_id;
  const user = await env.DB.prepare('SELECT id FROM "user" WHERE id=? AND email=? AND emailVerified=0')
    .bind(subject, flow.email).first();
  if (!subject || !user) throw refuseEmail();
  if (!flow.invitation_id) return;
  const claim = claimInvitationStatement(flow.invitation_id, "email-otp", subject);
  const promoted = 'SELECT 1 FROM nathan_invitations WHERE id=? AND email=? AND used_by_user=? AND uses=1';
  const params = [flow.invitation_id, flow.email, subject];
  const [, changed] = await env.DB.batch([
    env.DB.prepare(claim.sql + ' AND email=? AND EXISTS(SELECT 1 FROM "user" u JOIN nathan_admission_pending p ON p.email=u.email ' +
      'WHERE u.id=? AND u.email=? AND u.emailVerified=0 AND (p.user_id=u.id OR p.user_id IS NULL))')
      .bind(...claim.params, flow.email, subject, flow.email),
    env.DB.prepare('UPDATE "user" SET emailVerified=1 WHERE id=? AND email=? AND EXISTS(' + promoted + ')').bind(subject, flow.email, ...params),
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
    if (flow && ctx?.path === "/sign-in/email-otp" && record.userId !== flow.subject_id) throw refuseEmail();
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
          if (flow) await env.DB.prepare("INSERT INTO nathan_email_sessions(session_id) VALUES (?)").bind(session.id).run();
        }
      }
    }
  };
}
