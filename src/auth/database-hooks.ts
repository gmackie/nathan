import { APIError } from "better-auth/api";
import type { AuthEnv } from "./env";
import { admissionUserCreateGuard, admissionUserCreated } from "./admission";
import { scimSessionGuard } from "./scim/session-guard";
import { claimInvitationStatement } from "./admission-policy.mjs";
import { emailTarget, emailSessionAllowed, type EmailFlow } from "./email-sign-in-policy";

const refuseEmail = () => new APIError("FORBIDDEN", { message: "Email sign-in unavailable" });

/** Better Auth calls the update hook once the mailbox is proven. Commit its unproven-access
 * cleanup, promotion, admission and audit together on D1. A later error rolls them all back. */
async function promoteEmailSubject(env: AuthEnv, flow: EmailFlow) {
  const subject = flow.subject_id;
  const current = await emailTarget(env.DB, flow.email);
  if (!subject || current?.subject_id !== subject || current.invitation_id !== flow.invitation_id) throw refuseEmail();

  const invited = flow.invitation_id !== null;
  const eligibility = invited
    ? "EXISTS(SELECT 1 FROM nathan_admission_pending p WHERE p.email=user.email AND (p.user_id=user.id OR p.user_id IS NULL)) " +
      "AND EXISTS(SELECT 1 FROM nathan_invitations i WHERE i.id=? AND i.email=user.email AND i.uses=0 AND i.revoked_at IS NULL AND i.expires_at>unixepoch())"
    : "EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=user.id AND link_state='linked' AND link_method='jit' AND active=1 AND deleted=0)";
  const verifySubject = env.DB.prepare('UPDATE "user" SET emailVerified=1' + (invited ? ",name='',image=NULL" : "") +
    " WHERE id=? AND email=? AND emailVerified=0 AND EXISTS(SELECT 1 FROM nathan_email_sign_ins WHERE id=? AND generation=? " +
    "AND subject_id=user.id AND email=user.email AND invitation_id IS ? AND expires_at>unixepoch()) AND " + eligibility)
    .bind(subject, flow.email, flow.id, flow.generation, flow.invitation_id, ...(invited ? [flow.invitation_id] : []));
  const statements = [
    verifySubject,
    // outcome is NOT NULL. If the gated UPDATE matched no row, D1 aborts the batch before any cleanup.
    env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) " +
      "VALUES (?,'system:admission',?,'email-otp',CASE WHEN changes()=1 THEN ? ELSE NULL END)")
      .bind(crypto.randomUUID(), invited ? "account_admission" : "email_address_verify", invited ? "admitted_invitation" : "verified"),
    env.DB.prepare("DELETE FROM account WHERE userId=?").bind(subject),
    env.DB.prepare('DELETE FROM "session" WHERE userId=?').bind(subject)
  ];
  if (flow.invitation_id) {
    const claim = claimInvitationStatement(flow.invitation_id, "email-otp", subject);
    statements.push(env.DB.prepare(claim.sql).bind(...claim.params),
      env.DB.prepare("DELETE FROM nathan_admission_pending WHERE email=?").bind(flow.email));
  }
  await env.DB.batch(statements);
}

export function nathanDatabaseHooks(env: AuthEnv, flow?: EmailFlow) {
  // Defer Better Auth's pre-verification deletes to the promotion transaction. Its TOTP
  // after-hook still deletes the temporary session it just created for this request.
  const deferCleanup = async (record: { userId?: string; id?: string }, ctx: any) => {
    if (!flow || ctx?.path !== "/sign-in/email-otp" || (flow.issuedSessionId && record.id === flow.issuedSessionId)) return;
    if (record.userId !== flow.subject_id) throw refuseEmail();
    return false as const;
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
    ...(flow ? { account: { delete: { before: deferCleanup } } } : {}),
    session: {
      ...(flow ? { delete: { before: deferCleanup } } : {}),
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
