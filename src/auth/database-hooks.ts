/**
 * Nathan's Better Auth databaseHooks, in one place so every rule composes:
 * - user.create.before: the SAML connection guard (NATH-10) and account admission (NATH-16);
 * - user.create.after: records which account an invitation admitted (NATH-16);
 * - user.update.before: an email-code sign-in that verifies an existing unverified account runs
 *   admission first, as the verification link does (NATH-49);
 * - session.create.before: no session for a SCIM-deprovisioned user whose ban lapsed (NATH-19), and
 *   no email-code session for an account that may not sign in by code (NATH-49).
 * Better Auth runs plugin hooks (for example the admin plugin's ban check) before these.
 */
import type { AuthEnv } from "./env";
import { admissionUserCreateGuard, admissionUserCreated } from "./admission";
import { scimSessionGuard } from "./scim/session-guard";
import { emailOtpPromotionGuard, emailOtpUserCreateGuard, emailOtpSessionGuard } from "./email-otp";

export function nathanDatabaseHooks(env: AuthEnv) {
  return {
    user: {
      create: {
        before: async (user: any, ctx: any) => {
          // NATH-49: no account by email code inside a verified enterprise SSO domain.
          await emailOtpUserCreateGuard(env, user, ctx);
          return admissionUserCreateGuard(env, user, ctx);
        },
        after: (user: any) => admissionUserCreated(env, user)
      },
      update: {
        before: (data: any, ctx: any) => emailOtpPromotionGuard(env, data, ctx)
      }
    },
    session: {
      create: {
        before: async (session: any, ctx: any) => {
          await scimSessionGuard(env, session);
          // NATH-49: no email-code session for accounts that have something stronger.
          await emailOtpSessionGuard(env, session, ctx);
        }
      }
    }
  };
}
