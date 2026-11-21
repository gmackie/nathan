/**
 * Nathan's Better Auth databaseHooks, in one place so every rule composes:
 * - user.create.before: the SAML connection guard (NATH-10) and account admission (NATH-16);
 * - user.create.after: records which account an invitation admitted (NATH-16).
 * Better Auth runs plugin hooks (for example the admin plugin's ban check) before these.
 */
import type { AuthEnv } from "./env";
import { admissionUserCreateGuard, admissionUserCreated } from "./admission";

export function nathanDatabaseHooks(env: AuthEnv) {
  return {
    user: {
      create: {
        before: (user: any, ctx: any) => admissionUserCreateGuard(env, user, ctx),
        after: (user: any) => admissionUserCreated(env, user)
      }
    }
  };
}
