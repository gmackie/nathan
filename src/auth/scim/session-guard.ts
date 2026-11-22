/**
 * NATH-19: a directory-deprovisioned user never gets a session back because a ban lapsed.
 *
 * Nathan's SCIM ban is permanent. An administrator can replace it with their own ban. If that ban
 * expires, Better Auth's admin plugin lifts the expired ban at the user's next sign-in (its
 * session.create.before hook, which runs before Nathan's). Before NATH-19 the user could then sign in
 * until a manual resync, although the directory still says they left.
 *
 * This databaseHooks.session.create.before guard runs for every new session (any sign-in method,
 * after Better Auth's ban check). When the user's SCIM link is deprovisioned and no administrator
 * overrode the deprovisioning (override_cause, recorded by keep active or by lifting Nathan's own
 * SCIM ban), it refuses the session. In the same D1 batch it puts Nathan's SCIM ban back, marks the
 * ban as Nathan's again, deletes any session and audits it. The change feed records the ban (the 0011
 * trigger). Any error refuses the session (fail closed).
 */
import { APIError } from "better-auth/api";
import type { AuthEnv } from "../env";
import { scimBanReason } from "./lifecycle.ts";

export const DEPROVISIONED = Object.freeze({
  code: "ACCOUNT_DEPROVISIONED",
  message: "Your organization's directory has deactivated this account, so Nathan does not sign it in. Contact your administrator."
});

function refuse(): never {
  throw new APIError("FORBIDDEN", { code: DEPROVISIONED.code, message: DEPROVISIONED.message });
}

export async function scimSessionGuard(env: AuthEnv, session: { userId?: unknown } | null | undefined): Promise<void> {
  const userId = session?.userId;
  if (typeof userId !== "string" || !userId) return;
  let link: { connection: string; scimId: string } | null;
  try {
    link = await env.DB.prepare(
      "SELECT connection_id AS connection, scim_id AS scimId FROM nathan_scim_users " +
      "WHERE user_id=? AND link_state='deprovisioned' AND override_cause IS NULL LIMIT 1"
    ).bind(userId).first<{ connection: string; scimId: string }>();
  } catch {
    refuse();
  }
  if (!link) return;
  const reason = scimBanReason(link.connection), now = new Date().toISOString();
  try {
    await env.DB.batch([
      // Never weakens a permanent ban another administrator wrote.
      env.DB.prepare('UPDATE "user" SET "banned"=1, "banReason"=?, "banExpires"=NULL, "updatedAt"=? WHERE "id"=? ' +
        'AND NOT (ifnull("banned",0) IN (1,\'1\') AND "banExpires" IS NULL)').bind(reason, now, userId),
      env.DB.prepare("UPDATE nathan_scim_users SET scim_banned=1, updated_at=unixepoch() WHERE connection_id=? AND scim_id=? AND user_id=? " +
        "AND link_state='deprovisioned' AND override_cause IS NULL AND EXISTS (SELECT 1 FROM \"user\" WHERE \"id\"=? AND \"banReason\"=?)")
        .bind(link.connection, link.scimId, userId, userId, reason),
      env.DB.prepare('DELETE FROM "session" WHERE "userId"=?').bind(userId),
      env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,'scim_ban_lapse_reapplied',?,'succeeded')")
        .bind(crypto.randomUUID(), "scim:" + link.connection, link.connection + ":" + userId)
    ]);
  } catch {
    // The session is refused either way; the next attempt (or resync) restores the ban.
  }
  refuse();
}
