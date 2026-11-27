import { APIError } from "better-auth/api";
import { sha256 } from "../gateway/crypto";
import { userBanned } from "../shared/token-claims.mjs";
import { openConfigSecret, sealConfigSecret } from "./config-crypto.mjs";
import { sendAuthEmail } from "./email";
import { managementEmail, ownerInvitation, type AuthEnv } from "./env";

const purpose = "owner-mailbox:v1:verification";
const unavailable = () => new APIError("FORBIDDEN", { message: "Request a fresh administrator verification email." });
type OwnerUser = { id: string; email: string };

/** Better Auth signs the email address. The installer also requires the particular provisional
 * subject and invitation, so sending a new invitation cannot revive an earlier verification URL. */
export async function sendOwnerVerification(env: AuthEnv, user: OwnerUser, url: string) {
  const link = new URL(url), token = link.searchParams.get("token");
  if (!token || !env[ownerInvitation] || user.email !== env[managementEmail]) throw unavailable();
  const witness = JSON.stringify([user.id, env[ownerInvitation], await sha256(token)]);
  link.searchParams.set("owner", await sealConfigSecret(purpose, witness, env.NATHAN_CONFIG_KEY));
  await sendAuthEmail(env, user.email, "Verify your Nathan administrator email", link.href);
}

export async function verifyOwnerMailbox(env: AuthEnv, user: OwnerUser, request?: Request) {
  if (!request || user.email !== env[managementEmail]) throw unavailable();
  const params = new URL(request.url).searchParams;
  const token = params.get("token"), witness = params.get("owner");
  if (!token || !witness) throw unavailable();
  let invitation: string;
  try {
    const data = JSON.parse(await openConfigSecret(purpose, witness, env.NATHAN_CONFIG_KEY));
    if (!Array.isArray(data) || data.length !== 3 || data[0] !== user.id ||
        typeof data[1] !== "string" || data[2] !== await sha256(token)) throw unavailable();
    invitation = data[1];
  } catch { throw unavailable(); }

  const ban = await env.DB.prepare('SELECT banned,banExpires FROM "user" WHERE id=? AND email=?')
    .bind(user.id, user.email).first<{ banned: number | null; banExpires: string | number | null }>();
  if (!ban || userBanned(ban)) throw unavailable();
  try {
    // The sole expiry decision is in the first write. A failed guard or downstream write
    // rolls back the user, invitation, pending record and audit as a single D1 transaction.
    await env.DB.batch([
      env.DB.prepare("UPDATE nathan_invitations SET uses=1,used_at=unixepoch(),used_method='password',used_by_user=?1 " +
        "WHERE id=?2 AND email=?3 AND uses=0 AND revoked_at IS NULL AND expires_at>unixepoch() AND EXISTS(" +
        'SELECT 1 FROM "user" u JOIN nathan_admission_pending p ON p.user_id=u.id AND p.email=u.email ' +
        "JOIN nathan_bootstrap_status b ON b.admin_email=u.email WHERE u.id=?1 AND u.email=?3 AND u.emailVerified=0 " +
        "AND u.banned IS ?4 AND u.banExpires IS ?5 AND NOT EXISTS(SELECT 1 FROM nathan_scim_users d WHERE d.user_id=u.id " +
        "AND d.link_state='deprovisioned' AND d.override_cause IS NULL) " +
        "AND p.method='password' AND b.id='primary' AND b.state='pending' AND b.admin_user_id IS NULL)")
        .bind(user.id, invitation, user.email, ban.banned, ban.banExpires),
      env.DB.prepare('UPDATE "user" SET emailVerified=1,updatedAt=? WHERE id=? AND emailVerified=0 AND changes()=1')
        .bind(new Date().toISOString(), user.id),
      env.DB.prepare("DELETE FROM nathan_admission_pending WHERE user_id=? AND email=? AND changes()=1").bind(user.id, user.email),
      // outcome is NOT NULL. If any guarded write missed, abort the entire claim.
      env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES " +
        "(?,'system:admission','account_admission','password',CASE WHEN changes()=1 THEN 'admitted_invitation' ELSE NULL END)")
        .bind(crypto.randomUUID())
    ]);
  } catch {
    // A concurrent verification may have won. Accept only proof of that exact committed claim.
    const committed = await env.DB.prepare('SELECT u.banned,u.banExpires FROM "user" u JOIN nathan_invitations i ON i.used_by_user=u.id AND i.email=u.email ' +
      "WHERE u.id=? AND u.email=? AND u.emailVerified=1 AND i.id=? AND i.uses=1 AND i.used_method='password' " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_scim_users d WHERE d.user_id=u.id AND d.link_state='deprovisioned' AND d.override_cause IS NULL) " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_admission_pending p WHERE p.email=u.email)").bind(user.id, user.email, invitation).first();
    if (userBanned(committed)) throw unavailable();
  }
}
