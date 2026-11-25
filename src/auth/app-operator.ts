import { normalizeEmail } from "./admission-policy.mjs";
import type { AuthEnv } from "./env";

/** An operator may have been promoted after their customer session was issued. Check the
 * current roster at admission, authorization, token exchange and app access decisions. */
export async function isOperatorAddress(env: AuthEnv, email: string) {
  if ((env.NATHAN_ADMIN_EMAILS || "").split(",").some(address => normalizeEmail(address) === email)) return true;
  return Boolean(await env.DB.prepare(
    'SELECT 1 FROM "user" u WHERE u.email=? COLLATE NOCASE AND (u.role=\'admin\' OR ' +
    'EXISTS(SELECT 1 FROM nathan_admin_grants WHERE enabled=1 AND user_id=u.id) OR ' +
    'EXISTS(SELECT 1 FROM nathan_bootstrap_status WHERE admin_user_id=u.id)) ' +
    'UNION ALL SELECT 1 FROM nathan_bootstrap_status WHERE admin_email=? COLLATE NOCASE ' +
    'UNION ALL SELECT 1 FROM nathan_admin_grants WHERE enabled=1 AND email=? COLLATE NOCASE LIMIT 1'
  ).bind(email,email,email).first());
}

export async function allowedCustomerSubject(env: AuthEnv, subject: string) {
  const row = await env.DB.prepare('SELECT email FROM "user" WHERE id=?').bind(subject).first<{email:string}>();
  const email = normalizeEmail(row?.email);
  return Boolean(email && !await isOperatorAddress(env,email));
}
