import { loadConfig } from "./config.mjs";
import { CloudflareClient } from "./cloudflare.mjs";
import { ask, yesNo } from "./prompts.mjs";

export function validateAdminPromotion(email, cfg) {
  const candidate = String(email || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate)) throw Error("A valid email address is required");
  const allowed = new Set((cfg.adminEmails || []).map(e => String(e).trim().toLowerCase()));
  if (!allowed.has(candidate)) throw Error("Email is not in NATHAN_ADMIN_EMAILS; update and deploy the allowlist first");
  return candidate;
}
// The same identity and ownership predicates guard both writes and the final read.
export async function promoteBootstrapOwner(api, dbId, accountId, email, userId) {
  const params = [userId, email, "cli:" + accountId];
  const eligible = `SELECT u.id
    FROM "user" u JOIN nathan_bootstrap_status b ON b.id = 'primary'
    WHERE u.id = ? AND lower(u.email) = ? AND b.cloudflare_user_id = ?
      AND b.admin_email = lower(u.email) AND u.emailVerified = 1 AND coalesce(u.banned, 0) = 0
      AND (b.admin_user_id IS NULL OR b.admin_user_id = u.id)
      AND b.state IN ('pending', 'identity_verified', 'authenticators_enrolled', 'complete')
      AND (SELECT count(*) FROM "user" other WHERE lower(other.email) = lower(u.email)) = 1`;
  const bound = eligible + " AND b.admin_user_id = u.id AND b.state <> 'pending'";
  const statements = [
    {sql: `INSERT INTO nathan_security_audit (id,actor,action,target,outcome)
      SELECT ?, ?, 'admin_bootstrap', ?, 'succeeded'
      WHERE EXISTS (${eligible} AND (u.role IS NOT 'admin' OR b.admin_user_id IS NULL OR b.state = 'pending'))`,
      params: [crypto.randomUUID(), "cli:" + accountId, userId, ...params]},
    {sql: `UPDATE nathan_bootstrap_status SET admin_user_id = ?,
      state = CASE WHEN state = 'pending' THEN 'identity_verified' ELSE state END,
      updated_at = unixepoch()
      WHERE id = 'primary' AND (admin_user_id IS NULL OR state = 'pending') AND EXISTS (${eligible})`,
      params: [userId, ...params]},
    {sql: `UPDATE "user" SET role = 'admin' WHERE id IN (${bound}) AND role IS NOT 'admin'`, params},
    {sql: bound + " AND u.role = 'admin'", params}
  ];
  const results = await api.batchDatabase(dbId, statements);
  const verified = results.at(-1);
  if (verified.length !== 1 || verified[0].id !== userId) {
    throw Error("The verified account does not match the CLI installation's bootstrap owner");
  }
}

export async function adminCommand(args, file, apply) {
  const cfg = await loadConfig(file);
  if (args[0] !== "promote") {
    console.log("Usage: node scripts/nathan.mjs admin promote --apply\nPromotes an existing verified allowlisted user via a privileged Cloudflare D1 operation.");
    return;
  }
  if (!apply) throw Error("Admin role promotion requires explicit --apply");
  if (!cfg.accountId) throw Error("accountId required");
  const email = validateAdminPromotion(await ask("Verified administrator email"), cfg);
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, cfg.accountId);
  const database = await api.databaseNamed(cfg.database.name);
  if (!database) throw Error("Nathan D1 database not found");
  const dbId = database.uuid || database.id;
  const rows = await api.queryDatabase(dbId,
    'SELECT "id", "email", "emailVerified", "role" FROM "user" WHERE lower("email") = lower(?) LIMIT 2',
    [email]
  );
  if (rows.length !== 1 || rows[0].emailVerified !== 1) {
    throw Error("The verified user was not found. Complete an upstream OAuth sign-in and email verification first.");
  }
  if (!(await yesNo("Bind this verified allowlisted user as the installation administrator?", false))) throw Error("Cancelled");
  await promoteBootstrapOwner(api, dbId, cfg.accountId, email, rows[0].id);
  console.log("Verified administrator bound. Complete authenticator enrollment at /security.");
}
