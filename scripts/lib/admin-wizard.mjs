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
  const databases = await api.databases();
  const database = databases.find(d => d.name === cfg.database.name);
  if (!database) throw Error("Nathan D1 database not found");
  const dbId = database.uuid || database.id;
  const rows = await api.queryDatabase(dbId,
    'SELECT "id", "email", "emailVerified", "role" FROM "user" WHERE lower("email") = lower(?) LIMIT 2',
    [email]
  );
  if (rows.length !== 1 || rows[0].emailVerified !== 1) {
    throw Error("The verified user was not found. Complete an upstream OAuth sign-in and email verification first.");
  }
  if (rows[0].role === "admin") {
    console.log("Verified admin already holds the role; no change.");
    return;
  }
  if (!(await yesNo("Promote this verified allowlisted user to Nathan admin?"))) throw Error("Cancelled");
  await api.queryDatabase(dbId,
    'UPDATE "user" SET "role" = ? WHERE "id" = ? AND "emailVerified" = 1',
    ["admin", rows[0].id]
  );
  const confirm = await api.queryDatabase(dbId,
    'SELECT "role" FROM "user" WHERE "id" = ? AND "emailVerified" = 1',
    [rows[0].id]
  );
  if (confirm.length !== 1 || confirm[0].role !== "admin") throw Error("Admin promotion verification failed");
  const claimed=await api.queryDatabase(dbId,
    "UPDATE nathan_bootstrap_status SET admin_user_id=?,state='identity_verified',updated_at=unixepoch() "+
    "WHERE id='primary' AND admin_email=? AND cloudflare_user_id=? "+
    "AND (admin_user_id IS NULL OR admin_user_id=?)",
    [rows[0].id,email,"cli:"+cfg.accountId,rows[0].id]);
  const boot=await api.queryDatabase(dbId,
    "SELECT admin_user_id FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1",[]);
  if(boot.length!==1 || boot[0].admin_user_id!==rows[0].id)
    throw Error("Bootstrap ownership binding failed; admin account requires manual security review");

  console.log("Promoted verified allowlisted administrator. Enroll MFA immediately.");
}
