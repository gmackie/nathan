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
export async function initializeBootstrapOwner(api, dbId, accountId, email) {
  const actor = "cli:" + accountId;
  await api.queryDatabase(dbId,
    "INSERT OR IGNORE INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')",
    [actor, email]);
  const [owner] = await api.queryDatabase(dbId,
    "SELECT cloudflare_user_id,admin_email FROM nathan_bootstrap_status WHERE id='primary'");
  if (owner?.cloudflare_user_id !== actor || owner.admin_email !== email)
    throw Error("Admin bootstrap ownership mismatch");
}

export async function promoteBootstrapOwner(api, dbId, accountId, email, userId) {
  await api.queryDatabase(dbId, "INSERT INTO nathan_cli_owner_claim(actor,email,user_id) VALUES (?,?,?)",
    ["cli:" + accountId, email, userId]);
}

export async function adminCommand(args, file, apply) {
  const operation = args[0];
  if (operation !== "init" && operation !== "promote") {
    console.log("Usage: admin init|promote [--apply]");
    return;
  }
  const cfg = await loadConfig(file);
  if (!cfg.accountId) throw Error("accountId required");
  if (!apply) {
    console.log(operation === "init"
      ? "Reserve the first allowed administrator in " + cfg.database.name + " (" + cfg.hostname + "). Use --apply to initialize."
      : "Bind a verified, allowlisted user in " + cfg.database.name + " (" + cfg.hostname + "). Use --apply to promote.");
    return;
  }
  const email = validateAdminPromotion(operation === "init" ? cfg.adminEmails?.[0] : await ask("Verified administrator email"), cfg);
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, cfg.accountId);
  const database = await api.databaseNamed(cfg.database.name);
  if (!database) throw Error("Nathan D1 database not found");
  const dbId = database.uuid || database.id;
  if (operation === "init") {
    if (!await yesNo("Reserve " + email + " as the first administrator for " + cfg.hostname + " in " + cfg.database.name + "?"))
      throw Error("Cancelled");
    await initializeBootstrapOwner(api, dbId, cfg.accountId, email);
    console.log("Owner reserved. Sign in on your Worker with the verified email, then run admin promote.");
    return;
  }
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
