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
function deploymentSeed(accountId, forgegraphSeed) {
  if (forgegraphSeed !== undefined && !/^forgegraph:[a-z0-9][a-z0-9-]{0,62}:[a-z0-9][a-z0-9-]{0,62}$/.test(forgegraphSeed))
    throw Error("Expected a ForgeGraph seed of the form forgegraph:<app>:<stage>");
  return forgegraphSeed ?? "cli:" + accountId;
}

// The database trigger validates ownership and applies the grant and audit as one SQL statement.
export async function promoteBootstrapOwner(api, dbId, accountId, email, userId, forgegraphSeed) {
  const seed = deploymentSeed(accountId, forgegraphSeed);
  await api.queryDatabase(dbId,
    "INSERT INTO nathan_operator_owner_claim(user_id, email, seed, audit_id) VALUES (?, ?, ?, ?)",
    [userId, email, seed, crypto.randomUUID()]);
}

export async function adminCommand(args, file, apply) {
  const cfg = await loadConfig(file);
  if (args[0] !== "promote") {
    console.log("Usage: node scripts/nathan.mjs admin promote [--seed forgegraph:<app>:<stage>] --apply");
    return;
  }
  if (!apply) throw Error("Admin role promotion requires explicit --apply");
  if (args.length !== 1 && !(args.length === 3 && args[1] === "--seed" && args[2]))
    throw Error("Usage: admin promote [--seed forgegraph:<app>:<stage>] --apply");
  const forgegraphSeed = args[2];
  if (!cfg.accountId) throw Error("accountId required");
  const seed = deploymentSeed(cfg.accountId, forgegraphSeed);
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
  if (!(await yesNo("Bind " + email + " as owner of " + cfg.database.name + " (" + seed + ")?"))) throw Error("Cancelled");
  await promoteBootstrapOwner(api, dbId, cfg.accountId, email, rows[0].id, forgegraphSeed);
  console.log("Verified administrator bound. Complete authenticator enrollment at /security.");
}
