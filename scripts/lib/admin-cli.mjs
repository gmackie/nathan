/**
 * Account-token administration: the Identity Studio writes an operator holding a Cloudflare API
 * token (D1 edit on the Nathan account) can make from the CLI without a Studio session.
 *
 *   nathan app enable|disable <app> [--apply]
 *   nathan rbac grant|revoke <app> <role> --user <user id or email> | --group <group> [--apply]
 *   nathan mcp register <identifier> --app <app> --name <name> [--scopes <json|@file>] [--full <scope>] [--aliases <json|@file>] [--apply]
 *   nathan mcp status <identifier> --enable|--disable [--apply]
 *   nathan user find --email <email>
 *
 * Trade-off (docs/security.md): a holder of such a token can already write these D1 tables
 * directly, bypassing the Studio administrator's passkey step-up. These commands do not add that
 * power; they make the path validated and audited. Every write runs the very validation and
 * statements of the Studio path (src/shared/admin-ops.mjs), is planned by default, needs --apply
 * and an interactive confirmation, and is audited as `cli:<accountId>`: an "attempted" row before
 * the change, then Studio's own "succeeded" row in the same D1 batch as the change, or "failed".
 * No secret is accepted as a flag; the token comes from CLOUDFLARE_API_TOKEN.
 */
import { readFile } from "node:fs/promises";
import { loadConfig } from "./config.mjs";
import { CloudflareClient } from "./cloudflare.mjs";
import { ask, yesNo } from "./prompts.mjs";
import { auditStatement } from "../../src/shared/rbac-store.mjs";
import { isRoleKey } from "../../src/shared/policy.mjs";
import {
  planAppStatus, appStatusConfirmation, planGrantCreate, planGrantRevoke, planMcpRegister, planMcpStatus, mcpStatusConfirmation,
  committedStatements, rbacAuditAction, rbacAttemptTarget, requireApp, userByEmail, userById, requireGroup
} from "../../src/shared/admin-ops.mjs";

/** @typedef {{ queryDatabase(id: string, sql: string, params?: unknown[]): Promise<any[]>, batchDatabase(id: string, statements: {sql: string, params: unknown[]}[]): Promise<any[][]> }} D1Api */

export const cliActor = accountId => "cli:" + accountId;
/** The shared admin operations read through the D1 REST API. @param {D1Api} api @param {string} databaseId */
export const restReader = (api, databaseId) => ({ all: (sql, params) => api.queryDatabase(databaseId, sql, params) });

/**
 * Commits a shared admin plan in one D1 batch (the change, its change-feed row and Studio's
 * "succeeded" audit), after an "attempted" audit; a failed batch is audited "failed".
 * @param {{ api: D1Api, databaseId: string, actor: string, plan: import("../../src/shared/admin-ops.mjs").AdminPlan,
 *   apply: boolean, confirm?: (plan: any) => Promise<boolean> }} input
 */
export async function commitPlan({ api, databaseId, actor, plan, apply, confirm }) {
  const planned = { action: plan.action, target: plan.target, changes: plan.statements ? plan.statements.length : 0, result: plan.result };
  if (!apply || !plan.statements) return { applied: false, ...planned };
  if (!confirm || !await confirm(planned)) throw Error("Cancelled");
  const write = s => api.queryDatabase(databaseId, s.sql, s.params);
  await write(auditStatement(actor, plan.action, plan.target, "attempted"));
  try {
    await api.batchDatabase(databaseId, committedStatements(plan, actor));
  } catch (error) {
    await write(auditStatement(actor, plan.action, plan.target, "failed")).catch(() => {});
    throw error;
  }
  return { applied: true, ...planned };
}

/** RBAC grant writes audit a refusal as "rejected", like Studio (src/auth/rbac.ts). */
async function rbacPlan({ api, databaseId, actor, apply, body, build }) {
  try { return await build(); } catch (error) {
    if (apply) {
      const rejected = auditStatement(actor, rbacAuditAction(body.op), rbacAttemptTarget(body), "rejected");
      await api.queryDatabase(databaseId, rejected.sql, rejected.params).catch(() => {});
    }
    throw error;
  }
}
/** `--user` takes a Nathan user id (the OIDC `sub`) or an email. */
const principal = ({ user, group }) => {
  if (user && group) throw Error("Grant a role to a user or a group");
  if (group) return { principalType: "group", group };
  if (!user) throw Error("Grant a role to a user or a group");
  return user.includes("@") ? { principalType: "user", email: user } : { principalType: "user", userId: user };
};

/** @param {{ api: D1Api, databaseId: string, actor: string, apply: boolean, app: string, role: string, user?: string, group?: string, confirm?: any }} input */
export async function grantRole({ api, databaseId, actor, apply, app, role, user, group, confirm }) {
  const body = { op: "grant.create", app, role, ...principal({ user, group }) };
  const plan = await rbacPlan({ api, databaseId, actor, apply, body, build: () => planGrantCreate(restReader(api, databaseId), body, actor) });
  return commitPlan({ api, databaseId, actor, plan, apply, confirm });
}

/** Revokes the one grant of `role` on `app` to the user or group (Studio revokes by grant id). */
export async function revokeRole({ api, databaseId, actor, apply, app, role, user, group, confirm }) {
  const body = { op: "grant.revoke", app, role, ...principal({ user, group }) };
  const plan = await rbacPlan({ api, databaseId, actor, apply, body, build: async () => {
    const db = restReader(api, databaseId);
    const appId = await requireApp(db, app);
    if (!isRoleKey(role)) throw Error("Unknown role");
    const id = body.principalType === "group" ? await requireGroup(db, body.group)
      : body.userId ? await userById(db, body.userId) : await userByEmail(db, body.email);
    const rows = await db.all("SELECT id FROM nathan_rbac_grants WHERE app_id=? AND role_key=? AND principal_type=? AND principal_id=? LIMIT 1",
      [appId, role, body.principalType, id]);
    if (!rows[0]) throw Error("Unknown grant");
    return planGrantRevoke(db, { id: rows[0].id });
  } });
  return commitPlan({ api, databaseId, actor, plan, apply, confirm });
}

/** @param {{ api: D1Api, databaseId: string, actor: string, apply: boolean, id: string, enabled: boolean, confirmation?: string }} input */
export async function setAppStatus({ api, databaseId, actor, apply, id, enabled, confirmation }) {
  const plan = await planAppStatus(restReader(api, databaseId), { id, enabled, confirm: apply ? confirmation : appStatusConfirmation(id, enabled) });
  return commitPlan({ api, databaseId, actor, plan, apply, confirm: async () => true });
}

/** @param {{ api: D1Api, databaseId: string, actor: string, apply: boolean, issuerOrigin: string, body: any, confirm?: any }} input */
export async function registerMcp({ api, databaseId, actor, apply, issuerOrigin, body, confirm }) {
  const plan = await planMcpRegister(restReader(api, databaseId), body, issuerOrigin, actor);
  return commitPlan({ api, databaseId, actor, plan, apply, confirm });
}

/** @param {{ api: D1Api, databaseId: string, actor: string, apply: boolean, issuerOrigin: string, identifier: string, enabled: boolean, confirmation?: string }} input */
export async function setMcpStatus({ api, databaseId, actor, apply, issuerOrigin, identifier, enabled, confirmation }) {
  const plan = await planMcpStatus(restReader(api, databaseId), { identifier, enabled, confirm: apply ? confirmation : mcpStatusConfirmation(identifier, enabled) }, issuerOrigin);
  return commitPlan({ api, databaseId, actor, plan, apply, confirm: async () => true });
}

/** Read-only: the ids of the users with this email. Never sessions, tokens or recovery data. */
export async function findUserIds({ api, databaseId, email }) {
  const value = String(email ?? "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || value.length > 254) throw Error("Select an existing user by exact email");
  const rows = await api.queryDatabase(databaseId, 'SELECT "id" AS id FROM "user" WHERE lower("email")=? ORDER BY "id" LIMIT 5', [value]);
  return rows.map(r => r.id);
}

// ---- argument handling --------------------------------------------------------------------------

/** @param {string[]} args @param {string} name */
export function flag(args, name) {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const value = args[i + 1];
  if (value === undefined || value.startsWith("--")) throw Error(name + " needs a value");
  return value;
}
/** A JSON object given inline or as @file. */
async function jsonFlag(args, name) {
  const raw = flag(args, name);
  if (raw === undefined) return undefined;
  const text = raw.startsWith("@") ? await readFile(raw.slice(1), "utf8") : raw;
  try { return JSON.parse(text); } catch { throw Error(name + " must be a JSON object (inline or @file)"); }
}

export async function openNathanDatabase(file) {
  const cfg = await loadConfig(file);
  if (!cfg.accountId) throw Error("accountId required");
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, cfg.accountId);
  const database = await api.databaseNamed(cfg.database.name);
  if (!database) throw Error("Nathan D1 database not found");
  return { api, databaseId: database.uuid || database.id, actor: cliActor(cfg.accountId), issuerOrigin: "https://" + cfg.hostname };
}
const print = value => console.log(JSON.stringify(value, null, 2));
function planNotice(result, command) {
  print(result);
  if (!result.applied) console.log(result.changes ? "Plan only. Re-run with --apply to " + command + "." : "Nothing to change.");
}
async function confirmPlan(planned) {
  print(planned);
  return yesNo("Apply this change to Nathan (audited as the account-token CLI)?");
}
async function typed(expected) {
  if (await ask("Type " + expected + " to confirm") !== expected) throw Error("Cancelled");
  return expected;
}

export async function appCommand(args, file, apply) {
  const [sub, id] = args;
  if (sub === "apply") {
    const { appApplyCommand } = await import("./app-manifest.mjs");
    return appApplyCommand(args, file, apply, { openNathanDatabase, ask, yesNo });
  }
  if (!["enable", "disable"].includes(sub) || !id) {
    console.log("Usage: nathan app enable|disable <app> [--apply]\n       nathan app apply <manifest.json> [--apply] [--prune]\n" +
      "Enables an application, or applies an application's manifest to the shared IdP (planned unless --apply).");
    return;
  }
  const db = await openNathanDatabase(file);
  const enabled = sub === "enable";
  const confirmation = apply ? await typed(appStatusConfirmation(id, enabled)) : undefined;
  planNotice(await setAppStatus({ ...db, apply, id, enabled, confirmation }), sub + " " + id);
}

export async function grantCommand(args, file, apply) {
  const [sub, app, role] = args;
  const db = await openNathanDatabase(file);
  const input = { ...db, apply, app, role, user: flag(args, "--user"), group: flag(args, "--group"), confirm: confirmPlan };
  planNotice(await (sub === "grant" ? grantRole(input) : revokeRole(input)), sub + " the role");
}

export async function mcpCommand(args, file, apply) {
  const [sub, identifier] = args;
  if (!["register", "status"].includes(sub) || !identifier) {
    console.log("Usage: nathan mcp register <identifier> --app <app> --name <name> [--scopes <json|@file>] [--full <scope>] [--aliases <json|@file>] [--apply]\n" +
      "       nathan mcp status <identifier> --enable|--disable [--apply]\n" +
      "Same identifier, audience and catalog rules as Identity Studio's Remote MCP servers (docs/remote-mcp.md).");
    return;
  }
  const db = await openNathanDatabase(file);
  if (sub === "status") {
    const enable = args.includes("--enable"), disable = args.includes("--disable");
    if (enable === disable) throw Error("Choose --enable or --disable");
    const confirmation = apply ? await typed(mcpStatusConfirmation(identifier, enable)) : undefined;
    planNotice(await setMcpStatus({ ...db, apply, identifier, enabled: enable, confirmation }), (enable ? "enable " : "disable ") + identifier);
    return;
  }
  const body = { identifier, app: flag(args, "--app"), name: flag(args, "--name"), full: flag(args, "--full"),
    aliases: await jsonFlag(args, "--aliases"), scopes: await jsonFlag(args, "--scopes") };
  // Like Studio, a new registration is enabled (migration 0015); `mcp status --disable` turns it off.
  planNotice(await registerMcp({ ...db, apply, body, confirm: confirmPlan }), "register " + identifier);
}

export async function userCommand(args, file) {
  if (args[0] !== "find") {
    console.log("Usage: nathan user find --email <email>\nPrints the Nathan user id(s) for an email (read-only).");
    return;
  }
  const db = await openNathanDatabase(file);
  const ids = await findUserIds({ ...db, email: flag(args, "--email") });
  print({ ids });
}
