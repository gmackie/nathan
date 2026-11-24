/**
 * NATH-13 `nathan rbac plan|sync <app>`: syncs an application's permissions and roles declared in
 * nathan.config.json (applications[].rbac) into Nathan's D1 database. Uses the same plan and SQL as
 * Identity Studio. Grants are never synced from code. Writes are audited as cli:<accountId>.
 */
import { loadConfig } from "./config.mjs";
import { CloudflareClient } from "./cloudflare.mjs";
import { ask, yesNo } from "./prompts.mjs";
import { validateManifest, currentStateQueries, currentState, planSync, syncStatements } from "../../src/shared/rbac-manifest.mjs";
import { auditStatement, changeStatement } from "../../src/shared/rbac-store.mjs";
import { grantCommand } from "./admin-cli.mjs";

/**
 * Plans (and with apply, applies) one application's manifest through a D1 query API.
 * Statements run one at a time and are idempotent; a failure part-way leaves less access, never
 * more (a role's permissions are cleared before they are re-added), and re-running converges.
 * Audit: "attempted" before the first change, then "succeeded", or "partial"/"failed" on error.
 * @param {{ api: { queryDatabase(id: string, sql: string, params?: unknown[]): Promise<any[]> }, databaseId: string,
 *   app: any, actor: string, apply: boolean, prune?: boolean, confirm?: (message: string, ops: any[]) => Promise<boolean> }} input
 */
export async function syncApplicationRbac({ api, databaseId, app, actor, apply, prune = false, confirm }) {
  if (!app?.rbac) throw Error("Application " + (app?.id ?? "?") + " has no rbac section in nathan.config.json");
  const manifest = validateManifest(app.rbac);
  const read = async () => currentState(await Promise.all(currentStateQueries(app.id).map(q => api.queryDatabase(databaseId, q.sql, q.params))));
  let state = await read();
  let registered = false;
  if (!state.app) {
    if (!app.hostname) throw Error("Application " + app.id + " is not registered in Nathan and has no hostname to register it with");
    // Planned against an empty, disabled, deny-by-default registration.
    state = { app: { id: app.id, accessMode: "approved" }, permissions: [], roles: [] };
    registered = true;
  }
  const ops = planSync(state, manifest, { prune });
  if (!apply) return { app: app.id, registered: false, wouldRegister: registered, ops };
  if (!ops.length && !registered) return { app: app.id, registered: false, ops };
  if (!confirm || !await confirm("Apply " + ops.length + " RBAC change(s) to " + app.id + "?", ops)) throw Error("Cancelled");
  const statements = [
    ...(registered ? [
      { sql: "INSERT INTO nathan_applications(id,hostname,roles,enabled) VALUES (?,?,'[]',0) ON CONFLICT(id) DO NOTHING", params: [app.id, app.hostname] },
      changeStatement({ kind: "app.registered", appId: app.id, actor }),
      auditStatement(actor, "application_upsert", app.id, "succeeded")
    ] : []),
    ...syncStatements(app.id, ops, actor)
  ];
  // The D1 REST query API runs one statement per call, so a sync cannot be a single transaction.
  // The attempt is audited before the first change, and a failure part-way is audited with how
  // far it got, so the log never shows less than what happened.
  const run = statement => api.queryDatabase(databaseId, statement.sql, statement.params);
  await run(auditStatement(actor, "rbac_manifest_sync", app.id, "attempted"));
  let applied = 0;
  try {
    for (const statement of statements) { await run(statement); applied++; }
  } catch (error) {
    await run(auditStatement(actor, "rbac_manifest_sync", app.id + " (" + applied + " of " + statements.length + " statements applied)",
      applied ? "partial" : "failed")).catch(() => {});
    throw error;
  }
  return { app: app.id, registered, ops };
}

export async function rbacCommand(args, file, apply) {
  const [sub, appId] = args;
  if ((sub === "grant" || sub === "revoke") && appId && args[2]) return grantCommand(args, file, apply);
  if (!["plan", "sync"].includes(sub) || !appId) {
    console.log("Usage: nathan rbac plan <app>\n       nathan rbac sync <app> --apply [--prune]\n" +
      "       nathan rbac grant|revoke <app> <role> --user <user id or verified email> | --group <group> [--apply]\n" +
      "Syncs applications[].rbac (permissions and roles) from nathan.config.json. Grants are made with `rbac grant`\n" +
      "(account-token path, audited as cli:<accountId>) or in Identity Studio.");
    return;
  }
  const cfg = await loadConfig(file);
  const app = cfg.applications.find(a => a.id === appId);
  if (!app) throw Error("Unknown application " + appId);
  if (!cfg.accountId) throw Error("accountId required");
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, cfg.accountId);
  const database = await api.databaseNamed(cfg.database.name);
  if (!database) throw Error("Nathan D1 database not found");
  const prune = args.includes("--prune");
  const result = await syncApplicationRbac({
    api, databaseId: database.uuid || database.id, app, actor: "cli:" + cfg.accountId, prune,
    apply: sub === "sync" && apply,
    confirm: async (message, ops) => {
      console.log(JSON.stringify(ops, null, 2));
      if (ops.some(o => o.op === "access_mode" && o.key === "any_signed_in") &&
          await ask("This admits EVERY signed-in user to " + appId + ". Type " + appId + " to confirm") !== appId) return false;
      if (ops.some(o => o.op.endsWith(".delete")) &&
          await ask("Pruning deletes roles (and their grants) or permissions. Type PRUNE to confirm") !== "PRUNE") return false;
      return yesNo(message);
    }
  });
  console.log(JSON.stringify(result, null, 2));
  if (sub === "plan" || !apply) console.log("Plan only. Run `nathan rbac sync " + appId + " --apply` to apply.");
}
