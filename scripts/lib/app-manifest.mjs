/**
 * Per-application manifests for a Nathan that is the identity provider of many applications.
 *
 * Each application keeps one file in its own repository that says what it needs from the shared
 * IdP: its id and hostname, its permissions and roles, its remote MCP servers, and whether it is
 * enabled. The operator applies it to the IdP with an account token:
 *
 *   nathan app apply <manifest.json> [--apply] [--prune]
 *
 * Grants (who holds a role) are never in a manifest: they are made per person with `nathan rbac
 * grant` or in Identity Studio. The IdP's own nathan.config.json only names the deployment
 * (account, D1, issuer hostname); applications do not have to be listed in it.
 *
 *   {
 *     "id": "educateos-staging",
 *     "hostname": "staging.educateos.io",
 *     "enabled": true,                                  // optional; omitted = leave as is
 *     "rbac": { "permissions": { ... }, "roles": { ... }, "accessMode": "approved" },
 *     "mcp": [{ "identifier": "https://staging.educateos.io/mcp", "name": "EducateOS Staging",
 *               "scopes": { ... }, "full": null, "aliases": {}, "enabled": true }]
 *   }
 *
 * Every step is the same operation as its single command (rbac sync, mcp register|status, app
 * enable), with the same validation, statements and audit rows; the apply as a whole is audited
 * `app_manifest_apply` (attempted, then succeeded or partial/failed).
 */
import { readFile } from "node:fs/promises";
import { isAppId } from "../../src/shared/policy.mjs";
import { validateManifest } from "../../src/shared/rbac-manifest.mjs";
import { validateAudience } from "../../src/shared/token-claims.mjs";
import { auditStatement } from "../../src/shared/rbac-store.mjs";
import { planMcpRegister, planMcpStatus, planAppStatus, appStatusConfirmation, mcpStatusConfirmation } from "../../src/shared/admin-ops.mjs";
import { syncApplicationRbac } from "./rbac-wizard.mjs";
import { commitPlan, restReader } from "./admin-cli.mjs";

const HOSTNAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const plainObject = value => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const invalid = message => { throw Error("Invalid app manifest: " + message); };

/** @param {unknown} value @param {string} issuerOrigin */
export function validateAppManifest(value, issuerOrigin) {
  if (!plainObject(value)) invalid("expected an object");
  const m = /** @type {Record<string, any>} */ (value);
  for (const key of Object.keys(m)) {
    if (key === "grants") invalid("grants are never part of a manifest; use `nathan rbac grant` or Identity Studio");
    if (!["$schema", "id", "hostname", "enabled", "rbac", "mcp"].includes(key)) invalid("unsupported field " + key);
  }
  if (!isAppId(m.id)) invalid("id must be a lowercase application slug");
  if (typeof m.hostname !== "string" || !HOSTNAME.test(m.hostname)) invalid("hostname must be a lowercase DNS name");
  if (m.enabled !== undefined && typeof m.enabled !== "boolean") invalid("enabled must be true or false");
  const rbac = validateManifest(m.rbac);
  const mcp = m.mcp ?? [];
  if (!Array.isArray(mcp) || mcp.length > 20) invalid("mcp must be a list of at most 20 servers");
  const seen = new Set();
  for (const server of mcp) {
    if (!plainObject(server)) invalid("each mcp server must be an object");
    for (const key of Object.keys(server))
      if (!["identifier", "name", "full", "aliases", "scopes", "enabled"].includes(key)) invalid("unsupported mcp field " + key);
    validateAudience(server.identifier, issuerOrigin);
    if (seen.has(server.identifier)) invalid("duplicate mcp server " + server.identifier);
    seen.add(server.identifier);
    if (server.enabled !== undefined && typeof server.enabled !== "boolean") invalid("mcp enabled must be true or false");
  }
  return { id: m.id, hostname: m.hostname, enabled: m.enabled, rbac: m.rbac, permissionKeys: rbac.permissions.map(p => p.key), mcp };
}

/**
 * Plans (and with apply, applies) one manifest. `confirm(plan)` approves the whole plan; it must
 * collect any typed confirmation itself and return the strings in `confirmations`.
 * @param {{ api: any, databaseId: string, actor: string, issuerOrigin: string, manifest: any, apply: boolean, prune?: boolean,
 *   confirm?: (plan: any) => Promise<false | { confirmations: Record<string, string> }> }} input
 */
export async function applyAppManifest({ api, databaseId, actor, issuerOrigin, manifest, apply, prune = false, confirm }) {
  const m = validateAppManifest(manifest, issuerOrigin);
  const db = restReader(api, databaseId);
  const app = { id: m.id, hostname: m.hostname, rbac: m.rbac };
  const rbac = await syncApplicationRbac({ api, databaseId, app, actor, apply: false, prune });
  const current = (await db.all("SELECT enabled FROM nathan_applications WHERE id=?", [m.id]))[0] ?? null;
  const existingKeys = (await db.all("SELECT key FROM nathan_rbac_permissions WHERE app_id=?", [m.id])).map(r => r.key);
  // Planned against the permissions the app will have once the sync has run; re-validated for real before each commit.
  const permissionKeys = [...new Set([...m.permissionKeys, ...(prune ? [] : existingKeys)])];
  const mcp = [];
  for (const server of m.mcp) {
    const body = { identifier: server.identifier, app: m.id, name: server.name, full: server.full, aliases: server.aliases, scopes: server.scopes };
    const plan = await planMcpRegister(db, body, issuerOrigin, actor, { permissionKeys });
    const enabledNow = plan.result.created ? true : (await db.all("SELECT enabled FROM nathan_mcp_resources WHERE identifier=?", [server.identifier]))[0]?.enabled === 1;
    const status = server.enabled !== undefined && server.enabled !== enabledNow ? server.enabled : undefined;
    mcp.push({ identifier: server.identifier, body, register: plan.result.created ? "create" : "update", ...(status !== undefined ? { setEnabled: status } : {}) });
  }
  const enabledNow = current ? current.enabled === 1 : false;
  const setEnabled = m.enabled !== undefined && m.enabled !== enabledNow ? m.enabled : undefined;
  const plan = {
    app: m.id, register: rbac.wouldRegister, rbac: rbac.ops,
    mcp: mcp.map(({ body, ...rest }) => rest),
    ...(setEnabled !== undefined ? { setEnabled } : {})
  };
  if (!apply) return { applied: false, plan };
  if (!confirm) throw Error("Cancelled");
  const approved = await confirm(plan);
  if (!approved) throw Error("Cancelled");
  const confirmations = approved.confirmations ?? {};

  const write = s => api.queryDatabase(databaseId, s.sql, s.params);
  await write(auditStatement(actor, "app_manifest_apply", m.id, "attempted"));
  let step = "rbac";
  try {
    await syncApplicationRbac({ api, databaseId, app, actor, apply: true, prune, confirm: async () => true });
    for (const server of mcp) {
      step = "mcp " + server.identifier;
      await commitPlan({ api, databaseId, actor, apply: true, confirm: async () => true,
        plan: await planMcpRegister(db, server.body, issuerOrigin, actor) });
      if (server.setEnabled !== undefined)
        await commitPlan({ api, databaseId, actor, apply: true, confirm: async () => true,
          plan: await planMcpStatus(db, { identifier: server.identifier, enabled: server.setEnabled,
            confirm: confirmations[mcpStatusConfirmation(server.identifier, server.setEnabled)] }, issuerOrigin) });
    }
    if (setEnabled !== undefined) {
      step = "app status";
      await commitPlan({ api, databaseId, actor, apply: true, confirm: async () => true,
        plan: await planAppStatus(db, { id: m.id, enabled: setEnabled, confirm: confirmations[appStatusConfirmation(m.id, setEnabled)] }) });
    }
  } catch (error) {
    await write(auditStatement(actor, "app_manifest_apply", m.id + " (stopped at " + step + ")", step === "rbac" ? "failed" : "partial")).catch(() => {});
    throw error;
  }
  await write(auditStatement(actor, "app_manifest_apply", m.id, "succeeded"));
  return { applied: true, plan };
}

/** The typed confirmations a plan needs (Studio's strings), keyed by themselves. @param {any} plan */
export function requiredConfirmations(plan) {
  const out = [];
  if (plan.rbac.some(o => o.op === "access_mode" && o.key === "any_signed_in")) out.push("CONFIRM ANY SIGNED IN " + plan.app);
  if (plan.rbac.some(o => o.op.endsWith(".delete"))) out.push("PRUNE");
  for (const server of plan.mcp) if (server.setEnabled !== undefined) out.push(mcpStatusConfirmation(server.identifier, server.setEnabled));
  if (plan.setEnabled !== undefined) out.push(appStatusConfirmation(plan.app, plan.setEnabled));
  return out;
}

export async function readManifest(path) {
  try { return JSON.parse(await readFile(path, "utf8")); }
  catch (error) { throw Error("Cannot read app manifest " + path + ": " + (error instanceof SyntaxError ? "invalid JSON" : error.code ?? "error")); }
}

/** `nathan app apply <manifest.json> [--apply] [--prune]` */
export async function appApplyCommand(args, file, apply, { openNathanDatabase, ask, yesNo }) {
  const path = args[1];
  if (!path) {
    console.log("Usage: nathan app apply <manifest.json> [--apply] [--prune] [--config <idp config>]\n" +
      "Applies one application's manifest (permissions, roles, MCP servers, enabled) to the shared IdP. Grants are separate.");
    return;
  }
  const db = await openNathanDatabase(file);
  const result = await applyAppManifest({
    ...db, manifest: await readManifest(path), apply, prune: args.includes("--prune"),
    confirm: async plan => {
      console.log(JSON.stringify(plan, null, 2));
      const confirmations = {};
      for (const expected of requiredConfirmations(plan)) {
        if (await ask("Type " + expected + " to confirm") !== expected) return false;
        confirmations[expected] = expected;
      }
      return await yesNo("Apply this manifest to Nathan (audited as the account-token CLI)?") ? { confirmations } : false;
    }
  });
  console.log(JSON.stringify(result, null, 2));
  if (!result.applied) console.log("Plan only. Re-run with --apply to apply.");
}
