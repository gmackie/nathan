/**
 * Validation and statements of the privileged administrator writes that Identity Studio and the
 * account-token CLI (`scripts/nathan.mjs`) share: enabling an application, granting and revoking an
 * RBAC role, and registering or enabling a remote MCP server.
 *
 * Each `plan*` function reads through a minimal database interface, applies every check, and
 * returns the statements to commit, so the two callers cannot drift apart:
 *   - the identity Worker reads and commits through its D1 binding (one atomic batch);
 *   - the CLI reads and commits through the Cloudflare D1 REST API (one batch call), audited as
 *     `cli:<accountId>`.
 * Plain SQL with positional parameters, as in rbac-store.mjs.
 */
import { isAppId, isGroupId, isRoleKey, isSubjectId } from "./policy.mjs";
import { auditStatement, changeStatement } from "./rbac-store.mjs";
import { validateAudience } from "./token-claims.mjs";
import { validateResourceConfig } from "./mcp-scopes.mjs";

/** @typedef {{ sql: string, params: unknown[] }} Statement */
/** @typedef {{ all(sql: string, params: unknown[]): Promise<any[]> }} AdminReader */
/**
 * A planned write. `statements` absent means there is nothing to change (`result` says why).
 * @typedef {{ action: string, target: string, statements?: Statement[],
 *   change?: { kind: string, appId?: string|null, principalType?: "user"|"group"|null, principalId?: string|null, detail?: object },
 *   result: Record<string, unknown> }} AdminPlan
 */

/** @param {AdminReader} db @param {string} sql @param {unknown[]} params */
async function first(db, sql, params) { return (await db.all(sql, params))[0] ?? null; }
/** @param {AdminReader} db @param {string} sql @param {unknown[]} params */
async function count(db, sql, params) { return Number((await first(db, sql, params))?.n ?? 0); }

/** @param {AdminReader} db @param {unknown} appId @returns {Promise<string>} */
export async function requireApp(db, appId) {
  if (!isAppId(appId)) throw Error("Invalid application id");
  if (!await first(db, "SELECT id FROM nathan_applications WHERE id=?", [appId])) throw Error("Unknown application");
  return /** @type {string} */ (appId);
}
/** Exactly one user with this email (case-insensitive). @param {AdminReader} db @param {unknown} email */
export async function userByEmail(db, email) {
  const value = String(email ?? "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || value.length > 254) throw Error("Select an existing user by exact email");
  const users = await db.all('SELECT "id" AS id FROM "user" WHERE lower("email")=? LIMIT 2', [value]);
  if (users.length !== 1) throw Error("User not found");
  return /** @type {string} */ (users[0].id);
}
/** An existing user by Nathan user id (the OIDC `sub`). @param {AdminReader} db @param {unknown} userId */
export async function userById(db, userId) {
  if (!isSubjectId(userId)) throw Error("Invalid user id");
  if (!await first(db, 'SELECT "id" AS id FROM "user" WHERE "id"=?', [userId])) throw Error("User not found");
  return /** @type {string} */ (userId);
}
/** @param {AdminReader} db @param {unknown} groupId @param {{ editable?: boolean }} [options] */
export async function requireGroup(db, groupId, { editable = false } = {}) {
  if (!isGroupId(groupId)) throw Error("Invalid group id");
  const group = await first(db, "SELECT id, source FROM nathan_groups WHERE id=?", [groupId]);
  if (!group) throw Error("Unknown group");
  // Extension point (NATH-11): SCIM-mapped groups are maintained by the directory, not by hand.
  if (editable && group.source === "scim") throw Error("Membership of SCIM-mapped groups is managed by the directory");
  return /** @type {string} */ (group.id);
}

// ---- RBAC grants -------------------------------------------------------------------------------

export const RBAC_OPERATIONS = /** @type {const} */ (["access_mode", "permission.upsert", "permission.delete", "role.upsert", "role.delete",
  "group.upsert", "group.delete", "member.add", "member.remove", "grant.create", "grant.revoke", "sync"]);
/** Audit action of an RBAC operation, e.g. grant.create -> rbac_grant_create. @param {unknown} op */
export function rbacAuditAction(op) {
  if (op === "sync") return "rbac_manifest_sync";
  return RBAC_OPERATIONS.includes(/** @type {any} */ (op)) ? "rbac_" + String(op).replace(".", "_") : "rbac_unknown";
}
/** Best-effort, bounded description of what an administrator tried to change (for a "rejected" audit). @param {any} body */
export function rbacAttemptTarget(body) {
  const parts = RBAC_OPERATIONS.includes(body?.op)
    ? [body.app ?? body.group, body.key ?? body.role ?? body.accessMode ?? body.id ?? body.email]
    : [body?.op];
  const text = parts.filter(p => typeof p === "string" && p).join(":");
  return text.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 200) || "-";
}

/**
 * Grants a role of an application to a user (by `email`, or by `userId`) or a group.
 * @param {AdminReader} db @param {any} body `{ app, role, principalType: "user"|"group", email?, userId?, group? }`
 * @param {string} actor @returns {Promise<AdminPlan>}
 */
export async function planGrantCreate(db, body, actor) {
  const app = await requireApp(db, body.app);
  if (!isRoleKey(body.role) || !await count(db, "SELECT count(*) AS n FROM nathan_rbac_roles WHERE app_id=? AND key=?", [app, body.role]))
    throw Error("Unknown role");
  /** @type {"user"|"group"} */ let principalType;
  /** @type {string} */ let principalId;
  if (body.principalType === "user") {
    principalType = "user";
    principalId = body.userId !== undefined && body.userId !== null && body.userId !== "" ? await userById(db, body.userId) : await userByEmail(db, body.email);
  } else if (body.principalType === "group") { principalType = "group"; principalId = await requireGroup(db, body.group); }
  else throw Error("Grant a role to a user or a group");
  const target = app + ":" + body.role + ":" + principalType + ":" + principalId;
  if (await count(db, "SELECT count(*) AS n FROM nathan_rbac_grants WHERE app_id=? AND role_key=? AND principal_type=? AND principal_id=?",
    [app, body.role, principalType, principalId]))
    return { action: "rbac_grant_create", target, result: { app, role: body.role, principalType, principalId, created: false, note: "Already granted" } };
  const id = crypto.randomUUID();
  return {
    action: "rbac_grant_create", target,
    statements: [{
      sql: "INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES (?,?,?,?,?,?)",
      params: [id, app, body.role, principalType, principalId, actor]
    }],
    change: { kind: "grant.created", appId: app, principalType, principalId, detail: { role: body.role } },
    result: { id, app, role: body.role, principalType, principalId, created: true }
  };
}

/** @param {AdminReader} db @param {any} body `{ id }` (the grant id) @returns {Promise<AdminPlan>} */
export async function planGrantRevoke(db, body) {
  if (typeof body.id !== "string" || body.id.length > 200) throw Error("Invalid grant id");
  const grant = await first(db, "SELECT id, app_id AS app, role_key AS role, principal_type AS principalType, principal_id AS principalId FROM nathan_rbac_grants WHERE id=?", [body.id]);
  if (!grant) throw Error("Unknown grant");
  return {
    action: "rbac_grant_revoke", target: grant.app + ":" + grant.role + ":" + grant.principalType + ":" + grant.principalId,
    statements: [{ sql: "DELETE FROM nathan_rbac_grants WHERE id=?", params: [grant.id] }],
    change: { kind: "grant.revoked", appId: grant.app, principalType: grant.principalType, principalId: grant.principalId, detail: { role: grant.role } },
    result: { ...grant, revoked: true, note: "Nathan gateways stop honoring the grant within their access cache window (at most 60 s)" }
  };
}

// ---- Applications ------------------------------------------------------------------------------

/** Confirmation an administrator types to enable or disable an application. @param {string} id @param {boolean} enabled */
export const appStatusConfirmation = (id, enabled) => "CONFIRM " + (enabled ? "ENABLE " : "DISABLE ") + id;
/** @param {AdminReader} db @param {any} body `{ id, enabled, confirm }` @returns {Promise<AdminPlan>} */
export async function planAppStatus(db, body) {
  if (typeof body.id !== "string" || !isAppId(body.id)) throw Error("Invalid application id");
  if (typeof body.enabled !== "boolean" || body.confirm !== appStatusConfirmation(body.id, body.enabled)) throw Error("Explicit confirmation required");
  if (!await first(db, "SELECT id FROM nathan_applications WHERE id=?", [body.id])) throw Error("Unknown application");
  const id = body.id, enabled = body.enabled;
  return {
    action: enabled ? "application_enable" : "application_disable", target: id,
    statements: [{ sql: "UPDATE nathan_applications SET enabled=?,updated_at=unixepoch() WHERE id=?", params: [enabled ? 1 : 0, id] }],
    // NATH-13 change feed: an enable/disable changes every principal's effective access to the app.
    change: { kind: enabled ? "app.enabled" : "app.disabled", appId: id },
    result: { id, enabled }
  };
}

// ---- Remote MCP servers (NATH-14) --------------------------------------------------------------

const MCP_RESOURCE = "SELECT identifier, app_id, name, full_scope, aliases, enabled FROM nathan_mcp_resources WHERE identifier=? LIMIT 1";

/** Confirmation an administrator types to enable or disable an MCP server. @param {string} identifier @param {boolean} enabled */
export const mcpStatusConfirmation = (identifier, enabled) => "CONFIRM " + (enabled ? "ENABLE" : "DISABLE") + " MCP " + identifier;

/**
 * Registers (or updates) a remote MCP server: an exact https audience bound to one application,
 * whose catalog is the app's permissions. Refuses Nathan's own reserved paths and an identifier
 * that is already a Better Auth or a plain Nathan token audience.
 * @param {AdminReader} db @param {any} body `{ identifier, app, name, full?, aliases?, scopes? }`
 * @param {string} issuerOrigin e.g. https://login.example.com @param {string} actor @returns {Promise<AdminPlan>}
 */
export async function planMcpRegister(db, body, issuerOrigin, actor) {
  const identifier = validateAudience(body.identifier, issuerOrigin);
  if (typeof body.app !== "string" || !isAppId(body.app)) throw Error("Invalid application id");
  if (!await first(db, "SELECT id FROM nathan_applications WHERE id=? LIMIT 1", [body.app])) throw Error("Unknown application");
  if (await first(db, 'SELECT "identifier" FROM "oauthResource" WHERE "identifier"=? LIMIT 1', [identifier]))
    throw Error("Invalid resource: it is already a Better Auth token audience; use another identifier");
  const audience = await first(db, "SELECT app_id FROM nathan_token_audiences WHERE identifier=? LIMIT 1", [identifier]);
  const mcp = await first(db, MCP_RESOURCE, [identifier]);
  if (audience && !mcp) throw Error("Invalid resource: it is already a token audience; use another identifier");
  const permissionKeys = (await db.all("SELECT key FROM nathan_rbac_permissions WHERE app_id=? LIMIT 500", [body.app])).map(p => p.key);
  const config = validateResourceConfig({ name: body.name, full: body.full, aliases: body.aliases, scopes: body.scopes }, permissionKeys);
  const previousApp = mcp?.app_id ?? null;
  return {
    action: "mcp_resource_register", target: identifier + " app=" + body.app,
    statements: [
      { sql: "INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,?,?) " +
          "ON CONFLICT(identifier) DO UPDATE SET app_id=excluded.app_id, updated_at=unixepoch()", params: [identifier, body.app, actor] },
      { sql: "INSERT INTO nathan_mcp_resources(identifier,app_id,name,full_scope,aliases,created_by) VALUES (?,?,?,?,?,?) " +
          "ON CONFLICT(identifier) DO UPDATE SET app_id=excluded.app_id, name=excluded.name, full_scope=excluded.full_scope, aliases=excluded.aliases, updated_at=unixepoch()",
        params: [identifier, body.app, config.name, config.full, JSON.stringify(config.aliases), actor] },
      // Moving a resource to another application ends its connections: they were consented for the old one.
      { sql: "DELETE FROM nathan_mcp_grants WHERE resource=? AND ? IS NOT NULL AND ?<>?", params: [identifier, previousApp, previousApp, body.app] },
      { sql: "DELETE FROM nathan_mcp_scopes WHERE resource=?", params: [identifier] },
      ...config.scopes.map(s => ({
        sql: "INSERT INTO nathan_mcp_scopes(resource,scope,label,description,group_key,requires,sensitive,admin_only) VALUES (?,?,?,?,?,?,?,?)",
        params: [identifier, s.scope, s.label, s.description, s.group, JSON.stringify(s.requires), s.sensitive ? 1 : 0, s.adminOnly ? 1 : 0]
      }))
    ],
    result: { identifier, app: body.app, name: config.name, full: config.full, aliases: config.aliases, scopes: config.scopes, created: !mcp }
  };
}

/** @param {AdminReader} db @param {any} body `{ identifier, enabled, confirm }` @param {string} issuerOrigin @returns {Promise<AdminPlan>} */
export async function planMcpStatus(db, body, issuerOrigin) {
  const identifier = validateAudience(body.identifier, issuerOrigin);
  if (!await first(db, MCP_RESOURCE, [identifier])) throw Error("Unknown MCP resource");
  if (typeof body.enabled !== "boolean" || body.confirm !== mcpStatusConfirmation(identifier, body.enabled))
    throw Error("Explicit confirmation required");
  return {
    action: "mcp_resource_status", target: identifier + " enabled=" + body.enabled,
    statements: [{ sql: "UPDATE nathan_mcp_resources SET enabled=?, updated_at=unixepoch() WHERE identifier=?", params: [body.enabled ? 1 : 0, identifier] }],
    result: { identifier, enabled: body.enabled }
  };
}

/**
 * The one batch that commits a plan: its statements, its change-feed row (if any) and the
 * "succeeded" audit row, so a committed change is never missing from the log.
 * @param {AdminPlan} plan @param {string} actor @returns {Statement[]}
 */
export function committedStatements(plan, actor) {
  if (!plan.statements) return [];
  return [
    ...plan.statements,
    ...(plan.change ? [changeStatement({ ...plan.change, actor })] : []),
    auditStatement(actor, plan.action, plan.target, "succeeded")
  ];
}
