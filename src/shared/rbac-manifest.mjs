/**
 * Permissions and roles as code (NATH-13). An application's entry in nathan.config.json may carry:
 *
 *   "rbac": {
 *     "accessMode": "approved",                       // optional; omitted = leave as is
 *     "permissions": { "invoices:read": "Read invoices", "invoices:write": "Create and edit invoices" },
 *     "roles": {
 *       "viewer": { "description": "Read-only", "permissions": ["invoices:read"] },
 *       "editor": { "description": "Edit invoices", "permissions": ["invoices:read", "invoices:write"] }
 *     }
 *   }
 *
 * Grants (who holds a role) are never code: they are managed in Identity Studio. Sync upserts
 * declared entries and, only with `prune`, deletes code-sourced entries no longer declared.
 * The same plan and statements serve the CLI (D1 REST API) and Identity Studio (D1 binding).
 */
import { ACCESS_MODES, isPermissionKey, isRoleKey } from "./policy.mjs";
import { auditStatement, changeStatement } from "./rbac-store.mjs";

export const MAX_APP_PERMISSIONS = 256;
export const MAX_APP_ROLES = 64;

/** @typedef {import("./rbac-store.mjs").Statement} Statement */
/** @typedef {{ key: string, description: string }} PermissionSpec */
/** @typedef {{ key: string, description: string, permissions: string[] }} RoleSpec */
/** @typedef {{ accessMode?: "approved"|"any_signed_in", permissions: PermissionSpec[], roles: RoleSpec[] }} Manifest */
/** @typedef {{ op: string, key: string, description?: string, permissions?: string[], accessMode?: string }} SyncOp */

/** @param {any} value */
const plainObject = value => Boolean(value) && typeof value === "object" && !Array.isArray(value);
/** @param {unknown} value */
export const isDescription = value => typeof value === "string" && value.length <= 200 && !/[\x00-\x1f\x7f]/.test(value);
/** @param {string} message */
const invalid = message => { throw Error("Invalid RBAC manifest: " + message); };

/** @param {unknown} value @returns {Manifest} */
export function validateManifest(value) {
  if (!plainObject(value)) invalid("expected an object with permissions and roles");
  const manifest = /** @type {Record<string, any>} */ (value);
  for (const key of Object.keys(manifest))
    if (!["accessMode", "permissions", "roles"].includes(key)) invalid("unsupported field " + key + " (grants are managed in Identity Studio)");
  if (manifest.accessMode !== undefined && !ACCESS_MODES.includes(manifest.accessMode)) invalid("accessMode must be approved or any_signed_in");
  if (!plainObject(manifest.permissions)) invalid("permissions must map permission keys to descriptions");
  if (!plainObject(manifest.roles)) invalid("roles must map role keys to {description, permissions}");
  const permissions = Object.entries(manifest.permissions).map(([key, description]) => {
    if (!isPermissionKey(key)) invalid("permission key " + JSON.stringify(key) + " must look like resource:action");
    if (!isDescription(description)) invalid("description of " + key + " must be text up to 200 characters");
    return { key, description: /** @type {string} */ (description) };
  }).sort((a, b) => a.key.localeCompare(b.key));
  if (permissions.length > MAX_APP_PERMISSIONS) invalid("at most " + MAX_APP_PERMISSIONS + " permissions");
  const declared = new Set(permissions.map(p => p.key));
  const roles = Object.entries(manifest.roles).map(([key, role]) => {
    if (!isRoleKey(key)) invalid("role key " + JSON.stringify(key) + " must be lowercase letters, digits, - or _");
    if (!plainObject(role)) invalid("role " + key + " must be an object");
    const description = role.description ?? "";
    if (!isDescription(description)) invalid("description of role " + key + " must be text up to 200 characters");
    if (!Array.isArray(role.permissions)) invalid("role " + key + " needs a permissions array");
    for (const permission of role.permissions)
      if (!declared.has(permission)) invalid("role " + key + " uses undeclared permission " + JSON.stringify(permission));
    return { key, description, permissions: [...new Set(/** @type {string[]} */ (role.permissions))].sort() };
  }).sort((a, b) => a.key.localeCompare(b.key));
  if (roles.length > MAX_APP_ROLES) invalid("at most " + MAX_APP_ROLES + " roles");
  return { ...(manifest.accessMode ? { accessMode: manifest.accessMode } : {}), permissions, roles };
}

/** Current stored state of one application. @param {string} appId @returns {Statement[]} */
export function currentStateQueries(appId) {
  return [
    { sql: "SELECT id, access_mode AS accessMode FROM nathan_applications WHERE id=?", params: [appId] },
    { sql: "SELECT key, description, source FROM nathan_rbac_permissions WHERE app_id=? ORDER BY key", params: [appId] },
    { sql: "SELECT key, description, source FROM nathan_rbac_roles WHERE app_id=? ORDER BY key", params: [appId] },
    { sql: "SELECT role_key AS role, permission_key AS permission FROM nathan_rbac_role_permissions WHERE app_id=? ORDER BY role_key, permission_key", params: [appId] }
  ];
}
/** @param {any[][]} results */
export function currentState([apps, permissions, roles, links]) {
  return {
    app: apps[0] ? { id: apps[0].id, accessMode: apps[0].accessMode } : null,
    permissions: permissions.map(p => ({ key: p.key, description: p.description, source: p.source })),
    roles: roles.map(r => ({ key: r.key, description: r.description, source: r.source,
      permissions: links.filter(l => l.role === r.key).map(l => l.permission).sort() }))
  };
}

/**
 * @param {ReturnType<typeof currentState>} current
 * @param {Manifest} manifest
 * @param {{ prune?: boolean }} [options]
 * @returns {SyncOp[]}
 */
export function planSync(current, manifest, { prune = false } = {}) {
  if (!current.app) throw Error("Application is not registered in Nathan; register it in Identity Studio or with nathan protect first");
  /** @type {SyncOp[]} */
  const ops = [];
  const havePermissions = new Map(current.permissions.map(p => [p.key, p]));
  const haveRoles = new Map(current.roles.map(r => [r.key, r]));
  for (const permission of manifest.permissions) {
    const existing = havePermissions.get(permission.key);
    if (!existing || existing.description !== permission.description || existing.source !== "code")
      ops.push({ op: "permission.upsert", key: permission.key, description: permission.description });
  }
  for (const role of manifest.roles) {
    const existing = haveRoles.get(role.key);
    if (!existing || existing.description !== role.description || existing.source !== "code"
        || existing.permissions.join("\n") !== role.permissions.join("\n"))
      ops.push({ op: "role.upsert", key: role.key, description: role.description, permissions: role.permissions });
  }
  if (prune) {
    const wantRoles = new Set(manifest.roles.map(r => r.key));
    const wantPermissions = new Set(manifest.permissions.map(p => p.key));
    for (const role of current.roles)
      if (role.source === "code" && !wantRoles.has(role.key)) ops.push({ op: "role.delete", key: role.key });
    for (const permission of current.permissions)
      if (permission.source === "code" && !wantPermissions.has(permission.key)) ops.push({ op: "permission.delete", key: permission.key });
  }
  if (manifest.accessMode && manifest.accessMode !== current.app.accessMode)
    ops.push({ op: "access_mode", key: manifest.accessMode, accessMode: manifest.accessMode });
  return ops;
}

// ---- Write statements shared by Identity Studio and the CLI --------------------------------

/** @param {string} appId @param {string} key @param {string} description @param {"studio"|"code"} source @returns {Statement} */
export const permissionUpsert = (appId, key, description, source) => ({
  sql: "INSERT INTO nathan_rbac_permissions(app_id,key,description,source) VALUES (?,?,?,?) " +
    "ON CONFLICT(app_id,key) DO UPDATE SET description=excluded.description,source=excluded.source,updated_at=unixepoch()",
  params: [appId, key, description, source]
});
/** @param {string} appId @param {string} key @returns {Statement} */
export const permissionDelete = (appId, key) => ({ sql: "DELETE FROM nathan_rbac_permissions WHERE app_id=? AND key=?", params: [appId, key] });
/** Replaces the role's permission set. A failure part-way can only leave the role with fewer permissions.
 * @param {string} appId @param {string} key @param {string} description @param {string[]} permissions @param {"studio"|"code"} source @returns {Statement[]} */
export const roleUpsert = (appId, key, description, permissions, source) => [
  { sql: "INSERT INTO nathan_rbac_roles(app_id,key,description,source) VALUES (?,?,?,?) " +
      "ON CONFLICT(app_id,key) DO UPDATE SET description=excluded.description,source=excluded.source,updated_at=unixepoch()",
    params: [appId, key, description, source] },
  { sql: "DELETE FROM nathan_rbac_role_permissions WHERE app_id=? AND role_key=?", params: [appId, key] },
  ...permissions.map(permission => ({
    sql: "INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES (?,?,?)", params: [appId, key, permission]
  }))
];
/** @param {string} appId @param {string} key @returns {Statement} */
export const roleDelete = (appId, key) => ({ sql: "DELETE FROM nathan_rbac_roles WHERE app_id=? AND key=?", params: [appId, key] });
/** @param {string} appId @param {string} mode @returns {Statement} */
export const accessModeUpdate = (appId, mode) => ({
  sql: "UPDATE nathan_applications SET access_mode=?,updated_at=unixepoch() WHERE id=?", params: [mode, appId]
});

/**
 * Statements for a planned sync, each followed by its change-feed row, ending with one audit row.
 * @param {string} appId @param {SyncOp[]} ops @param {string} actor @returns {Statement[]}
 */
export function syncStatements(appId, ops, actor) {
  if (!ops.length) return [];
  /** @type {Statement[]} */
  const statements = [];
  for (const op of ops) {
    if (op.op === "permission.upsert") statements.push(permissionUpsert(appId, op.key, op.description ?? "", "code"));
    else if (op.op === "permission.delete") statements.push(permissionDelete(appId, op.key));
    else if (op.op === "role.upsert") statements.push(...roleUpsert(appId, op.key, op.description ?? "", op.permissions ?? [], "code"));
    else if (op.op === "role.delete") statements.push(roleDelete(appId, op.key));
    else if (op.op === "access_mode") statements.push(accessModeUpdate(appId, op.key));
    else throw Error("Unknown RBAC sync operation");
    const kind = op.op === "access_mode" ? "app.access_mode" : op.op.replace(/\.(upsert|delete)$/, m => m === ".upsert" ? ".upserted" : ".deleted");
    statements.push(changeStatement({ kind, appId, detail: { key: op.key, source: "code" }, actor }));
  }
  statements.push(auditStatement(actor, "rbac_manifest_sync", appId, "succeeded"));
  return statements;
}
