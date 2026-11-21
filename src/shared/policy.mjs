/**
 * Nathan's one access evaluator (NATH-13). Pure and runtime independent: the gateway's
 * RPC, the directory API for Gatekeeper and the SDK's service-binding path all call it,
 * so every path gives the same answer for the same stored state.
 *
 * Minimal RBAC only: applications declare permission strings, roles bundle permissions,
 * roles are granted per application to users or groups. No conditions, policy language or
 * approvals; those belong to Gatekeeper.
 */

/** NATH-1 access modes. "approved": only users/groups with a grant (no grants = nobody).
 * "any_signed_in": every active signed-in user, an explicit administrator choice. */
export const ACCESS_MODES = Object.freeze(["approved", "any_signed_in"]);

const APP_ID = /^[a-z][a-z0-9-]{0,62}$/;
const ROLE_KEY = /^[a-z][a-z0-9_-]{0,62}$/;
const GROUP_ID = /^[a-z][a-z0-9_-]{0,79}$/;
const PERMISSION_SEGMENT = "[a-z][a-z0-9_.-]*";
const PERMISSION_KEY = new RegExp("^" + PERMISSION_SEGMENT + "(?::" + PERMISSION_SEGMENT + ")*$");

/** @param {unknown} value */
export const isAppId = value => typeof value === "string" && APP_ID.test(value);
/** @param {unknown} value */
export const isRoleKey = value => typeof value === "string" && ROLE_KEY.test(value);
/** @param {unknown} value */
export const isGroupId = value => typeof value === "string" && GROUP_ID.test(value);
/** Permission keys look like `invoices:write`: lowercase segments separated by colons, no wildcards.
 * @param {unknown} value */
export const isPermissionKey = value => typeof value === "string" && value.length <= 128 && PERMISSION_KEY.test(value);
/** @param {unknown} value */
export const isSubjectId = value => typeof value === "string" && value.length > 0 && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value);

/**
 * @typedef {"approved"|"any_signed_in"} AccessMode
 * @typedef {{ id: string, enabled: boolean, accessMode: AccessMode }} AppState
 * @typedef {{ id: string, banned: boolean }} UserState
 * @typedef {{ role: string, principalType: "user"|"group", principalId: string }} Grant
 * @typedef {{ key: string, permissions: string[] }} RoleDefinition
 * @typedef {{ app: AppState|null, user: UserState|null, groups: string[], grants: Grant[], roles: RoleDefinition[] }} AccessInput
 * @typedef {"granted"|"signed_in"|"no_grant"|"unknown_app"|"unknown_user"|"app_disabled"|"user_blocked"|"invalid_input"} AccessReason
 * @typedef {{ allowed: boolean, reason: AccessReason, roles: string[], permissions: string[] }} AccessDecision
 */

/** @param {AccessReason} reason @returns {AccessDecision} */
const deny = reason => ({ allowed: false, reason, roles: [], permissions: [] });
/** @param {any} value */
const isObject = value => Boolean(value) && typeof value === "object" && !Array.isArray(value);
/** @param {any} app */
const validApp = app => isObject(app) && isAppId(app.id) && typeof app.enabled === "boolean" && ACCESS_MODES.includes(app.accessMode);
/** @param {any} user */
const validUser = user => isObject(user) && isSubjectId(user.id) && typeof user.banned === "boolean";
/** @param {any} grant */
const validGrant = grant => isObject(grant) && typeof grant.role === "string"
  && (grant.principalType === "user" || grant.principalType === "group") && typeof grant.principalId === "string";
/** @param {any} role */
const validRole = role => isObject(role) && isRoleKey(role.key)
  && Array.isArray(role.permissions) && role.permissions.every(isPermissionKey);

/**
 * Decides whether a user may use an application and with which roles and permissions.
 * Deny by default; a blocked user, disabled app, unknown app or user, or malformed input
 * always denies with empty roles and permissions.
 * @param {AccessInput} input
 * @returns {AccessDecision}
 */
export function evaluateAccess(input) {
  if (!isObject(input)) return deny("invalid_input");
  const { app, user, groups, grants, roles } = input;
  if (app === null) return deny("unknown_app");
  if (!validApp(app)) return deny("invalid_input");
  if (user === null) return deny("unknown_user");
  if (!validUser(user)) return deny("invalid_input");
  if (!Array.isArray(groups) || !groups.every(g => typeof g === "string")) return deny("invalid_input");
  if (!Array.isArray(grants) || !grants.every(validGrant)) return deny("invalid_input");
  if (!Array.isArray(roles) || !roles.every(validRole)) return deny("invalid_input");
  if (!app.enabled) return deny("app_disabled");
  if (user.banned) return deny("user_blocked");

  const memberOf = new Set(groups);
  const definitions = new Map(roles.map(role => [role.key, role.permissions]));
  const granted = new Set();
  for (const grant of grants) {
    if (!definitions.has(grant.role)) continue;
    const applies = grant.principalType === "user" ? grant.principalId === user.id : memberOf.has(grant.principalId);
    if (applies) granted.add(grant.role);
  }
  if (granted.size === 0)
    return app.accessMode === "any_signed_in" ? { allowed: true, reason: "signed_in", roles: [], permissions: [] } : deny("no_grant");
  const permissions = new Set();
  for (const role of granted) for (const permission of definitions.get(role) ?? []) permissions.add(permission);
  return { allowed: true, reason: "granted", roles: [...granted].sort(), permissions: [...permissions].sort() };
}
