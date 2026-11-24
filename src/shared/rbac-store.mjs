/**
 * Storage contract for Nathan's minimal RBAC (migration 0011). Plain SQL with positional
 * parameters so the identity Worker (D1), the CLI (D1 REST API) and the node:sqlite tests
 * run the very same statements, and pure row mappers that feed the one evaluator.
 */
import { evaluateAccess } from "./policy.mjs";

/** @typedef {{ sql: string, params: unknown[] }} Statement */

const GRANTS_FOR_USER =
  "((principal_type='user' AND principal_id=?) OR " +
  "(principal_type='group' AND principal_id IN (SELECT group_id FROM nathan_group_members WHERE user_id=?)))";

/** Current admissions that have been withdrawn, including those with an independently owned grant. */
export const INACTIVE_PROVISIONS =
  "SELECT p.app_id FROM nathan_app_provisions p WHERE p.user_id=? AND NOT EXISTS " +
  "(SELECT 1 FROM nathan_active_app_provisions a WHERE a.app_id=p.app_id AND a.user_id=p.user_id)";

export const revokedMembership = () => ({ allowed: false, reason: "app_membership_revoked", roles: [], permissions: [] });

/** The five reads that make one evaluator input. Run them in one D1 batch (one snapshot).
 * @param {string} appId @param {string} userId @returns {Statement[]} */
export function accessQueries(appId, userId) {
  return [
    { sql: "SELECT id, enabled, access_mode AS accessMode FROM nathan_applications WHERE id=?", params: [appId] },
    { sql: 'SELECT "id" AS id, "email" AS email, "banned" AS banned FROM "user" WHERE "id"=?', params: [userId] },
    { sql: "SELECT m.group_id AS id FROM nathan_group_members m JOIN nathan_groups g ON g.id=m.group_id WHERE m.user_id=? ORDER BY m.group_id", params: [userId] },
    { sql: "SELECT role_key AS role, principal_type AS principalType, principal_id AS principalId FROM nathan_rbac_grants WHERE app_id=? AND " + GRANTS_FOR_USER,
      params: [appId, userId, userId] },
    { sql: "SELECT r.key AS key, rp.permission_key AS permission FROM nathan_rbac_roles r LEFT JOIN nathan_rbac_role_permissions rp " +
      "ON rp.app_id=r.app_id AND rp.role_key=r.key WHERE r.app_id=? ORDER BY r.key, rp.permission_key", params: [appId] }
  ];
}

/** @param {any} value */
const truthy = value => value === 1 || value === true || value === "1";

/** @param {any} row */
export function appState(row) {
  return row ? { id: row.id, enabled: truthy(row.enabled), accessMode: row.accessMode } : null;
}
/** Better Auth stores `banned` as 1/0/null. A set ban flag always blocks (fail closed), even if
 * `banExpires` has passed: Better Auth only lifts an expired ban at the user's next sign-in.
 * @param {any} row */
export function userState(row) {
  return row ? { id: row.id, banned: truthy(row.banned) } : null;
}
/** @param {{key:string, permission:string|null}[]} rows */
export function roleDefinitions(rows) {
  /** @type {Map<string,string[]>} */
  const roles = new Map();
  for (const row of rows) {
    if (!roles.has(row.key)) roles.set(row.key, []);
    if (row.permission) roles.get(row.key)?.push(row.permission);
  }
  return [...roles].map(([key, permissions]) => ({ key, permissions }));
}

/**
 * Turns the results of {@link accessQueries} into an evaluator input.
 * @param {[any[], any[], any[], any[], any[]]} results rows of each query, in order
 */
export function accessInputFromRows([apps, users, groups, grants, roles]) {
  return {
    app: appState(apps[0]),
    user: userState(users[0]),
    groups: groups.map(g => g.id),
    grants: grants.map(g => ({ role: g.role, principalType: g.principalType, principalId: g.principalId })),
    roles: roleDefinitions(roles)
  };
}

/** @param {[any[], any[], any[], any[], any[]]} results */
export function decideFromRows(results) {
  return evaluateAccess(accessInputFromRows(results));
}

/** Reads behind the directory view of one user. Run them in one D1 batch.
 * @param {string} userId @returns {Statement[]} */
export function directoryQueries(userId) {
  const appsWithGrants = "SELECT app_id FROM nathan_rbac_grants WHERE " + GRANTS_FOR_USER;
  return [
    { sql: 'SELECT "id" AS id, "email" AS email, "banned" AS banned FROM "user" WHERE "id"=?', params: [userId] },
    { sql: "SELECT g.id AS id, g.name AS name, g.source AS source FROM nathan_group_members m JOIN nathan_groups g ON g.id=m.group_id WHERE m.user_id=? ORDER BY g.id", params: [userId] },
    { sql: "SELECT app_id AS app, role_key AS role, principal_type AS principalType, principal_id AS principalId FROM nathan_rbac_grants WHERE " + GRANTS_FOR_USER + " ORDER BY app_id, role_key, principal_type, principal_id",
      params: [userId, userId] },
    { sql: "SELECT id, enabled, access_mode AS accessMode FROM nathan_applications WHERE access_mode='any_signed_in' OR id IN (" + appsWithGrants +
      ") OR id IN (SELECT app_id FROM nathan_app_provisions WHERE user_id=?) ORDER BY id LIMIT 500", params: [userId, userId, userId] },
    { sql: "SELECT r.app_id AS app, r.key AS key, rp.permission_key AS permission FROM nathan_rbac_roles r LEFT JOIN nathan_rbac_role_permissions rp " +
      "ON rp.app_id=r.app_id AND rp.role_key=r.key WHERE r.app_id IN (" + appsWithGrants + ") ORDER BY r.app_id, r.key, rp.permission_key",
      params: [userId, userId] },
    { sql: "SELECT MAX(COALESCE((SELECT MAX(seq) FROM nathan_rbac_changes),0),(SELECT pruned_through FROM nathan_rbac_feed_state WHERE id='primary')) AS cursor", params: [] },
    { sql: INACTIVE_PROVISIONS, params: [userId] }
  ];
}

/** Issuer-qualified subject used by the directory API and Gatekeeper: `<issuer>#<sub>`.
 * @param {string} issuer e.g. https://login.example.com/api/auth @param {string} sub */
export const qualifiedSubject = (issuer, sub) => issuer + "#" + sub;
/** @param {string} issuer @param {unknown} value @returns {string|null} the Nathan user id */
export function parseQualifiedSubject(issuer, value) {
  if (typeof value !== "string" || !value.startsWith(issuer + "#")) return null;
  const sub = value.slice(issuer.length + 1);
  return sub.length > 0 && sub.length <= 256 && !/[\x00-\x1f\x7f]/.test(sub) ? sub : null;
}

/**
 * The directory view of one principal, computed with the same evaluator as the gateway.
 * @param {{ issuer: string, observedAt: string, results: any[][] }} input results of {@link directoryQueries}
 */
export function directoryView({ issuer, observedAt, results }) {
  const [users, groups, grants, apps, roles, watermark, inactive] = results;
  const user = userState(users[0]);
  if (!user) return null;
  const groupIds = groups.map(g => g.id);
  const revoked = new Set(inactive.map(p => p.app_id));
  /** @type {Record<string, any>} */
  const applications = {};
  for (const row of apps) {
    const app = appState(row);
    if (!app) continue;
    const decision = revoked.has(app.id) ? revokedMembership() : evaluateAccess({
      app, user, groups: groupIds,
      grants: grants.filter(g => g.app === app.id).map(g => ({ role: g.role, principalType: g.principalType, principalId: g.principalId })),
      roles: roleDefinitions(roles.filter(r => r.app === app.id))
    });
    applications[app.id] = { enabled: app.enabled, accessMode: app.accessMode, ...decision };
  }
  return {
    subject: qualifiedSubject(issuer, user.id), issuer, sub: user.id,
    email: users[0].email ?? null, active: !user.banned,
    groups: groups.map(g => ({ id: g.id, name: g.name, source: g.source })),
    grants: grants.map(g => ({ app: g.app, role: g.role, via: { type: g.principalType, id: g.principalId } })),
    applications,
    observedAt,
    cursor: String(watermark[0]?.cursor ?? 0)
  };
}

/** Change-feed row written in the same batch as each RBAC write.
 * @param {{ kind: string, appId?: string|null, principalType?: "user"|"group"|null, principalId?: string|null, detail?: object, actor: string }} change
 * @returns {Statement} */
export function changeStatement({ kind, appId = null, principalType = null, principalId = null, detail = {}, actor }) {
  return {
    sql: "INSERT INTO nathan_rbac_changes(kind,app_id,principal_type,principal_id,detail,actor) VALUES (?,?,?,?,?,?)",
    params: [kind, appId, principalType, principalId, JSON.stringify(detail), actor]
  };
}
/** @param {string} actor @param {string} action @param {string} target @param {string} outcome @returns {Statement} */
export function auditStatement(actor, action, target, outcome) {
  return {
    sql: "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)",
    params: [crypto.randomUUID(), actor, action, target, outcome]
  };
}

/** Change-feed page. `pruned` is the feed watermark: a cursor below it must resync.
 * @param {number} cursor @param {number} limit @returns {Statement[]} */
export function changeQueries(cursor, limit) {
  return [
    { sql: "SELECT pruned_through AS pruned FROM nathan_rbac_feed_state WHERE id='primary'", params: [] },
    { sql: "SELECT seq, kind, app_id AS app, principal_type AS principalType, principal_id AS principalId, detail, created_at AS createdAt " +
      "FROM nathan_rbac_changes WHERE seq>? ORDER BY seq LIMIT ?", params: [cursor, limit + 1] }
  ];
}
/** @param {{ issuer: string, observedAt: string, cursor: number, limit: number, results: any[][] }} input */
export function changePage({ issuer, observedAt, cursor, limit, results }) {
  const pruned = Number(results[0][0]?.pruned ?? 0);
  if (cursor < pruned) return { resync: true, cursor: String(pruned), observedAt };
  const rows = results[1];
  const page = rows.slice(0, limit);
  return {
    changes: page.map(row => {
      /** @type {any} */
      let detail = {};
      try { detail = JSON.parse(row.detail); } catch {}
      return {
        seq: String(row.seq), kind: row.kind, app: row.app ?? null,
        principal: row.principalType ? {
          type: row.principalType, id: row.principalId,
          ...(row.principalType === "user" ? { subject: qualifiedSubject(issuer, row.principalId) } : {})
        } : null,
        detail, at: new Date(Number(row.createdAt) * 1000).toISOString()
      };
    }),
    cursor: String(page.length ? page[page.length - 1].seq : cursor),
    hasMore: rows.length > limit,
    observedAt
  };
}

/** Retention for the change feed; older entries are pruned and their consumers must resync. */
export const CHANGE_RETENTION_SECONDS = 30 * 24 * 3600;
/** @returns {Statement[]} */
export function pruneChangeStatements() {
  return [
    { sql: "UPDATE nathan_rbac_feed_state SET pruned_through=MAX(pruned_through,COALESCE((SELECT MAX(seq) FROM nathan_rbac_changes WHERE created_at < unixepoch()-?),0)) WHERE id='primary'",
      params: [CHANGE_RETENTION_SECONDS] },
    { sql: "DELETE FROM nathan_rbac_changes WHERE seq <= (SELECT pruned_through FROM nathan_rbac_feed_state WHERE id='primary')", params: [] }
  ];
}
