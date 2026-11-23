/**
 * NATH-13: roles and minimal RBAC in the identity Worker. Reads go through the one evaluator in
 * src/shared/policy.mjs; every Identity Studio write is admin-only (checked by the caller), audited
 * and recorded in the change feed in the same D1 batch.
 */
import type { AuthEnv } from "./env";
import { audit } from "./admin-service";
import { ACCESS_MODES, isAppId, isGroupId, isPermissionKey, isRoleKey, isSubjectId } from "../shared/policy.mjs";
import { accessQueries, decideFromRows, directoryQueries, directoryView, changeQueries, changePage,
  changeStatement, auditStatement, pruneChangeStatements, parseQualifiedSubject } from "../shared/rbac-store.mjs";
import { validateManifest, currentStateQueries, currentState, planSync, syncStatements, permissionUpsert,
  permissionDelete, roleUpsert, roleDelete, accessModeUpdate, isDescription, MAX_APP_PERMISSIONS, MAX_APP_ROLES } from "../shared/rbac-manifest.mjs";
import * as adminOps from "../shared/admin-ops.mjs";

type Statement = { sql: string; params: unknown[] };
export type AccessResult = { allowed: boolean; reason: string; roles: string[]; permissions: string[]; email: string | null; observedAt: string };

const MAX_GROUPS = 500;
const prepare = (env: AuthEnv, s: Statement) => env.DB.prepare(s.sql).bind(...s.params);
async function read(env: AuthEnv, statements: Statement[]): Promise<any[][]> {
  const results = await env.DB.batch(statements.map(s => prepare(env, s)));
  return results.map(r => (r.results ?? []) as any[]);
}
export function issuerOf(env: AuthEnv) {
  return new URL(env.NATHAN_ISSUER).origin + "/api/auth";
}

/** Effective access of a Nathan user (OIDC `sub` of a public-subject client) to one application. */
export async function resolveAccess(env: AuthEnv, applicationId: unknown, subject: unknown): Promise<AccessResult> {
  const observedAt = new Date().toISOString();
  if (!isAppId(applicationId) || !isSubjectId(subject))
    return { allowed: false, reason: "invalid_input", roles: [], permissions: [], email: null, observedAt };
  const rows = await read(env, accessQueries(applicationId as string, subject as string));
  const decision = decideFromRows(rows as any);
  return { ...decision, email: decision.allowed ? rows[1][0]?.email ?? null : null, observedAt };
}

/** Directory view of a principal keyed by `<issuer>#<sub>`; null when the subject is unknown. */
export async function directoryPrincipal(env: AuthEnv, subjectKey: unknown) {
  const issuer = issuerOf(env);
  const userId = parseQualifiedSubject(issuer, subjectKey);
  if (!userId) return null;
  return directoryView({ issuer, observedAt: new Date().toISOString(), results: await read(env, directoryQueries(userId)) });
}
export async function directoryChanges(env: AuthEnv, cursorInput: unknown, limitInput: unknown) {
  const cursor = cursorInput === undefined || cursorInput === null || cursorInput === "" ? 0 : Number(cursorInput);
  const limit = limitInput === undefined || limitInput === null || limitInput === "" ? 100 : Number(limitInput);
  if (!Number.isSafeInteger(cursor) || cursor < 0) throw Error("Invalid cursor");
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw Error("Invalid limit");
  return changePage({ issuer: issuerOf(env), observedAt: new Date().toISOString(), cursor, limit, results: await read(env, changeQueries(cursor, limit)) });
}
export async function pruneRbacChanges(env: AuthEnv) {
  await env.DB.batch(pruneChangeStatements().map(s => prepare(env, s)));
}

// ---- Identity Studio reads ---------------------------------------------------------------------

export async function rbacOverview(env: AuthEnv, appId: unknown) {
  if (!isAppId(appId)) throw Error("Invalid application id");
  const [apps, permissions, roles, links, grants] = await read(env, [
    { sql: "SELECT id, hostname, enabled, access_mode AS accessMode FROM nathan_applications WHERE id=?", params: [appId] },
    ...currentStateQueries(appId as string).slice(1),
    { sql: "SELECT g.id, g.role_key AS role, g.principal_type AS principalType, g.principal_id AS principalId, g.created_by AS createdBy, g.created_at AS createdAt, " +
        "CASE g.principal_type WHEN 'user' THEN (SELECT \"email\" FROM \"user\" WHERE \"id\"=g.principal_id) ELSE (SELECT name FROM nathan_groups WHERE id=g.principal_id) END AS label " +
        "FROM nathan_rbac_grants g WHERE g.app_id=? ORDER BY g.role_key, g.principal_type, label LIMIT 1000", params: [appId] }
  ]);
  if (!apps[0]) throw Error("Unknown application");
  const state = currentState([apps, permissions, roles, links]);
  return {
    app: { id: apps[0].id, hostname: apps[0].hostname, enabled: apps[0].enabled === 1, accessMode: apps[0].accessMode },
    permissions: state.permissions, roles: state.roles, grants
  };
}
export async function listGroups(env: AuthEnv) {
  const [groups] = await read(env, [{
    sql: "SELECT g.id, g.name, g.description, g.source, (SELECT count(*) FROM nathan_group_members m WHERE m.group_id=g.id) AS members " +
      "FROM nathan_groups g ORDER BY g.id LIMIT ?", params: [MAX_GROUPS]
  }]);
  return { groups };
}
export async function groupMembers(env: AuthEnv, groupId: unknown) {
  if (!isGroupId(groupId)) throw Error("Invalid group id");
  const [groups, members] = await read(env, [
    { sql: "SELECT id, name, description, source FROM nathan_groups WHERE id=?", params: [groupId] },
    { sql: 'SELECT m.user_id AS userId, u."email" AS email, m.added_by AS addedBy, m.created_at AS createdAt FROM nathan_group_members m ' +
        'JOIN "user" u ON u."id"=m.user_id WHERE m.group_id=? ORDER BY u."email" LIMIT 1000', params: [groupId] }
  ]);
  if (!groups[0]) throw Error("Unknown group");
  return { group: groups[0], members };
}

// ---- Identity Studio writes --------------------------------------------------------------------

type Change = Parameters<typeof changeStatement>[0];
/** Errors already audited as "failed" by a commit; anything else thrown is a rejection before commit. */
const auditedFailures = new WeakSet<object>();
async function auditFailure(env: AuthEnv, actor: string, action: string, target: string, error: unknown) {
  await audit(env, actor, action, target, "failed").catch(() => {});
  if (error && typeof error === "object") auditedFailures.add(error);
}
/** One atomic batch: the change, its change-feed row and the success audit. A failure is audited separately. */
async function commit(env: AuthEnv, actor: string, action: string, target: string, statements: Statement[], change: Omit<Change, "actor">) {
  try {
    await env.DB.batch([...statements, changeStatement({ ...change, actor }), auditStatement(actor, action, target, "succeeded")].map(s => prepare(env, s)));
  } catch (error) {
    await auditFailure(env, actor, action, target, error);
    throw error;
  }
}
/** The shared admin operations (src/shared/admin-ops.mjs) read through the D1 binding. */
export const d1Reader = (env: AuthEnv) => ({
  all: async (sql: string, params: unknown[]) => ((await env.DB.prepare(sql).bind(...params).all()).results ?? []) as any[]
});
const requireApp = (env: AuthEnv, appId: unknown) => adminOps.requireApp(d1Reader(env), appId);
async function count(env: AuthEnv, sql: string, ...params: unknown[]) {
  return Number((await env.DB.prepare(sql).bind(...params).first<{ n: number }>())?.n ?? 0);
}
const userByEmail = (env: AuthEnv, email: unknown) => adminOps.userByEmail(d1Reader(env), email);
const requireGroup = (env: AuthEnv, groupId: unknown, options: { editable?: boolean } = {}) => adminOps.requireGroup(d1Reader(env), groupId, options);
const description = (value: unknown) => {
  const text = value ?? "";
  if (!isDescription(text)) throw Error("Description must be text up to 200 characters");
  return text as string;
};

export const RBAC_OPERATIONS = adminOps.RBAC_OPERATIONS;
const auditAction = adminOps.rbacAuditAction;
const attemptTarget = adminOps.rbacAttemptTarget;

/**
 * Applies one administrator RBAC operation. The caller must already have verified an enrolled,
 * stepped-up administrator session (isAdminPrincipal + mayAdminister) and same-origin JSON.
 * Every outcome is audited: "succeeded" or "failed" with the commit, "rejected" when validation
 * refuses the attempt before anything is written.
 */
export async function applyRbacOperation(env: AuthEnv, body: any, actor: string): Promise<Record<string, unknown>> {
  try {
    return await applyOperation(env, body, actor);
  } catch (error) {
    if (!(error && typeof error === "object" && auditedFailures.has(error)))
      await audit(env, actor, auditAction(body?.op), attemptTarget(body), "rejected").catch(() => {});
    throw error;
  }
}
async function applyOperation(env: AuthEnv, body: any, actor: string): Promise<Record<string, unknown>> {
  const op = body?.op;
  if (!RBAC_OPERATIONS.includes(op)) throw Error("Unknown RBAC operation");

  if (op === "access_mode") {
    const app = await requireApp(env, body.app);
    if (!ACCESS_MODES.includes(body.accessMode)) throw Error("Invalid access mode");
    // Admitting every signed-in user is an explicit administrator choice (NATH-1).
    if (body.accessMode === "any_signed_in" && body.confirm !== "CONFIRM ANY SIGNED IN " + app)
      throw Error("Explicit confirmation required");
    await commit(env, actor, "rbac_access_mode", app + ":" + body.accessMode, [accessModeUpdate(app, body.accessMode)],
      { kind: "app.access_mode", appId: app, detail: { accessMode: body.accessMode } });
    return { app, accessMode: body.accessMode };
  }
  if (op === "permission.upsert") {
    const app = await requireApp(env, body.app);
    if (!isPermissionKey(body.key)) throw Error("Permission keys look like resource:action");
    const exists = await count(env, "SELECT count(*) AS n FROM nathan_rbac_permissions WHERE app_id=? AND key=?", app, body.key);
    if (!exists && await count(env, "SELECT count(*) AS n FROM nathan_rbac_permissions WHERE app_id=?", app) >= MAX_APP_PERMISSIONS)
      throw Error("Too many permissions");
    await commit(env, actor, "rbac_permission_upsert", app + ":" + body.key, [permissionUpsert(app, body.key, description(body.description), "studio")],
      { kind: "permission.upserted", appId: app, detail: { key: body.key } });
    return { app, permission: body.key };
  }
  if (op === "permission.delete") {
    const app = await requireApp(env, body.app);
    if (!isPermissionKey(body.key)) throw Error("Invalid permission key");
    await commit(env, actor, "rbac_permission_delete", app + ":" + body.key, [permissionDelete(app, body.key)],
      { kind: "permission.deleted", appId: app, detail: { key: body.key } });
    return { app, deleted: body.key };
  }
  if (op === "role.upsert") {
    const app = await requireApp(env, body.app);
    if (!isRoleKey(body.key)) throw Error("Role keys are lowercase letters, digits, - or _");
    if (!Array.isArray(body.permissions) || body.permissions.length > MAX_APP_PERMISSIONS || !body.permissions.every(isPermissionKey))
      throw Error("Invalid role permissions");
    const permissions = [...new Set(body.permissions as string[])].sort();
    const declared = (await env.DB.prepare("SELECT key FROM nathan_rbac_permissions WHERE app_id=?").bind(app).all<{ key: string }>())
      .results.map(r => r.key);
    if (permissions.some(p => !declared.includes(p))) throw Error("Declare each permission before adding it to a role");
    const exists = await count(env, "SELECT count(*) AS n FROM nathan_rbac_roles WHERE app_id=? AND key=?", app, body.key);
    if (!exists && await count(env, "SELECT count(*) AS n FROM nathan_rbac_roles WHERE app_id=?", app) >= MAX_APP_ROLES)
      throw Error("Too many roles");
    await commit(env, actor, "rbac_role_upsert", app + ":" + body.key, roleUpsert(app, body.key, description(body.description), permissions, "studio"),
      { kind: "role.upserted", appId: app, detail: { key: body.key, permissions } });
    return { app, role: body.key, permissions };
  }
  if (op === "role.delete") {
    const app = await requireApp(env, body.app);
    if (!isRoleKey(body.key)) throw Error("Invalid role key");
    if (body.confirm !== "CONFIRM DELETE ROLE " + app + "/" + body.key) throw Error("Explicit confirmation required");
    await commit(env, actor, "rbac_role_delete", app + ":" + body.key, [roleDelete(app, body.key)],
      { kind: "role.deleted", appId: app, detail: { key: body.key } });
    return { app, deleted: body.key, note: "Grants of this role were removed with it" };
  }
  if (op === "group.upsert") {
    if (!isGroupId(body.id)) throw Error("Group ids are lowercase letters, digits, - or _");
    if (typeof body.name !== "string" || !body.name.trim() || !isDescription(body.name) || body.name.length > 100) throw Error("Invalid group name");
    const exists = await count(env, "SELECT count(*) AS n FROM nathan_groups WHERE id=?", body.id);
    if (!exists && await count(env, "SELECT count(*) AS n FROM nathan_groups") >= MAX_GROUPS) throw Error("Too many groups");
    await commit(env, actor, "rbac_group_upsert", body.id, [{
      sql: "INSERT INTO nathan_groups(id,name,description,created_by) VALUES (?,?,?,?) " +
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,updated_at=unixepoch()",
      params: [body.id, body.name.trim(), description(body.description), actor]
    }], { kind: "group.upserted", principalType: "group", principalId: body.id });
    return { group: body.id };
  }
  if (op === "group.delete") {
    const group = await requireGroup(env, body.id);
    if (body.confirm !== "CONFIRM DELETE GROUP " + group) throw Error("Explicit confirmation required");
    await commit(env, actor, "rbac_group_delete", group, [
      { sql: "DELETE FROM nathan_rbac_grants WHERE principal_type='group' AND principal_id=?", params: [group] },
      { sql: "DELETE FROM nathan_groups WHERE id=?", params: [group] }
    ], { kind: "group.deleted", principalType: "group", principalId: group });
    return { deleted: group, note: "The group's memberships and grants were removed with it" };
  }
  if (op === "member.add") {
    const group = await requireGroup(env, body.group, { editable: true });
    const userId = await userByEmail(env, body.email);
    if (await count(env, "SELECT count(*) AS n FROM nathan_group_members WHERE group_id=? AND user_id=?", group, userId))
      return { group, userId, added: false, note: "Already a member" };
    await commit(env, actor, "rbac_member_add", group + ":" + userId, [{
      sql: "INSERT INTO nathan_group_members(group_id,user_id,added_by) VALUES (?,?,?)", params: [group, userId, actor]
    }], { kind: "member.added", principalType: "user", principalId: userId, detail: { group } });
    return { group, userId, added: true };
  }
  if (op === "member.remove") {
    const group = await requireGroup(env, body.group, { editable: true });
    const userId = isSubjectId(body.userId) ? body.userId as string : await userByEmail(env, body.email);
    await commit(env, actor, "rbac_member_remove", group + ":" + userId, [{
      sql: "DELETE FROM nathan_group_members WHERE group_id=? AND user_id=?", params: [group, userId]
    }], { kind: "member.removed", principalType: "user", principalId: userId, detail: { group } });
    return { group, userId, removed: true };
  }
  if (op === "grant.create" || op === "grant.revoke") {
    // Shared with the account-token CLI (`nathan rbac grant|revoke`): one validation, one statement set.
    const plan = op === "grant.create" ? await adminOps.planGrantCreate(d1Reader(env), body, actor) : await adminOps.planGrantRevoke(d1Reader(env), body);
    if (plan.statements) await commit(env, actor, plan.action, plan.target, plan.statements, plan.change as Omit<Change, "actor">);
    return plan.result;
  }
  // sync: the same plan the CLI uses, applied atomically through the D1 binding.
  const app = await requireApp(env, body.app);
  const manifest = validateManifest(body.manifest);
  const prune = body.prune === true;
  const ops = planSync(currentState(await read(env, currentStateQueries(app))), manifest, { prune });
  if (body.dryRun === true) return { app, dryRun: true, ops };
  if (prune && ops.some(o => o.op.endsWith(".delete")) && body.confirmPrune !== "CONFIRM PRUNE " + app)
    throw Error("Explicit confirmation required to prune");
  if (ops.some(o => o.op === "access_mode" && o.key === "any_signed_in") && body.confirm !== "CONFIRM ANY SIGNED IN " + app)
    throw Error("Explicit confirmation required for any-signed-in access");
  const statements = syncStatements(app, ops, actor);
  if (statements.length) {
    try { await env.DB.batch(statements.map(s => prepare(env, s))); }
    catch (error) { await auditFailure(env, actor, "rbac_manifest_sync", app, error); throw error; }
  }
  return { app, ops, applied: ops.length };
}
