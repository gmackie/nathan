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
/** One atomic batch: the change, its change-feed row and the success audit. A failure is audited separately. */
async function commit(env: AuthEnv, actor: string, action: string, target: string, statements: Statement[], change: Omit<Change, "actor">) {
  try {
    await env.DB.batch([...statements, changeStatement({ ...change, actor }), auditStatement(actor, action, target, "succeeded")].map(s => prepare(env, s)));
  } catch (error) {
    await audit(env, actor, action, target, "failed").catch(() => {});
    throw error;
  }
}
async function requireApp(env: AuthEnv, appId: unknown): Promise<string> {
  if (!isAppId(appId)) throw Error("Invalid application id");
  const row = await env.DB.prepare("SELECT id FROM nathan_applications WHERE id=?").bind(appId).first();
  if (!row) throw Error("Unknown application");
  return appId as string;
}
async function count(env: AuthEnv, sql: string, ...params: unknown[]) {
  return Number((await env.DB.prepare(sql).bind(...params).first<{ n: number }>())?.n ?? 0);
}
async function userByEmail(env: AuthEnv, email: unknown): Promise<string> {
  const value = String(email ?? "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || value.length > 254) throw Error("Select an existing user by exact email");
  const users = await env.DB.prepare('SELECT "id" AS id FROM "user" WHERE lower("email")=? LIMIT 2').bind(value).all<{ id: string }>();
  if (users.results.length !== 1) throw Error("User not found");
  return users.results[0].id;
}
async function requireGroup(env: AuthEnv, groupId: unknown, { editable = false } = {}) {
  if (!isGroupId(groupId)) throw Error("Invalid group id");
  const group = await env.DB.prepare("SELECT id, source FROM nathan_groups WHERE id=?").bind(groupId).first<{ id: string; source: string }>();
  if (!group) throw Error("Unknown group");
  // Extension point (NATH-11): SCIM-mapped groups are maintained by the directory, not by hand.
  if (editable && group.source === "scim") throw Error("Membership of SCIM-mapped groups is managed by the directory");
  return group.id;
}
const description = (value: unknown) => {
  const text = value ?? "";
  if (!isDescription(text)) throw Error("Description must be text up to 200 characters");
  return text as string;
};

export const RBAC_OPERATIONS = ["access_mode", "permission.upsert", "permission.delete", "role.upsert", "role.delete",
  "group.upsert", "group.delete", "member.add", "member.remove", "grant.create", "grant.revoke", "sync"] as const;

/**
 * Applies one administrator RBAC operation. The caller must already have verified an enrolled,
 * stepped-up administrator session (isAdminPrincipal + mayAdminister) and same-origin JSON.
 */
export async function applyRbacOperation(env: AuthEnv, body: any, actor: string): Promise<Record<string, unknown>> {
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
  if (op === "grant.create") {
    const app = await requireApp(env, body.app);
    if (!isRoleKey(body.role) || !await count(env, "SELECT count(*) AS n FROM nathan_rbac_roles WHERE app_id=? AND key=?", app, body.role))
      throw Error("Unknown role");
    let principalType: "user" | "group", principalId: string;
    if (body.principalType === "user") { principalType = "user"; principalId = await userByEmail(env, body.email); }
    else if (body.principalType === "group") { principalType = "group"; principalId = await requireGroup(env, body.group); }
    else throw Error("Grant a role to a user or a group");
    if (await count(env, "SELECT count(*) AS n FROM nathan_rbac_grants WHERE app_id=? AND role_key=? AND principal_type=? AND principal_id=?",
      app, body.role, principalType, principalId)) return { app, role: body.role, principalType, principalId, created: false, note: "Already granted" };
    const id = crypto.randomUUID();
    await commit(env, actor, "rbac_grant_create", app + ":" + body.role + ":" + principalType + ":" + principalId, [{
      sql: "INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES (?,?,?,?,?,?)",
      params: [id, app, body.role, principalType, principalId, actor]
    }], { kind: "grant.created", appId: app, principalType, principalId, detail: { role: body.role } });
    return { id, app, role: body.role, principalType, principalId, created: true };
  }
  if (op === "grant.revoke") {
    if (typeof body.id !== "string" || body.id.length > 200) throw Error("Invalid grant id");
    const grant = await env.DB.prepare("SELECT id, app_id AS app, role_key AS role, principal_type AS principalType, principal_id AS principalId FROM nathan_rbac_grants WHERE id=?")
      .bind(body.id).first<{ id: string; app: string; role: string; principalType: "user" | "group"; principalId: string }>();
    if (!grant) throw Error("Unknown grant");
    await commit(env, actor, "rbac_grant_revoke", grant.app + ":" + grant.role + ":" + grant.principalType + ":" + grant.principalId, [{
      sql: "DELETE FROM nathan_rbac_grants WHERE id=?", params: [grant.id]
    }], { kind: "grant.revoked", appId: grant.app, principalType: grant.principalType, principalId: grant.principalId, detail: { role: grant.role } });
    return { ...grant, revoked: true, note: "Nathan gateways stop honoring the grant within their access cache window (at most 60 s)" };
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
    catch (error) { await audit(env, actor, "rbac_manifest_sync", app, "failed").catch(() => {}); throw error; }
  }
  return { app, ops, applied: ops.length };
}
