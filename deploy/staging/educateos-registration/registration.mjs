import { applicationStatusChange, committedStatements, newRoleGrant, planMcpRegister } from "../../../src/shared/admin-ops.mjs";
import { isSubjectId } from "../../../src/shared/policy.mjs";
import { auditStatement, changeStatement } from "../../../src/shared/rbac-store.mjs";
import { planSync, syncStatements, validateManifest } from "../../../src/shared/rbac-manifest.mjs";

export const account = "c07a7e704db1808e1fff91bed2b1cd49";
const database = "6ee7794d-d20d-4b7b-8518-984b8efe26e6";
const app = "educateos-staging";
const hostname = "staging.educateos.io";
const role = "teacher";
const actor = "cli:" + account;
export const issuer = "https://nathan-stg.gmac.io";
export const resource = "https://staging.educateos.io/mcp";
export const callback = "http://127.0.0.1:33418/callback";
const serverName = "EducateOS Staging";
const permissions = {
  "lms:read": "Read courses and lessons",
  "lms:draft": "Draft course content",
  "lms:write": "Publish and change course content",
  "mcp:tools": "Use EducateOS MCP tools"
};
const scopes = {
  "lms:read": { label: "Read courses", description: "Read courses and lessons.", group: "lms" },
  "lms:draft": { label: "Draft content", description: "Draft course content.", group: "lms", requires: ["lms:read"] },
  "lms:write": { label: "Publish content", description: "Publish and change course content.", group: "lms", sensitive: true },
  "mcp:tools": { label: "Use tools", description: "Use EducateOS MCP tools.", group: "mcp" }
};
const keys = Object.keys(permissions).sort();
const manifest = validateManifest({permissions, roles:{teacher:{description:"Teacher", permissions:keys}}});
const sql = (sql, ...params) => ({sql, params});
const userEligible = 'EXISTS (SELECT 1 FROM "user" WHERE id=? AND "emailVerified"=1 AND COALESCE(banned,0)=0)';
const targets = userId => [app, resource + " app=" + app, app + ":" + role + ":user:" + userId];
const fresh = userEligible + `
  AND NOT EXISTS (SELECT 1 FROM nathan_applications WHERE id=? OR hostname=?)
  AND NOT EXISTS (SELECT 1 FROM "oauthResource" WHERE identifier=?)
  AND NOT EXISTS (SELECT 1 FROM nathan_token_audiences WHERE identifier=?)
  AND NOT EXISTS (SELECT 1 FROM nathan_mcp_resources WHERE identifier=?)
  AND NOT EXISTS (SELECT 1 FROM nathan_security_audit WHERE target IN (?,?,?))`;
const freshParams = userId => [userId,app,hostname,resource,resource,resource,...targets(userId)];
const reconcile = () => Error("Staging registration needs reconciliation");
const equalList = (a,b) => Array.isArray(a) && a.length === b.length && a.every((v,i) => v === b[i]);

async function readRegistration(api, userId, originalClientId) {
  const [state, apps, permRows, roles, links, grants, resources, catalog, audits, clients] = await api.batchDatabase(database, [
    sql("SELECT (" + fresh + ") AS fresh, " + userEligible + " AS eligible", ...freshParams(userId), userId),
    sql("SELECT hostname,enabled,access_mode FROM nathan_applications WHERE id=?",app),
    sql("SELECT key,description FROM nathan_rbac_permissions WHERE app_id=? ORDER BY key",app),
    sql("SELECT description FROM nathan_rbac_roles WHERE app_id=? AND key=?",app,role),
    sql("SELECT permission_key FROM nathan_rbac_role_permissions WHERE app_id=? AND role_key=? ORDER BY permission_key",app,role),
    sql("SELECT created_by FROM nathan_rbac_grants WHERE app_id=? AND role_key=? AND principal_type='user' AND principal_id=?",app,role,userId),
    sql("SELECT r.app_id,r.name,r.enabled,r.full_scope,r.aliases,a.app_id AS audience FROM nathan_mcp_resources r JOIN nathan_token_audiences a USING(identifier) WHERE r.identifier=?",resource),
    sql("SELECT scope,label,description,group_key,requires,sensitive,admin_only FROM nathan_mcp_scopes WHERE resource=? ORDER BY scope",resource),
    sql("SELECT DISTINCT action,target,outcome FROM nathan_security_audit WHERE actor=? AND target IN (?,?,?)",actor,...targets(userId)),
    sql("SELECT redirect_uris FROM nathan_mcp_clients WHERE client_id=? AND expires_at>unixepoch()",originalClientId)
  ]);
  if (state[0]?.eligible !== 1) throw Error("Staging teacher is missing, unverified or suspended");
  if (state[0].fresh === 1) return null;
  const a = apps[0], r = resources[0];
  if (a?.hostname !== hostname || a.enabled !== 1 || a.access_mode !== "approved" ||
      roles[0]?.description !== "Teacher" || grants[0]?.created_by !== actor ||
      r?.app_id !== app || r.audience !== app || r.name !== serverName || r.enabled !== 1 ||
      r.full_scope !== null || Object.keys(JSON.parse(r.aliases)).length !== 0 ||
      !equalList(permRows.map(p => p.key), keys) || permRows.some(p => p.description !== permissions[p.key]) ||
      !equalList(links.map(p => p.permission_key), keys) || !equalList(catalog.map(s => s.scope), keys)) throw reconcile();
  for (const row of catalog) {
    const expected = scopes[row.scope];
    if (row.label !== expected.label || row.description !== expected.description || row.group_key !== expected.group ||
        row.sensitive !== Number(expected.sensitive === true) || row.admin_only !== 0 ||
        !equalList(JSON.parse(row.requires), expected.requires ?? [])) throw reconcile();
  }
  const [appTarget, resourceTarget, grantTarget] = targets(userId);
  const actions = {app_manifest_apply:appTarget, rbac_manifest_sync:appTarget, application_enable:appTarget,
    mcp_resource_register:resourceTarget, rbac_grant_create:grantTarget};
  for (const [action,target] of Object.entries(actions)) {
    for (const outcome of ["attempted","succeeded"]) {
      if (!audits.some(a => a.action === action && a.target === target && a.outcome === outcome)) throw reconcile();
    }
  }
  if (clients.length && !equalList(JSON.parse(clients[0].redirect_uris),[callback])) throw Error("Original public client callback mismatch");
  return {app, role, resource, userId, permissions:keys, sensitiveScopes:["lms:write"], actor,
    auditedActions:Object.keys(actions), originalClientActive:clients.length === 1};
}

export async function applyAndVerify(api, userId, originalClientId) {
  if (!isSubjectId(userId) || !/^nmcp_[A-Za-z0-9_-]{1,160}$/.test(originalClientId)) throw Error("Invalid staging registration configuration");
  const db = await api.databaseNamed("nathan-stg-auth");
  if ((db?.uuid ?? db?.id) !== database) throw Error("Staging D1 identity mismatch");
  const prior = await readRegistration(api, userId, originalClientId);
  if (prior) return prior;

  const reader = {all:(s,params) => api.queryDatabase(database,s,params)};
  const mcp = await planMcpRegister(reader, {app,identifier:resource,name:serverName,scopes}, issuer, actor, {permissionKeys:keys});
  const ops = planSync({app:{id:app,accessMode:"approved"}, permissions:[], roles:[]}, manifest);
  const enable = applicationStatusChange(app,true);
  const grant = newRoleGrant(app,role,"user",userId,actor);
  const attempted = plan => auditStatement(actor, plan.action, plan.target, "attempted");
  // D1 runs this batch as one transaction. A failed precondition violates the
  // audit table's NOT NULL primary key and rolls back every statement. This
  // fences concurrent instances and closes the gap after the planning reads.
  const claim = sql("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) SELECT CASE WHEN " +
    fresh + " THEN ? ELSE NULL END,?,'app_manifest_apply',?,'attempted'",
    ...freshParams(userId), "educateos-staging-registration-2026-11-24", actor, app);
  try {
    await api.batchDatabase(database, [
      claim, auditStatement(actor,"rbac_manifest_sync",app,"attempted"),
      sql("INSERT INTO nathan_applications(id,hostname,roles,enabled) VALUES (?,?,'[]',0)",app,hostname),
      changeStatement({kind:"app.registered",appId:app,actor}), auditStatement(actor,"application_upsert",app,"succeeded"),
      ...syncStatements(app,ops,actor), attempted(mcp), ...committedStatements(mcp,actor),
      attempted(enable), ...committedStatements(enable,actor), auditStatement(actor,"app_manifest_apply",app,"succeeded"),
      attempted(grant), ...committedStatements(grant,actor)
    ]);
  } catch {
    const recovered = await readRegistration(api, userId, originalClientId);
    if (recovered) return recovered;
    throw Error("Staging D1 batch did not commit");
  }
  const receipt = await readRegistration(api, userId, originalClientId);
  if (!receipt) throw reconcile();
  return receipt;
}
