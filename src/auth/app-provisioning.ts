import { WorkerEntrypoint } from "cloudflare:workers";
import { sha256 } from "../gateway/crypto";
import { isSubjectId } from "../shared/policy.mjs";
import { normalizeEmail } from "./admission-policy.mjs";
import { pinnedApplication, type BindingProps } from "./app-binding";
import type { AuthEnv } from "./env";
import { standaloneOrigins } from "./management-ingress";
import { allowRequests } from "./request-limit";

type Failure = { error: "invalid_input" | "not_configured" | "identity_conflict" | "stale_revision" | "rate_limited"; reason?: "verified_enterprise_domain" };
type ProvisionResult = { sub: string } | Failure;
type GrantsResult = { sub: string; revision: number; applied: boolean } | Failure;
const grantRoles = new Set(["member", "guardian", "staff", "driver", "platform_admin"]);
const configuredApp = "SELECT 1 FROM nathan_provisionable_apps WHERE id=? AND hostname=?";

async function authorize(env: AuthEnv, props: BindingProps): Promise<{ app: string; hostname: string } | Failure> {
  const app = pinnedApplication(props), origins = standaloneOrigins(env);
  if (!app || app !== env.NATHAN_APP_ID || !origins || env.NATHAN_INSTALL_ACTIVE !== "true")
    return { error: "not_configured" };
  if (!await allowRequests(env, "app-provision", app, 120)) return { error: "rate_limited" };
  return { app, hostname: new URL(origins.app).hostname };
}

const validId = (value: unknown): value is string => typeof value === "string" && isSubjectId(value) && value.trim() === value;
const externalKey = (app: string, id: string) => sha256(JSON.stringify([app,id]));
const subjectKey = (key: string, sub: string) => sha256(JSON.stringify([key,sub]));
const adminEmails = (env: AuthEnv) => String(env.NATHAN_ADMIN_EMAILS || "").split(",").map(normalizeEmail).filter(Boolean);

async function refuse(env: AuthEnv, app: string, action: string, error: Failure["error"]): Promise<Failure> {
  await env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,'unmatched',?)")
    .bind(crypto.randomUUID(), "app-provision:" + app, action, error).run();
  return { error };
}

/** A transaction rollback removes its success audit too. Bound the separate failure
 * receipt to one per application, operation and minute while storage is available. */
async function auditedBatch(db: D1Database, app: string, action: string, statements: D1PreparedStatement[]) {
  try {
    return await db.batch(statements);
  } catch (error) {
    await db.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) " +
      "SELECT ?1,?2,?3,'unmatched','failed' WHERE NOT EXISTS(SELECT 1 FROM nathan_security_audit " +
      "WHERE actor=?2 AND action=?3 AND outcome='failed' AND created_at>=unixepoch()-60)")
      .bind(crypto.randomUUID(), "app-provision:" + app, action).run().catch(() => {});
    throw error;
  }
}

async function admit(env: AuthEnv, app: string, hostname: string, key: string, email: string): Promise<ProvisionResult> {
  const db = env.DB, candidate = crypto.randomUUID(), actor = "app-provision:" + app;
  const now = new Date().toISOString();
  const labels = email.slice(email.lastIndexOf("@") + 1).split(".");
  const suffixes = JSON.stringify(labels.map((_, index) => labels.slice(index).join(".")));
  // Better Auth permits a comma-separated domain list. Match complete labels, including
  // inherited subdomains, within the same transaction that reserves the new subject.
  const enterprise = `SELECT 1 FROM ssoProvider s, json_each('[' || replace(json_quote(s.domain), ',', '","') || ']') d
    JOIN json_each(?) suffix ON suffix.value=lower(trim(d.value,char(9,10,11,12,13,32))) WHERE s.domainVerified=1`;
  // A fresh subject ID distinguishes this creation from a concurrent provision
  // or an existing account. Every dependent write uses that same candidate in
  // this batch. A retry reads its mapping without re-creating a removed grant.
  const [configuration, , , , , audit] = await auditedBatch(db, app, "app_user_provision", [
    db.prepare(configuredApp).bind(app, hostname),
    db.prepare('INSERT INTO "user"(id,name,email,emailVerified,createdAt,updatedAt,role,banned) ' +
      "SELECT ?,'',?,0,?,?,'user',0 WHERE EXISTS(" + configuredApp + ") " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_app_provisions WHERE app_id=? AND external_id_hash=?) " +
      'AND NOT EXISTS(SELECT 1 FROM "user" WHERE email=? COLLATE NOCASE) ' +
      "AND NOT EXISTS(SELECT 1 FROM nathan_bootstrap_status WHERE admin_email=? COLLATE NOCASE) " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_admin_grants WHERE enabled=1 AND email=? COLLATE NOCASE) " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_admission_pending WHERE email=?) " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_invitations WHERE email=? AND uses=0) " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_scim_users WHERE linked_email=? COLLATE NOCASE OR user_name=? COLLATE NOCASE) " +
      "AND NOT EXISTS(" + enterprise + ")")
      .bind(candidate,email,now,now,app,hostname,app,key,email,email,email,email,email,email,email,suffixes),
    db.prepare("INSERT INTO nathan_app_provisions(app_id,external_id_hash,subject_hash,user_id,email) " +
      'SELECT ?,?,?,id,email FROM "user" WHERE id=?').bind(app,key,await subjectKey(key,candidate),candidate),
    db.prepare("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) " +
      "SELECT ?,app_id,'member','user',user_id,? FROM nathan_app_provisions WHERE user_id=?")
      .bind(crypto.randomUUID(),actor,candidate),
    db.prepare("INSERT INTO nathan_rbac_changes(kind,app_id,principal_type,principal_id,detail,actor) " +
      "SELECT 'grant.created',app_id,'user',user_id,json_object('role','member'),? FROM nathan_app_provisions WHERE user_id=?")
      .bind(actor,candidate),
    db.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) " +
      "SELECT ?,?,'app_user_provision',COALESCE(p.user_id,'unmatched')," +
      "CASE WHEN p.user_id=? THEN 'created' WHEN p.user_id IS NOT NULL THEN 'existing' " +
      "WHEN NOT EXISTS(SELECT 1 FROM nathan_app_provisions WHERE app_id=? AND external_id_hash=?) " +
      "AND EXISTS(" + enterprise + ") THEN 'verified_enterprise_domain' ELSE 'refused' END " +
      "FROM (SELECT 1) LEFT JOIN nathan_active_app_provisions p ON p.app_id=? AND p.external_id_hash=? AND p.email=? " +
      "AND EXISTS(" + configuredApp + ") RETURNING target,outcome")
      .bind(crypto.randomUUID(),actor,candidate,app,key,suffixes,app,key,email,app,hostname)
  ]);
  if (!configuration.results.length) return { error: "not_configured" };
  const row = audit.results[0] as { target: string; outcome: string };
  if (row.outcome === "verified_enterprise_domain")
    return { error: "identity_conflict", reason: "verified_enterprise_domain" };
  return row.outcome === "refused" ? { error: "identity_conflict" } : { sub: row.target };
}

async function reconcile(env: AuthEnv, app: string, hostname: string, key: string, sub: string, revision: number, roles: string): Promise<GrantsResult> {
  const db = env.DB;
  // A ban prevents granting access. It must still be possible to withdraw
  // the source's existing roles so that lifting the ban cannot restore them.
  const identity = "FROM nathan_app_provisions p JOIN user u ON u.id=p.user_id AND u.email=p.email " +
    "JOIN nathan_provisionable_apps a ON a.id=p.app_id WHERE p.app_id=? AND a.hostname=? AND p.external_id_hash=? " +
    "AND p.user_id=? AND p.erased_revision IS NULL AND COALESCE(u.role,'user')='user' " +
    "AND u.email NOT IN (SELECT value FROM json_each(?)) " +
    "AND NOT EXISTS(SELECT 1 FROM nathan_admin_grants WHERE enabled=1 AND (user_id=u.id OR email=u.email COLLATE NOCASE)) " +
    "AND NOT EXISTS(SELECT 1 FROM nathan_bootstrap_status WHERE admin_user_id=u.id OR admin_email=u.email COLLATE NOCASE)";
  const identityArgs = [app,hostname,key,sub,JSON.stringify(adminEmails(env))];
  const canApply = "(?='[]' OR (COALESCE(u.banned,0)=0 AND NOT EXISTS(SELECT 1 FROM nathan_scim_users " +
    "WHERE user_id=u.id AND link_state='deprovisioned' AND override_cause IS NULL)))";
  const target = identity + " AND " + canApply;
  const targetArgs = [...identityArgs,roles];
  const manifest = "SELECT 1 WHERE EXISTS(" + configuredApp + ") AND NOT EXISTS(SELECT 1 FROM json_each(?) wanted " +
    "WHERE NOT EXISTS(SELECT 1 FROM nathan_rbac_roles WHERE app_id=? AND key=wanted.value))";
  const manifestArgs = [app,hostname,roles,app];
  const [configured, previous, update] = await auditedBatch(db, app, "app_grants_sync", [
    db.prepare(manifest).bind(...manifestArgs),
    db.prepare("SELECT grant_revision,desired_roles," + canApply + " AS writable " + identity +
      " UNION ALL SELECT erased_revision,NULL,0 FROM nathan_app_provisions WHERE app_id=? AND external_id_hash=? AND subject_hash=? " +
      "AND user_id IS NULL AND erased_revision IS NOT NULL AND EXISTS(" + configuredApp + ")")
      .bind(roles,...identityArgs,app,key,await subjectKey(key,sub),app,hostname),
    db.prepare("UPDATE nathan_app_provisions SET grant_revision=?1, desired_roles=?2 WHERE grant_revision<?1 " +
      "AND user_id=(SELECT user_id " + target + ") AND EXISTS(" + manifest + ") RETURNING grant_revision")
      .bind(revision,roles,...targetArgs,...manifestArgs),
    db.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) " +
      "SELECT ?,?,'app_grants_sync',COALESCE(p.user_id,'unmatched')," +
      "CASE WHEN changes()=1 THEN 'applied' WHEN p.grant_revision=? AND p.desired_roles=? THEN 'existing' ELSE 'refused' END " +
      "FROM (SELECT 1) LEFT JOIN (SELECT user_id,grant_revision,desired_roles " + target + ") p ON EXISTS(" + manifest + ")")
      .bind(crypto.randomUUID(),"app-provision:" + app,revision,roles,...targetArgs,...manifestArgs)
  ]);
  if (update.results.length) return { sub, revision, applied: true };
  const prior = previous.results[0] as { grant_revision: number; desired_roles: string | null; writable: number } | undefined;
  if (prior && prior.grant_revision > revision) return { error: "stale_revision" };
  // Erasure is terminal even if Studio has since retired a role from this delivery.
  if (prior?.desired_roles === null) return { error: "identity_conflict" };
  if (!configured.results.length) return { error: "not_configured" };
  if (prior?.writable && prior.grant_revision === revision && prior.desired_roles === roles) return { sub, revision, applied: false };
  return { error: "identity_conflict" };
}

async function eraseMember(env: AuthEnv, app: string, hostname: string, key: string, sub: string, revision: number): Promise<GrantsResult> {
  const db = env.DB;
  const registered = "SELECT 1 FROM nathan_applications WHERE id=? AND hostname=? AND enabled=1";
  // Bans and revoked app grants never prevent erasure. A later operator or
  // directory enrollment, or independent access to another application, does.
  const target = "FROM nathan_app_provisions p LEFT JOIN user u ON u.id=p.user_id WHERE p.app_id=? AND p.external_id_hash=? " +
    "AND p.subject_hash=? AND (p.user_id IS NULL OR (u.id=? AND u.email=p.email AND COALESCE(u.role,'user')='user' " +
    "AND u.email NOT IN (SELECT value FROM json_each(?)) " +
    "AND NOT EXISTS(SELECT 1 FROM nathan_bootstrap_status WHERE admin_user_id=u.id OR admin_email=u.email COLLATE NOCASE) " +
    "AND NOT EXISTS(SELECT 1 FROM nathan_admin_grants WHERE enabled=1 AND (user_id=u.id OR email=u.email COLLATE NOCASE)) " +
    "AND NOT EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=u.id) " +
    "AND NOT EXISTS(SELECT 1 FROM oauthClient WHERE userId=u.id) AND NOT EXISTS(SELECT 1 FROM ssoProvider WHERE userId=u.id) " +
    "AND NOT EXISTS(SELECT 1 FROM member m WHERE m.userId=u.id " +
    `AND EXISTS(SELECT 1 FROM json_each('[' || replace(json_quote(m.role), ',', '","') || ']') r WHERE trim(r.value,char(9,10,11,12,13,32))='owner')) ` +
    "AND NOT EXISTS(SELECT 1 FROM nathan_rbac_grants g WHERE g.app_id<>p.app_id AND ((g.principal_type='user' AND g.principal_id=u.id) " +
    "OR (g.principal_type='group' AND g.principal_id IN (SELECT group_id FROM nathan_group_members WHERE user_id=u.id))))))";
  const args = [app, key, await subjectKey(key,sub), sub, JSON.stringify(adminEmails(env))];
  const [configured, previous, claimed, deleted] = await auditedBatch(db, app, "app_user_erase", [
    db.prepare(registered).bind(app,hostname),
    db.prepare("SELECT p.user_id,p.grant_revision,p.erased_revision " + target).bind(...args),
    db.prepare("UPDATE nathan_app_provisions SET erased_revision=?1, grant_revision=?1, desired_roles='[]' " +
      "WHERE grant_revision<?1 AND erased_revision IS NULL AND (app_id,external_id_hash) IN (SELECT p.app_id,p.external_id_hash " +
      target + ") AND EXISTS(" + registered + ") RETURNING user_id")
      .bind(revision, ...args, app, hostname),
    db.prepare("DELETE FROM user WHERE id=? AND changes()=1 AND EXISTS(SELECT 1 FROM nathan_app_provisions " +
      "WHERE user_id=user.id AND app_id=? AND external_id_hash=? AND erased_revision=?) RETURNING id")
      .bind(sub,app,key,revision),
    db.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) " +
      "SELECT ?,?,'app_user_erase',CASE WHEN p.erased_revision=? THEN ? ELSE 'unmatched' END, " +
      // A trigger that skipped the user delete must also roll back its revision
      // and grant changes. outcome is NOT NULL, so this fails the entire batch.
      "CASE WHEN p.user_id IS NOT NULL AND p.erased_revision=? THEN NULL " +
      "WHEN changes()=1 THEN 'erased' WHEN p.erased_revision=? THEN 'existing' ELSE 'refused' END " +
      "FROM (SELECT 1) LEFT JOIN (SELECT p.user_id,p.erased_revision " + target + ") p ON EXISTS(" + registered + ")")
      .bind(crypto.randomUUID(),"app-provision:" + app,revision,sub,revision,revision,...args,app,hostname)
  ]);
  if (!configured.results.length) return { error: "not_configured" };
  if (deleted.results.length) return { sub, revision, applied: true };
  const row = previous.results[0] as { user_id: string | null; grant_revision: number; erased_revision: number | null } | undefined;
  if (row && row.grant_revision > revision) return { error: "stale_revision" };
  if (row?.user_id === null && (row.erased_revision === revision || claimed.results.length))
    return { sub, revision, applied: false };
  return { error: "identity_conflict" };
}

/** Private admission capability. The trusted caller supplies its durable local
 * identity and admission decision. Neither method takes a Nathan administrator role. */
export class NathanAppProvisioner extends WorkerEntrypoint<AuthEnv, BindingProps> {
  async provision(input: unknown): Promise<ProvisionResult> {
    try {
      const scope = await authorize(this.env, this.ctx.props);
      if ("error" in scope) return scope;
      const record = input as { externalId?: unknown; email?: unknown } | null;
      const email = normalizeEmail(record?.email), externalId = record?.externalId;
      if (!record || Object.keys(record).length !== 2 || !email || !validId(externalId))
        return await refuse(this.env,scope.app,"app_user_provision","invalid_input");
      if (adminEmails(this.env).includes(email))
        return await refuse(this.env,scope.app,"app_user_provision","identity_conflict");
      return await admit(this.env,scope.app,scope.hostname,await externalKey(scope.app,externalId),email);
    } catch {
      // Do not return SQL, credentials or profile fields in an RPC error.
      throw Error("Application provisioning temporarily unavailable");
    }
  }

  async syncGrants(input: unknown): Promise<GrantsResult> {
    try {
      const scope = await authorize(this.env, this.ctx.props);
      if ("error" in scope) return scope;
      const record = input as { externalId?: unknown; sub?: unknown; roles?: unknown; revision?: unknown } | null;
      const { externalId, sub, roles, revision } = record ?? {};
      if (!record || Object.keys(record).length !== 4 || !validId(externalId) || !validId(sub) ||
          typeof revision !== "number" || !Number.isSafeInteger(revision) || revision <= 0 ||
          !Array.isArray(roles) || roles.length > grantRoles.size || new Set(roles).size !== roles.length ||
          !roles.every(role => typeof role === "string" && grantRoles.has(role)) || (roles.length > 0 && !roles.includes("member")))
        return await refuse(this.env,scope.app,"app_grants_sync","invalid_input");
      return await reconcile(this.env,scope.app,scope.hostname,await externalKey(scope.app,externalId),sub,revision,JSON.stringify([...roles].sort()));
    } catch {
      throw Error("Application grant reconciliation temporarily unavailable");
    }
  }

  async erase(input: unknown): Promise<GrantsResult> {
    try {
      const scope = await authorize(this.env, this.ctx.props);
      if ("error" in scope) return scope;
      const record = input as { externalId?: unknown; sub?: unknown; revision?: unknown } | null;
      const { externalId, sub, revision } = record ?? {};
      if (!record || Object.keys(record).length !== 3 || !validId(externalId) || !validId(sub) ||
          typeof revision !== "number" || !Number.isSafeInteger(revision) || revision <= 0)
        return await refuse(this.env,scope.app,"app_user_erase","invalid_input");
      return await eraseMember(this.env,scope.app,scope.hostname,await externalKey(scope.app,externalId),sub,revision);
    } catch {
      throw Error("Application erasure temporarily unavailable");
    }
  }
}
