/**
 * NATH-11: applies staged SCIM state from a connection's Durable Object to D1.
 *
 * The Durable Object calls these functions one resource at a time, serialized per connection, with
 * the resource's *current* staged state and revision. Each call is a single D1 batch (one
 * transaction), so a change is applied completely or not at all, and it is idempotent:
 * - a resource already applied at this revision is skipped (replays and duplicate outbox rows);
 * - change-feed rows, audit rows and logout deliveries are written only for real transitions.
 *
 * Security rules (NATH-1, AGENTS.md):
 * - a link is keyed by (connection, externalId) and never moves to another connection;
 * - the first link is made by email only when the email's domain is the connection's verified domain
 *   and the Nathan user's email is verified; never by an unverified email;
 * - deprovisioning (active=false or DELETE) bans the user, deletes every session and revokes every
 *   access and refresh token in the same batch that enqueues back-channel logout; if that batch fails
 *   the caller answers 5xx and retries, nothing reports success early;
 * - SCIM groups change only the Nathan groups an administrator mapped; a mapping never grants roles.
 */
import type { AuthEnv } from "../env";
import { changeStatement, auditStatement } from "../../shared/rbac-store.mjs";

type Statement = { sql: string; params: unknown[] };
export type ConnectionPolicy = {
  id: string; domain: string; organizationId: string | null; enabled: boolean;
  linking: boolean; jit: boolean; domainVerified: boolean;
};
export type UserSnapshot = {
  id: string; externalId: string; userName: string; displayName: string; emails: { value: string }[];
  active: boolean; deleted: boolean; revision: number; groups: { id: string; externalId: string | null }[];
};
export type GroupSnapshot = {
  id: string; externalId: string | null; displayName: string; deleted: boolean; revision: number; members: string[];
};
export type ApplyResult = { changed: boolean; deprovisioned: boolean };

const truthy = (value: unknown) => value === 1 || value === true || value === "1";
const actorOf = (connection: string) => "scim:" + connection;
/** The ban reason Nathan writes; reactivation lifts only a ban that still carries it. */
export const scimBanReason = (connection: string) => "SCIM deprovisioned (connection " + connection + ")";
const statement = (sql: string, ...params: unknown[]): Statement => ({ sql, params });

async function first<T>(env: AuthEnv, sql: string, ...params: unknown[]): Promise<T | null> {
  return env.DB.prepare(sql).bind(...params).first<T>();
}
async function rows<T>(env: AuthEnv, sql: string, ...params: unknown[]): Promise<T[]> {
  return (await env.DB.prepare(sql).bind(...params).all<T>()).results;
}
async function commit(env: AuthEnv, statements: Statement[]) {
  if (statements.length) await env.DB.batch(statements.map(s => env.DB.prepare(s.sql).bind(...s.params)));
}

/**
 * Whether a connection's enterprise domain is verified. Today the evidence is Better Auth's enterprise
 * SSO domain verification (a DNS TXT record checked by verifyEnterpriseDomain); NATH-10's
 * verified-domain data plugs in here, the single place SCIM reads it.
 */
export async function isVerifiedDomain(env: AuthEnv, domain: string, organizationId: string | null): Promise<boolean> {
  const providers = await rows<{ domain: string; org: string | null }>(env,
    'SELECT "domain" AS domain, "organizationId" AS org FROM "ssoProvider" WHERE "domainVerified"=1 LIMIT 500');
  return providers.some(p => String(p.domain).toLowerCase().split(",").map(d => d.trim()).includes(domain)
    && (!organizationId || p.org === organizationId));
}
export async function loadPolicy(env: AuthEnv, connectionId: string): Promise<ConnectionPolicy | null> {
  const row = await first<any>(env,
    "SELECT id, domain, organization_id AS organizationId, enabled, linking_enabled AS linking, jit_enabled AS jit FROM nathan_scim_connections WHERE id=?",
    connectionId);
  if (!row) return null;
  return {
    id: row.id, domain: String(row.domain).toLowerCase(), organizationId: row.organizationId ?? null,
    enabled: truthy(row.enabled), linking: truthy(row.linking), jit: truthy(row.jit),
    domainVerified: await isVerifiedDomain(env, String(row.domain).toLowerCase(), row.organizationId ?? null)
  };
}

/**
 * Admission hook for just-in-time account creation. NATH-16 (invitation-only admission) must make
 * this require a pending invitation for `email` when the installation is invitation-only; until
 * then the connection's explicit JIT toggle (default off) is the only gate.
 */
export async function admitJustInTime(_env: AuthEnv, policy: ConnectionPolicy, _email: string): Promise<boolean> {
  return policy.jit;
}

type LinkDecision = { userId: string; method: "email" } | { create: { id: string; email: string; name: string } } | { note: string };
async function decideLink(env: AuthEnv, policy: ConnectionPolicy, snap: UserSnapshot): Promise<LinkDecision> {
  const candidates = [...new Set([...snap.emails.map(e => e.value), snap.userName].map(v => String(v).toLowerCase()))]
    .filter(email => email.split("@")[1] === policy.domain);
  if (!candidates.length) return { note: "No directory email in the connection's domain " + policy.domain };
  if (!policy.domainVerified) return { note: "The connection's domain is not verified; no email-based linking or creation" };
  const matches = await rows<{ id: string; verified: unknown }>(env,
    'SELECT "id" AS id, "emailVerified" AS verified FROM "user" WHERE lower("email") IN (SELECT value FROM json_each(?)) LIMIT 5',
    JSON.stringify(candidates));
  const verified = matches.filter(m => truthy(m.verified));
  if (verified.length > 1) return { note: "Several verified Nathan users match; no link established" };
  if (verified.length === 1) {
    const taken = await first<{ connection: string }>(env, "SELECT connection_id AS connection FROM nathan_scim_users WHERE user_id=?", verified[0].id);
    if (taken) return { note: taken.connection === policy.id
      ? "The matching Nathan user is linked to another directory user"
      : "The matching Nathan user is linked to another SCIM connection; links never move" };
    return { userId: verified[0].id, method: "email" };
  }
  if (matches.length) return { note: "A Nathan user with this email exists but its email is not verified; never linked" };
  if (!snap.active) return { note: "Inactive directory user; no account created" };
  if (!await admitJustInTime(env, policy, candidates[0]))
    return { note: policy.jit ? "Admission policy refused just-in-time creation" : "No verified Nathan user with this email; just-in-time creation is off" };
  return { create: { id: crypto.randomUUID(), email: candidates[0], name: (snap.displayName || candidates[0]).slice(0, 256) } };
}

/** Mapped Nathan group ids for a set of SCIM groups. */
async function mappedGroups(env: AuthEnv, connection: string, groups: { id: string; externalId: string | null }[]) {
  const mappings = await rows<{ type: string; value: string; groupId: string }>(env,
    "SELECT ref_type AS type, ref_value AS value, group_id AS groupId FROM nathan_scim_group_mappings WHERE connection_id=?", connection);
  return new Set(mappings.filter(m => groups.some(g => m.type === "id" ? g.id === m.value : g.externalId !== null && g.externalId === m.value))
    .map(m => m.groupId));
}
function membershipStatements(connection: string, userId: string, add: string[], remove: string[]): Statement[] {
  const actor = actorOf(connection), out: Statement[] = [];
  for (const group of add) out.push(
    statement("INSERT OR IGNORE INTO nathan_group_members(group_id,user_id,added_by) VALUES (?,?,?)", group, userId, actor),
    changeStatement({ kind: "member.added", principalType: "user", principalId: userId, detail: { group, source: "scim", connection }, actor }));
  for (const group of remove) out.push(
    statement("DELETE FROM nathan_group_members WHERE group_id=? AND user_id=?", group, userId),
    changeStatement({ kind: "member.removed", principalType: "user", principalId: userId, detail: { group, source: "scim", connection }, actor }));
  return out;
}

/** Applies one staged SCIM User: linking, deprovisioning or reactivation, and mapped memberships. */
export async function applyUser(env: AuthEnv, policy: ConnectionPolicy, snap: UserSnapshot, force = false): Promise<ApplyResult> {
  const connection = policy.id, actor = actorOf(connection);
  const row = await first<any>(env, "SELECT * FROM nathan_scim_users WHERE connection_id=? AND scim_id=?", connection, snap.id);
  if (row && Number(row.applied_revision) >= snap.revision && !force) return { changed: false, deprovisioned: false };
  const statements: Statement[] = [];
  let userId: string | null = row?.user_id ?? null;
  let method: string | null = userId ? row.link_method : null;
  let state: string = userId ? row.link_state : "unlinked";
  let note: string | null = userId ? null : row?.link_note ?? null;
  let scimBanned = userId ? truthy(row.scim_banned) : false;
  let linkedAt: number | null = userId ? row.linked_at : null;
  let created = false;

  if (!userId && !snap.deleted) {
    if (!policy.linking) note = "Linking is disabled for this connection";
    else {
      const decision = await decideLink(env, policy, snap);
      if ("note" in decision) note = decision.note;
      else {
        const now = new Date().toISOString();
        if ("create" in decision) {
          // Just-in-time: the directory record does not prove the email, so it stays unverified.
          statements.push(statement('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role","banned") VALUES (?,?,?,0,?,?,\'user\',0)',
            decision.create.id, decision.create.name, decision.create.email, now, now));
          userId = decision.create.id; method = "jit"; created = true;
        } else { userId = decision.userId; method = "email"; }
        state = "linked"; note = null; linkedAt = Math.floor(Date.now() / 1000);
        statements.push(
          changeStatement({ kind: "user.linked", principalType: "user", principalId: userId, detail: { connection, method }, actor }),
          auditStatement(actor, "scim_user_link", connection + ":" + userId + ":" + method, "succeeded"));
      }
    }
  }
  const existing = userId && !created
    ? await first<{ banned: unknown }>(env, 'SELECT "banned" AS banned FROM "user" WHERE "id"=?', userId) : null;
  let deprovisioned = false;
  const tail: Statement[] = [];
  if (userId) {
    if (snap.deleted || !snap.active) {
      const transition = state !== "deprovisioned";
      if (transition || force) {
        const now = new Date().toISOString();
        if (created || (existing && !truthy(existing.banned))) {
          tail.push(statement('UPDATE "user" SET "banned"=1, "banReason"=?, "banExpires"=NULL, "updatedAt"=? WHERE "id"=?', scimBanReason(connection), now, userId));
          scimBanned = true;
        }
        if (transition) tail.push(statement(
          "INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,connection_id,reason) " +
          "SELECT lower(hex(randomblob(16))), c.\"clientId\", ?, ?, ? FROM \"oauthClient\" c " +
          "WHERE c.\"backchannelLogoutUri\" IS NOT NULL AND ifnull(c.\"disabled\",0) IN (0,'0','false') AND (" +
          "EXISTS (SELECT 1 FROM \"oauthAccessToken\" t WHERE t.\"clientId\"=c.\"clientId\" AND t.\"userId\"=?) OR " +
          "EXISTS (SELECT 1 FROM \"oauthRefreshToken\" t WHERE t.\"clientId\"=c.\"clientId\" AND t.\"userId\"=?) OR " +
          "EXISTS (SELECT 1 FROM \"oauthConsent\" t WHERE t.\"clientId\"=c.\"clientId\" AND t.\"userId\"=?))",
          userId, connection, "scim." + (snap.deleted ? "deleted" : "deactivated"), userId, userId, userId));
        // Every session and token goes, offline_access refresh tokens included: the person left.
        tail.push(
          statement('DELETE FROM "session" WHERE "userId"=?', userId),
          statement('UPDATE "oauthAccessToken" SET "revoked"=? WHERE "userId"=? AND "revoked" IS NULL', now, userId),
          statement('UPDATE "oauthRefreshToken" SET "revoked"=? WHERE "userId"=? AND "revoked" IS NULL', now, userId));
        if (transition) {
          tail.push(
            changeStatement({ kind: "user.deprovisioned", principalType: "user", principalId: userId,
              detail: { connection, cause: snap.deleted ? "deleted" : "deactivated" }, actor }),
            auditStatement(actor, "scim_user_deprovision", connection + ":" + userId, "succeeded"));
          deprovisioned = true;
        }
      }
      state = "deprovisioned";
    } else if (state === "deprovisioned") {
      // Reactivation lifts only Nathan's own SCIM ban; sessions and tokens are not restored.
      if (scimBanned) tail.push(statement(
        'UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL, "updatedAt"=? WHERE "id"=? AND "banned" IN (1,\'1\') AND "banReason"=?',
        new Date().toISOString(), userId, scimBanReason(connection)));
      scimBanned = false; state = "linked";
      tail.push(
        changeStatement({ kind: "user.reactivated", principalType: "user", principalId: userId, detail: { connection }, actor }),
        auditStatement(actor, "scim_user_reactivate", connection + ":" + userId, "succeeded"));
    }
    const desired = snap.deleted ? new Set<string>() : await mappedGroups(env, connection, snap.groups);
    const current = created ? [] : (await rows<{ group: string }>(env,
      "SELECT m.group_id AS \"group\" FROM nathan_group_members m JOIN nathan_scim_group_mappings mp ON mp.group_id=m.group_id " +
      "WHERE mp.connection_id=? AND m.user_id=?", connection, userId)).map(r => r.group);
    tail.push(...membershipStatements(connection, userId, [...desired].filter(g => !current.includes(g)), current.filter(g => !desired.has(g))));
  }
  statements.push(statement(
    "INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,deleted,user_id,link_state,link_method,link_note,scim_banned,applied_revision,linked_at,updated_at) " +
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,unixepoch()) ON CONFLICT(connection_id,scim_id) DO UPDATE SET external_id=excluded.external_id, user_name=excluded.user_name, " +
    "active=excluded.active, deleted=excluded.deleted, user_id=excluded.user_id, link_state=excluded.link_state, link_method=excluded.link_method, " +
    "link_note=excluded.link_note, scim_banned=excluded.scim_banned, applied_revision=excluded.applied_revision, linked_at=excluded.linked_at, updated_at=unixepoch()",
    connection, snap.id, snap.externalId, snap.userName, snap.active ? 1 : 0, snap.deleted ? 1 : 0, userId, userId ? state : "unlinked",
    userId ? method : null, note, scimBanned ? 1 : 0, snap.revision, linkedAt), ...tail);
  await commit(env, statements);
  return { changed: true, deprovisioned };
}

/** Applies one staged SCIM Group: membership of its mapped Nathan group, if an administrator mapped it. */
export async function applyGroup(env: AuthEnv, policy: ConnectionPolicy, snap: GroupSnapshot, force = false): Promise<ApplyResult> {
  const connection = policy.id;
  const row = await first<{ revision: number }>(env, "SELECT applied_revision AS revision FROM nathan_scim_groups WHERE connection_id=? AND scim_id=?", connection, snap.id);
  if (row && Number(row.revision) >= snap.revision && !force) return { changed: false, deprovisioned: false };
  const statements: Statement[] = [statement(
    "INSERT INTO nathan_scim_groups(connection_id,scim_id,external_id,display_name,members,deleted,applied_revision,updated_at) VALUES (?,?,?,?,?,?,?,unixepoch()) " +
    "ON CONFLICT(connection_id,scim_id) DO UPDATE SET external_id=excluded.external_id, display_name=excluded.display_name, members=excluded.members, " +
    "deleted=excluded.deleted, applied_revision=excluded.applied_revision, updated_at=unixepoch()",
    connection, snap.id, snap.externalId, snap.displayName, snap.deleted ? 0 : snap.members.length, snap.deleted ? 1 : 0, snap.revision)];
  const mapping = await first<{ groupId: string }>(env,
    "SELECT group_id AS groupId FROM nathan_scim_group_mappings WHERE connection_id=? AND ((ref_type='id' AND ref_value=?) OR (ref_type='externalId' AND ref_value=?))",
    connection, snap.id, snap.externalId ?? "");
  if (mapping) {
    const desired = snap.deleted ? [] : (await rows<{ userId: string }>(env,
      "SELECT user_id AS userId FROM nathan_scim_users WHERE connection_id=? AND deleted=0 AND user_id IS NOT NULL AND scim_id IN (SELECT value FROM json_each(?))",
      connection, JSON.stringify(snap.members))).map(r => r.userId);
    const current = (await rows<{ userId: string }>(env, "SELECT user_id AS userId FROM nathan_group_members WHERE group_id=?", mapping.groupId)).map(r => r.userId);
    for (const userId of desired.filter(u => !current.includes(u))) statements.push(...membershipStatements(connection, userId, [mapping.groupId], []));
    for (const userId of current.filter(u => !desired.includes(u))) statements.push(...membershipStatements(connection, userId, [], [mapping.groupId]));
  }
  await commit(env, statements);
  return { changed: true, deprovisioned: false };
}

export async function markSynced(env: AuthEnv, connectionId: string) {
  await env.DB.prepare("UPDATE nathan_scim_connections SET last_sync_at=unixepoch() WHERE id=?").bind(connectionId).run();
}
/** Records a reconciliation failure for the Studio error log (bounded; no directory attribute values). */
export async function recordError(env: AuthEnv, connectionId: string, kind: string, resourceId: string, message: string) {
  const text = message.replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 300);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO nathan_scim_errors(id,connection_id,resource_type,resource_id,message) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(), connectionId, kind, resourceId.slice(0, 64), text),
    env.DB.prepare("UPDATE nathan_scim_connections SET last_error_at=unixepoch() WHERE id=?").bind(connectionId),
    env.DB.prepare("DELETE FROM nathan_scim_errors WHERE connection_id=? AND id NOT IN (SELECT id FROM nathan_scim_errors WHERE connection_id=? ORDER BY created_at DESC LIMIT 200)")
      .bind(connectionId, connectionId)
  ]);
}
