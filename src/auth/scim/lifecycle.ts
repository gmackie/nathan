/**
 * NATH-11: applies staged SCIM state from a connection's Durable Object to D1.
 *
 * The Durable Object calls these functions one resource at a time, serialized per connection, with
 * the resource's *current* staged state and revision. Application is idempotent and race-safe:
 * - a resource already applied at this revision is skipped (replays and duplicate outbox rows);
 * - every D1 batch starts with a compare-and-set on the row's apply_seq, so a second writer that read
 *   the same state rolls back completely instead of repeating a transition;
 * - change-feed rows, audit rows and logout deliveries are written only for real transitions.
 *
 * Security rules (NATH-1, AGENTS.md):
 * - a link is keyed by (connection, externalId) among live identities and never moves to another
 *   connection; a rehire with the same externalId in the same connection takes over the link;
 * - the first link is made by email only when the email's domain is the connection's verified domain
 *   and the Nathan user's email is verified; never by an unverified email;
 * - Nathan administrators (global admin role, an admin grant, the bootstrap owner, NATHAN_ADMIN_EMAILS)
 *   are never linked or deprovisioned automatically: the change waits in nathan_scim_reviews for an
 *   administrator's explicit, stepped-up approval, and the last administrator is never deprovisioned;
 * - a link whose Nathan account was deleted is never re-made automatically, here or elsewhere;
 * - deprovisioning (active=false or DELETE) bans the user, deletes every session and revokes every
 *   access and refresh token in the same batch that enqueues back-channel logout; if that batch fails
 *   the caller answers 5xx and retries, nothing reports success early;
 * - an administrator's unban (keep active) is recorded and not undone by a replay or resync; only a
 *   new deprovision change from the directory applies again;
 * - SCIM groups change only the Nathan groups an administrator mapped; a mapping never grants roles.
 *
 * Work per Durable Object invocation is bounded (RECONCILE_LIMITS): a large group is applied in
 * several batches, possibly across invocations, and is marked applied only when complete.
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
export type ApplyOptions = { force?: boolean; budget?: Budget };
/** `partial`: the budget ran out and the resource must be applied again; `removalsPending`: some
 * membership removals are among the work left (callers must not report the change as applied). */
export type ApplyResult = { changed: boolean; deprovisioned: boolean; partial?: boolean; removalsPending?: boolean };

/**
 * Bounds per Durable Object invocation (request or alarm). D1 counts every statement of a batch as a
 * query and limits queries per invocation, so reconciliation counts reads and written statements and
 * stops when the budget is spent; the alarm continues in a fresh invocation.
 */
export const RECONCILE_LIMITS = { statementsPerBatch: 100, statementsPerInvocation: 500, userReserve: 60 };

/** Counts D1 reads and batched statements for one invocation. */
export class Budget {
  used = 0;
  readonly limit: number;
  constructor(limit: number = RECONCILE_LIMITS.statementsPerInvocation) { this.limit = limit; }
  get remaining() { return this.limit - this.used; }
  /** The same env whose DB charges this budget for every query. */
  wrap<E extends { DB: any }>(env: E): E {
    const budget = this, db = env.DB;
    const counted = (inner: any): any => ({
      inner,
      bind: (...values: unknown[]) => counted(inner.bind(...values)),
      first: (...a: unknown[]) => { budget.used++; return inner.first(...a); },
      all: (...a: unknown[]) => { budget.used++; return inner.all(...a); },
      run: (...a: unknown[]) => { budget.used++; return inner.run(...a); },
      raw: (...a: unknown[]) => { budget.used++; return inner.raw(...a); }
    });
    return { ...env, DB: {
      prepare: (sql: string) => counted(db.prepare(sql)),
      batch: (statements: any[]) => { budget.used += statements.length; return db.batch(statements.map(s => s?.inner ?? s)); }
    } };
  }
}

const truthy = (value: unknown) => value === 1 || value === true || value === "1";
const actorOf = (connection: string) => "scim:" + connection;
const UNCHANGED: ApplyResult = { changed: false, deprovisioned: false };
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

// ---- administrator protection -----------------------------------------------------------------

const adminEmails = (env: AuthEnv) => String(env.NATHAN_ADMIN_EMAILS || "").split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
/**
 * Why a Nathan user is an administrator principal SCIM must never act on by itself, or null. Broader
 * than isAdminPrincipal on purpose: any one of these makes the account protected.
 */
export async function adminProtection(env: AuthEnv, userId: string): Promise<string | null> {
  const u = await first<{ email: string; role: string | null; granted: unknown; owner: unknown }>(env,
    'SELECT u."email" AS email, u."role" AS role, ' +
    "EXISTS(SELECT 1 FROM nathan_admin_grants g WHERE g.user_id=u.\"id\" AND g.enabled=1) AS granted, " +
    "EXISTS(SELECT 1 FROM nathan_bootstrap_status b WHERE b.admin_user_id=u.\"id\") AS owner " +
    'FROM "user" u WHERE u."id"=?', userId);
  if (!u) return null;
  if (truthy(u.owner)) return "the bootstrap owner";
  if (truthy(u.granted)) return "an administrator grant";
  if (String(u.role ?? "").split(",").map(r => r.trim()).includes("admin")) return "the global admin role";
  if (adminEmails(env).includes(String(u.email).toLowerCase())) return "an administrator email in NATHAN_ADMIN_EMAILS";
  return null;
}
/** Administrators other than `userId` who are not banned (bootstrap owner or enabled admin grant). */
export async function otherActiveAdmins(env: AuthEnv, userId: string): Promise<number> {
  const legacy = env.NATHAN_BOOTSTRAP_REQUIRED !== "true";
  const row = await first<{ n: number }>(env,
    'SELECT count(*) AS n FROM "user" u WHERE u."id"<>? AND ifnull(u."banned",0) NOT IN (1,\'1\') AND (' +
    "EXISTS(SELECT 1 FROM nathan_bootstrap_status b WHERE b.admin_user_id=u.\"id\") OR " +
    "EXISTS(SELECT 1 FROM nathan_admin_grants g WHERE g.user_id=u.\"id\" AND g.enabled=1) OR " +
    "(? AND u.\"role\"='admin' AND u.\"emailVerified\" IN (1,'1') AND lower(u.\"email\") IN (SELECT value FROM json_each(?))))",
    userId, legacy ? 1 : 0, JSON.stringify(adminEmails(env)));
  return Number(row?.n ?? 0);
}

type Review = { id: string; state: string; userId: string };
async function openReview(env: AuthEnv, connection: string, scimId: string, action: "link" | "deprovision"): Promise<Review | null> {
  return first<Review>(env,
    "SELECT id, state, user_id AS userId FROM nathan_scim_reviews WHERE connection_id=? AND scim_id=? AND action=? AND state IN ('pending','approved')",
    connection, scimId, action);
}
/** Opens a review item (once per open action), superseding an open one for a different user. */
function reviewStatements(connection: string, scimId: string, existing: Review | null, item:
  { userId: string; action: "link" | "deprovision"; cause: string | null; reason: string; revision: number }): Statement[] {
  if (existing && existing.userId === item.userId) {
    // Still waiting; an approval that can no longer be applied (last administrator) goes back to pending.
    return existing.state === "pending" ? [] : [statement("UPDATE nathan_scim_reviews SET state='pending', reason=?, decided_by=NULL, decided_at=NULL WHERE id=?", item.reason, existing.id)];
  }
  return [
    ...(existing ? [statement("UPDATE nathan_scim_reviews SET state='superseded', decided_at=unixepoch() WHERE id=?", existing.id)] : []),
    statement("INSERT INTO nathan_scim_reviews(id,connection_id,scim_id,user_id,action,cause,reason,revision) VALUES (?,?,?,?,?,?,?,?)",
      crypto.randomUUID(), connection, scimId, item.userId, item.action, item.cause, item.reason.slice(0, 300), item.revision),
    auditStatement(actorOf(connection), "scim_admin_review_open", connection + ":" + item.userId + ":" + item.action, "pending")
  ];
}

/**
 * Admission hook for just-in-time account creation. NATH-16 (invitation-only admission) must make
 * this require a pending invitation for `email` when the installation is invitation-only; until
 * then the connection's explicit JIT toggle (default off) is the only gate.
 */
export async function admitJustInTime(_env: AuthEnv, policy: ConnectionPolicy, _email: string): Promise<boolean> {
  return policy.jit;
}

type Transfer = { scimId: string; banned: boolean; state: string };
type LinkDecision =
  | { userId: string; method: "email" | "approved"; email: string; reviewId?: string; transfer?: Transfer }
  | { create: { id: string; email: string; name: string } }
  | { review: { userId: string; reason: string } }
  | { note: string };
async function decideLink(env: AuthEnv, policy: ConnectionPolicy, snap: UserSnapshot, row: any): Promise<LinkDecision> {
  const candidates = [...new Set([...snap.emails.map(e => e.value), snap.userName].map(v => String(v).toLowerCase()))]
    .filter(email => email.split("@")[1] === policy.domain);
  if (!candidates.length) return { note: "No directory email in the connection's domain " + policy.domain };
  if (!policy.domainVerified) return { note: "The connection's domain is not verified; no email-based linking or creation" };
  // A live directory identity whose linked Nathan account was deleted: never re-linked automatically.
  const orphan = row && row.linked_email
    ? { connection: policy.id }
    : await first<{ connection: string }>(env,
      "SELECT connection_id AS connection FROM nathan_scim_users WHERE user_id IS NULL AND deleted=0 AND linked_email IN (SELECT value FROM json_each(?)) " +
      "AND NOT (connection_id=? AND scim_id=?) LIMIT 1", JSON.stringify(candidates), policy.id, snap.id);
  const orphanReason = !orphan ? null : orphan.connection === policy.id
    ? "The Nathan account this directory user was linked to was deleted; re-linking needs administrator review"
    : "This email was linked through SCIM connection " + orphan.connection + " before its Nathan account was deleted; linking needs administrator review";
  const matches = await rows<{ id: string; verified: unknown; email: string }>(env,
    'SELECT "id" AS id, "emailVerified" AS verified, lower("email") AS email FROM "user" WHERE lower("email") IN (SELECT value FROM json_each(?)) LIMIT 5',
    JSON.stringify(candidates));
  const verified = matches.filter(m => truthy(m.verified));
  if (verified.length > 1) return { note: "Several verified Nathan users match; no link established" };
  if (verified.length === 1) {
    const target = verified[0];
    const taken = await first<{ connection: string; scimId: string; deleted: unknown; externalId: string; banned: unknown; state: string }>(env,
      "SELECT connection_id AS connection, scim_id AS scimId, deleted, external_id AS externalId, scim_banned AS banned, link_state AS state FROM nathan_scim_users WHERE user_id=?",
      target.id);
    let transfer: Transfer | undefined;
    if (taken) {
      // A rehire: the same (connection, externalId) as a deleted identity takes over its link.
      if (taken.connection === policy.id && truthy(taken.deleted) && taken.externalId === snap.externalId)
        transfer = { scimId: taken.scimId, banned: truthy(taken.banned), state: taken.state };
      else return { note: taken.connection === policy.id
        ? "The matching Nathan user is linked to another directory user"
        : "The matching Nathan user is linked to another SCIM connection; links never move" };
    }
    const protection = await adminProtection(env, target.id);
    if (protection || orphanReason) {
      const review = await openReview(env, policy.id, snap.id, "link");
      if (review?.state === "approved" && review.userId === target.id)
        return { userId: target.id, method: "approved", email: target.email, reviewId: review.id, transfer };
      return { review: { userId: target.id, reason: protection
        ? "Matches a Nathan administrator (" + protection + "); linking waits for administrator review in Identity Studio"
        : orphanReason! } };
    }
    return { userId: target.id, method: "email", email: target.email, transfer };
  }
  if (matches.length) return { note: "A Nathan user with this email exists but its email is not verified; never linked" };
  if (orphanReason) return { note: "The Nathan account linked to this email was deleted; no account is created again automatically" };
  if (!snap.active) return { note: "Inactive directory user; no account created" };
  if (candidates.some(email => adminEmails(env).includes(email)))
    return { note: "Administrator email (NATHAN_ADMIN_EMAILS); never created just in time" };
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
  for (const group of remove) out.push(
    statement("DELETE FROM nathan_group_members WHERE group_id=? AND user_id=?", group, userId),
    changeStatement({ kind: "member.removed", principalType: "user", principalId: userId, detail: { group, source: "scim", connection }, actor }));
  for (const group of add) out.push(
    statement("INSERT OR IGNORE INTO nathan_group_members(group_id,user_id,added_by) VALUES (?,?,?)", group, userId, actor),
    changeStatement({ kind: "member.added", principalType: "user", principalId: userId, detail: { group, source: "scim", connection }, actor }));
  return out;
}
/** First statement of every batch: claims the row at the apply_seq that was read (or creates it). */
function guardStatement(table: "nathan_scim_users" | "nathan_scim_groups", connection: string, scimId: string, seq: number | null, insert: Statement): Statement {
  return seq === null ? insert : statement(
    "UPDATE " + table + " SET apply_seq=CASE WHEN apply_seq=? THEN apply_seq+1 ELSE -1 END WHERE connection_id=? AND scim_id=?", seq, connection, scimId);
}
/** After a failed batch: whether another writer applied this revision meanwhile (then nothing to do). */
async function lostRace(env: AuthEnv, table: string, connection: string, scimId: string, seq: number | null, revision: number) {
  const now = await first<{ seq: number; revision: number }>(env,
    "SELECT apply_seq AS seq, applied_revision AS revision FROM " + table + " WHERE connection_id=? AND scim_id=?", connection, scimId);
  return Boolean(now && Number(now.seq) !== (seq ?? -1) && Number(now.revision) >= revision);
}

/** Applies one staged SCIM User: linking, deprovisioning or reactivation, and mapped memberships. */
export async function applyUser(env: AuthEnv, policy: ConnectionPolicy, snap: UserSnapshot, options: ApplyOptions = {}): Promise<ApplyResult> {
  const force = options.force === true;
  const connection = policy.id, actor = actorOf(connection);
  const row = await first<any>(env, "SELECT * FROM nathan_scim_users WHERE connection_id=? AND scim_id=?", connection, snap.id);
  if (row && Number(row.applied_revision) >= snap.revision && !force) return UNCHANGED;
  const seq = row ? Number(row.apply_seq) : null;
  const statements: Statement[] = [guardStatement("nathan_scim_users", connection, snap.id, seq, statement(
    "INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,deleted,apply_seq) VALUES (?,?,?,?,?,?,1)",
    connection, snap.id, snap.externalId, snap.userName, snap.active ? 1 : 0, snap.deleted ? 1 : 0))];
  const now = new Date().toISOString(), nowSeconds = Math.floor(Date.now() / 1000);
  let userId: string | null = row?.user_id ?? null;
  let method: string | null = userId ? row.link_method : null;
  let state: string = userId ? row.link_state : "unlinked";
  let note: string | null = userId ? null : row?.link_note ?? null;
  let scimBanned = userId ? truthy(row.scim_banned) : false;
  let linkedAt: number | null = row?.linked_at ?? null;
  let linkedEmail: string | null = row?.linked_email ?? null;
  const hold: string | null = row?.link_hold ?? null;
  let override = { cause: row?.override_cause ?? null as string | null, by: row?.override_by ?? null as string | null, at: row?.override_at ?? null as number | null };
  let created = false;
  const tail: Statement[] = [];

  if (!userId && snap.deleted) {
    tail.push(statement("UPDATE nathan_scim_reviews SET state='superseded', decided_at=unixepoch() WHERE connection_id=? AND scim_id=? AND state IN ('pending','approved')", connection, snap.id));
  } else if (!userId) {
    if (hold) note = hold;
    else if (!policy.linking) note = "Linking is disabled for this connection";
    else {
      const decision = await decideLink(env, policy, snap, row);
      if ("note" in decision) note = decision.note;
      else if ("review" in decision) {
        note = decision.review.reason;
        statements.push(...reviewStatements(connection, snap.id, await openReview(env, connection, snap.id, "link"),
          { userId: decision.review.userId, action: "link", cause: null, reason: decision.review.reason, revision: snap.revision }));
      } else {
        if ("create" in decision) {
          // Just-in-time: the directory record does not prove the email, so it stays unverified.
          statements.push(statement('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role","banned") VALUES (?,?,?,0,?,?,\'user\',0)',
            decision.create.id, decision.create.name, decision.create.email, now, now));
          userId = decision.create.id; method = "jit"; created = true; linkedEmail = decision.create.email; state = "linked";
        } else {
          userId = decision.userId; method = decision.method; linkedEmail = decision.email; state = "linked";
          if (decision.transfer) {
            // The deleted identity gives up its link first (one SCIM identity per Nathan user).
            statements.push(statement("UPDATE nathan_scim_users SET user_id=NULL, linked_email=NULL, link_note=?, updated_at=unixepoch() WHERE connection_id=? AND scim_id=?",
              "Link moved to the rehired directory user " + snap.id, connection, decision.transfer.scimId));
            scimBanned = decision.transfer.banned;
            if (decision.transfer.state === "deprovisioned") state = "deprovisioned";
          }
          if (decision.reviewId) statements.push(
            statement("UPDATE nathan_scim_reviews SET state='applied' WHERE id=?", decision.reviewId),
            auditStatement(actor, "scim_admin_review_apply", connection + ":" + userId + ":link", "succeeded"));
        }
        note = null; linkedAt = nowSeconds;
        statements.push(
          changeStatement({ kind: "user.linked", principalType: "user", principalId: userId, detail: { connection, method }, actor }),
          auditStatement(actor, "scim_user_link", connection + ":" + userId + ":" + method, "succeeded"));
      }
    }
  }
  const existing = userId && !created
    ? await first<{ banned: unknown }>(env, 'SELECT "banned" AS banned FROM "user" WHERE "id"=?', userId) : null;
  let deprovisioned = false;
  if (userId) {
    const cause = snap.deleted ? "deleted" : "deactivated";
    if (snap.deleted || !snap.active) {
      // An administrator lifted Nathan's SCIM ban outside SCIM (Better Auth admin API, by hand): record
      // it as an override so this replay, and every later one for the same cause, leaves it alone.
      if (state === "deprovisioned" && !override.cause && existing && !truthy(existing.banned)) {
        override = { cause: truthy(row?.deleted) ? "deleted" : "deactivated", by: "out-of-band unban (detected by reconciliation)", at: nowSeconds };
        scimBanned = false;
        tail.push(auditStatement(actor, "scim_override_detected", connection + ":" + userId, "recorded"));
      }
      // A different cause than the one an administrator overrode is a new deprovision change.
      const renewed = Boolean(override.cause && override.cause !== cause);
      if (renewed) override = { cause: null, by: null, at: null };
      if (override.cause) {
        note = "Kept active by " + override.by + " at " + new Date(Number(override.at) * 1000).toISOString() + "; the directory reports this user " + cause;
        state = "deprovisioned";
      } else {
        let allowed = true;
        const protection = await adminProtection(env, userId);
        if (protection) {
          const review = await openReview(env, connection, snap.id, "deprovision");
          const approved = review?.state === "approved" && review.userId === userId;
          if (approved && await otherActiveAdmins(env, userId) > 0) {
            tail.push(statement("UPDATE nathan_scim_reviews SET state='applied' WHERE id=?", review!.id),
              auditStatement(actor, "scim_admin_review_apply", connection + ":" + userId + ":deprovision", "succeeded"));
          } else {
            allowed = false;
            note = approved
              ? "Not deprovisioned: this is the last administrator; SCIM never removes the last administrator"
              : "Deprovisioning waits for administrator review: this is a Nathan administrator (" + protection + ")";
            tail.push(...reviewStatements(connection, snap.id, review, { userId, action: "deprovision", cause, reason: note, revision: snap.revision }));
          }
        }
        if (allowed) {
          const transition = state !== "deprovisioned" || renewed;
          if (transition || force) {
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
              userId, connection, "scim." + cause, userId, userId, userId));
            // Every session and token goes, offline_access refresh tokens included: the person left.
            tail.push(
              statement('DELETE FROM "session" WHERE "userId"=?', userId),
              statement('UPDATE "oauthAccessToken" SET "revoked"=? WHERE "userId"=? AND "revoked" IS NULL', now, userId),
              statement('UPDATE "oauthRefreshToken" SET "revoked"=? WHERE "userId"=? AND "revoked" IS NULL', now, userId));
            if (transition) {
              tail.push(
                changeStatement({ kind: "user.deprovisioned", principalType: "user", principalId: userId, detail: { connection, cause }, actor }),
                auditStatement(actor, "scim_user_deprovision", connection + ":" + userId, "succeeded"));
              deprovisioned = true;
            }
          }
          state = "deprovisioned";
        }
      }
    } else {
      if (state === "deprovisioned") {
        // Reactivation lifts only Nathan's own SCIM ban; sessions and tokens are not restored.
        if (scimBanned) tail.push(statement(
          'UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL, "updatedAt"=? WHERE "id"=? AND "banned" IN (1,\'1\') AND "banReason"=?',
          now, userId, scimBanReason(connection)));
        scimBanned = false; state = "linked";
        tail.push(
          changeStatement({ kind: "user.reactivated", principalType: "user", principalId: userId, detail: { connection }, actor }),
          auditStatement(actor, "scim_user_reactivate", connection + ":" + userId, "succeeded"));
      }
      override = { cause: null, by: null, at: null };
      tail.push(statement("UPDATE nathan_scim_reviews SET state='superseded', decided_at=unixepoch() WHERE connection_id=? AND scim_id=? AND action='deprovision' AND state IN ('pending','approved')",
        connection, snap.id));
    }
    const desired = snap.deleted ? new Set<string>() : await mappedGroups(env, connection, snap.groups);
    const current = created ? [] : (await rows<{ group: string }>(env,
      "SELECT m.group_id AS \"group\" FROM nathan_group_members m JOIN nathan_scim_group_mappings mp ON mp.group_id=m.group_id " +
      "WHERE mp.connection_id=? AND m.user_id=?", connection, userId)).map(r => r.group);
    tail.push(...membershipStatements(connection, userId, [...desired].filter(g => !current.includes(g)), current.filter(g => !desired.has(g))));
  }
  statements.push(statement(
    "INSERT INTO nathan_scim_users(connection_id,scim_id,external_id,user_name,active,deleted,user_id,link_state,link_method,link_note,linked_email,link_hold,scim_banned,applied_revision,linked_at,override_cause,override_by,override_at,updated_at) " +
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,unixepoch()) ON CONFLICT(connection_id,scim_id) DO UPDATE SET external_id=excluded.external_id, user_name=excluded.user_name, " +
    "active=excluded.active, deleted=excluded.deleted, user_id=excluded.user_id, link_state=excluded.link_state, link_method=excluded.link_method, " +
    "link_note=excluded.link_note, linked_email=excluded.linked_email, link_hold=excluded.link_hold, scim_banned=excluded.scim_banned, applied_revision=excluded.applied_revision, " +
    "linked_at=excluded.linked_at, override_cause=excluded.override_cause, override_by=excluded.override_by, override_at=excluded.override_at, updated_at=unixepoch()",
    connection, snap.id, snap.externalId, snap.userName, snap.active ? 1 : 0, snap.deleted ? 1 : 0, userId, userId ? state : "unlinked",
    userId ? method : null, note, linkedEmail, hold, scimBanned ? 1 : 0, snap.revision, linkedAt,
    userId ? override.cause : null, userId ? override.by : null, userId ? override.at : null), ...tail);
  try { await commit(env, statements); }
  catch (error) {
    if (await lostRace(env, "nathan_scim_users", connection, snap.id, seq, snap.revision)) return UNCHANGED;
    throw error;
  }
  return { changed: true, deprovisioned };
}

/**
 * Applies one staged SCIM Group: membership of its mapped Nathan group, if an administrator mapped it.
 * Removals go first. With a budget, membership changes are committed in batches of at most
 * RECONCILE_LIMITS.statementsPerBatch while the budget lasts; the group is marked applied (its
 * revision recorded) only in the batch that completes it, so a partial result is simply re-applied.
 */
export async function applyGroup(env: AuthEnv, policy: ConnectionPolicy, snap: GroupSnapshot, options: ApplyOptions = {}): Promise<ApplyResult> {
  const connection = policy.id, budget = options.budget;
  const row = await first<{ revision: number; seq: number }>(env,
    "SELECT applied_revision AS revision, apply_seq AS seq FROM nathan_scim_groups WHERE connection_id=? AND scim_id=?", connection, snap.id);
  if (row && Number(row.revision) >= snap.revision && !options.force) return UNCHANGED;
  const mapping = await first<{ groupId: string }>(env,
    "SELECT group_id AS groupId FROM nathan_scim_group_mappings WHERE connection_id=? AND ((ref_type='id' AND ref_value=?) OR (ref_type='externalId' AND ref_value=?))",
    connection, snap.id, snap.externalId ?? "");
  const work: { remove: boolean; statements: Statement[] }[] = [];
  if (mapping) {
    const desired = snap.deleted ? [] : (await rows<{ userId: string }>(env,
      "SELECT user_id AS userId FROM nathan_scim_users WHERE connection_id=? AND deleted=0 AND user_id IS NOT NULL AND scim_id IN (SELECT value FROM json_each(?))",
      connection, JSON.stringify(snap.members))).map(r => r.userId);
    const current = (await rows<{ userId: string }>(env, "SELECT user_id AS userId FROM nathan_group_members WHERE group_id=?", mapping.groupId)).map(r => r.userId);
    const want = new Set(desired), have = new Set(current);
    for (const userId of current) if (!want.has(userId)) work.push({ remove: true, statements: membershipStatements(connection, userId, [], [mapping.groupId]) });
    for (const userId of desired) if (!have.has(userId)) work.push({ remove: false, statements: membershipStatements(connection, userId, [mapping.groupId], []) });
  }
  const seq = row ? Number(row.seq) : null;
  const marker = [guardStatement("nathan_scim_groups", connection, snap.id, seq, statement(
    "INSERT INTO nathan_scim_groups(connection_id,scim_id,external_id,display_name,apply_seq) VALUES (?,?,?,?,1)",
    connection, snap.id, snap.externalId, snap.displayName)), statement(
    "INSERT INTO nathan_scim_groups(connection_id,scim_id,external_id,display_name,members,deleted,applied_revision,updated_at) VALUES (?,?,?,?,?,?,?,unixepoch()) " +
    "ON CONFLICT(connection_id,scim_id) DO UPDATE SET external_id=excluded.external_id, display_name=excluded.display_name, members=excluded.members, " +
    "deleted=excluded.deleted, applied_revision=excluded.applied_revision, updated_at=unixepoch()",
    connection, snap.id, snap.externalId, snap.displayName, snap.deleted ? 0 : snap.members.length, snap.deleted ? 1 : 0, snap.revision)];
  const perBatch = RECONCILE_LIMITS.statementsPerBatch;
  let next = 0;
  for (;;) {
    const room = Math.min(perBatch, budget ? budget.remaining : Infinity);
    const batch: Statement[] = [];
    while (next < work.length && batch.length + work[next].statements.length <= room) batch.push(...work[next++].statements);
    if (next === work.length && batch.length + marker.length <= room) {
      try { await commit(env, [...batch, ...marker]); }
      catch (error) {
        if (await lostRace(env, "nathan_scim_groups", connection, snap.id, seq, snap.revision)) return UNCHANGED;
        throw error;
      }
      return { changed: true, deprovisioned: false };
    }
    // Budget spent: the next invocation recomputes what is left from D1 and continues.
    if (!batch.length) return { changed: true, deprovisioned: false, partial: true, removalsPending: work.slice(next).some(w => w.remove) };
    await commit(env, batch);
  }
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
