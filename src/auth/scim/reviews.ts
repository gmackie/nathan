/**
 * NATH-11 review fixes: Identity Studio operations an administrator uses where SCIM must not act alone.
 *
 * - Review items (nathan_scim_reviews): directory changes that would link or deprovision a Nathan
 *   administrator, or re-link an account that was deleted, wait here. Approve applies the change once
 *   (the connection's Durable Object re-applies that user); dismiss keeps the account as it is.
 * - Keep active: lifts Nathan's own SCIM ban despite the directory and records the override, so a
 *   replay or resync does not re-ban; only a new deprovision change from the directory applies again.
 * - Unlink: detaches a directory user from its Nathan account, removes directory-maintained group
 *   memberships, and holds the identity so it is not linked again automatically.
 * - Outbox: shows the head of a connection's reconciliation queue and skips a permanently failing
 *   entry after review, so one poisoned change cannot keep the connection answering 503 forever.
 *
 * Callers (src/auth/worker.ts) have already required an enrolled, stepped-up administrator
 * (isAdminPrincipal + mayAdminister) and a same-origin JSON request. Every operation takes an exact
 * confirmation string naming its target, and every attempt is audited: succeeded, failed or rejected.
 */
import type { AuthEnv } from "../env";
import { changeStatement, auditStatement } from "../../shared/rbac-store.mjs";
import { guarded, reject, requireConnection } from "./lifecycle-admin";
import { otherActiveAdmins, recordError, scimBanReason } from "./lifecycle";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Messages safe to show an administrator (worker.ts maps anything else to a generic rejection). */
export const SCIM_REVIEW_ERRORS = /^(Unknown review|Review item|An administrator cannot|The last administrator|That Nathan user|The Nathan user|No linked|The directory reports|Invalid|Unknown SCIM connection|Exact confirmation|Only the reviewed head|The head entry|SCIM directory unavailable|Nothing)/;

type Statement = { sql: string; params: unknown[] };
const statement = (sql: string, ...params: unknown[]): Statement => ({ sql, params });
async function commit(env: AuthEnv, statements: Statement[]) {
  await env.DB.batch(statements.map(s => env.DB.prepare(s.sql).bind(...s.params)));
}

/** Calls an internal operation of a connection's Durable Object (never reachable from /scim/v2). */
async function directory(env: AuthEnv, connection: string, op: "requeue" | "outbox" | "skip", body?: unknown) {
  if (!env.SCIM_DIRECTORY) throw reject("SCIM directory unavailable");
  const response = await env.SCIM_DIRECTORY.getByName("connection:" + connection).fetch(new Request("https://scim.internal/__nathan/" + op, {
    method: op === "outbox" ? "GET" : "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "X-Nathan-SCIM-Base": new URL(env.NATHAN_ISSUER).origin + "/scim/v2/" + connection, "X-Nathan-SCIM-Admin": op,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }) }
  }));
  return { ok: response.ok, status: response.status, body: await response.json().catch(() => ({})) as any };
}

type ReviewRow = { id: string; connection: string; scimId: string; userId: string; action: "link" | "deprovision"; cause: string | null;
  state: string; email: string; verified: unknown };
async function loadReview(env: AuthEnv, connection: string, id: unknown): Promise<ReviewRow> {
  if (typeof id !== "string" || !UUID.test(id)) throw reject("Invalid review id");
  const row = await env.DB.prepare('SELECT r.id, r.connection_id AS connection, r.scim_id AS scimId, r.user_id AS userId, r.action, r.cause, r.state, ' +
    'lower(u."email") AS email, u."emailVerified" AS verified FROM nathan_scim_reviews r JOIN "user" u ON u."id"=r.user_id WHERE r.id=? AND r.connection_id=?')
    .bind(id, connection).first<ReviewRow>();
  if (!row) throw reject("Unknown review item");
  if (row.state !== "pending") throw reject("Review item is no longer pending (" + row.state + ")");
  return row;
}
async function linkedUser(env: AuthEnv, connection: string, scimId: unknown) {
  if (typeof scimId !== "string" || !UUID.test(scimId)) throw reject("Invalid SCIM user id");
  const row = await env.DB.prepare('SELECT s.scim_id AS scimId, s.user_id AS userId, s.active, s.deleted, s.link_state AS state, lower(u."email") AS email ' +
    'FROM nathan_scim_users s JOIN "user" u ON u."id"=s.user_id WHERE s.connection_id=? AND s.scim_id=?')
    .bind(connection, scimId).first<{ scimId: string; userId: string; active: number; deleted: number; state: string; email: string }>();
  if (!row) throw reject("No linked directory user with that SCIM id in this connection");
  return row;
}

/** approve | dismiss (a review item), keep-active | unlink (a linked directory user). */
export async function scimUserOperation(env: AuthEnv, input: any, actor: string) {
  const op = input?.op;
  const target = [input?.connection, input?.review ?? input?.scimId].filter(v => typeof v === "string").join(":");
  const action = op === "approve" || op === "dismiss" ? "scim_review_" + op : op === "keep-active" ? "scim_user_keep_active" : op === "unlink" ? "scim_user_unlink" : "scim_user_operation";
  return guarded(env, actor, action, target, async () => {
    const connection = await requireConnection(env, input?.connection);
    if (op === "approve") return approve(env, connection, input, actor);
    if (op === "dismiss") return dismiss(env, connection, input, actor);
    if (op === "keep-active") return keepActive(env, connection, input, actor);
    if (op === "unlink") return unlink(env, connection, input, actor);
    throw reject("Invalid SCIM user operation");
  });
}

async function approve(env: AuthEnv, connection: string, input: any, actor: string) {
  const review = await loadReview(env, connection, input.review);
  if (input.confirm !== "CONFIRM APPROVE " + review.action.toUpperCase() + " " + review.email) throw reject("Exact confirmation required");
  if (review.action === "deprovision") {
    if (review.userId === actor) throw reject("An administrator cannot approve their own deprovisioning");
    if (await otherActiveAdmins(env, review.userId) === 0) throw reject("The last administrator is never deprovisioned by SCIM");
  } else {
    if (review.verified !== 1 && review.verified !== true) throw reject("The Nathan user's email is not verified; it cannot be linked");
    // A deleted identity with the same externalId in this connection hands its link over (a rehire).
    if (await env.DB.prepare("SELECT 1 FROM nathan_scim_users s WHERE s.user_id=? AND NOT (s.connection_id=? AND s.deleted=1 AND " +
      "s.external_id=(SELECT external_id FROM nathan_scim_users WHERE connection_id=? AND scim_id=?))")
      .bind(review.userId, connection, connection, review.scimId).first())
      throw reject("That Nathan user is already linked to a directory user");
  }
  await commit(env, [
    statement("UPDATE nathan_scim_reviews SET state='approved', decided_by=?, decided_at=unixepoch() WHERE id=? AND state='pending'", actor, review.id),
    auditStatement(actor, "scim_review_approve", connection + ":" + review.userId + ":" + review.action, "succeeded")
  ]);
  // The Durable Object re-applies the directory user now; the approval is consumed exactly once.
  const applied = await directory(env, connection, "requeue", { kind: "User", id: review.scimId }).catch(() => null);
  const state = (await env.DB.prepare("SELECT state FROM nathan_scim_reviews WHERE id=?").bind(review.id).first<{ state: string }>())?.state;
  return { review: review.id, action: review.action, user: review.email, state, applied: state === "applied",
    note: state === "applied" ? (review.action === "link" ? "Linked." : "Deprovisioned: blocked, sessions ended, tokens revoked, back-channel logout queued.")
      : state === "approved" ? "Approved; it applies with the next reconciliation of this connection" + (applied?.ok ? "." : " (the directory object is busy or unavailable).")
        : "The directory's state changed; nothing was applied (" + state + ")." };
}

async function dismiss(env: AuthEnv, connection: string, input: any, actor: string) {
  const review = await loadReview(env, connection, input.review);
  if (input.confirm !== "CONFIRM DISMISS " + review.action.toUpperCase() + " " + review.email) throw reject("Exact confirmation required");
  const statements = [
    statement("UPDATE nathan_scim_reviews SET state='dismissed', decided_by=?, decided_at=unixepoch() WHERE id=? AND state='pending'", actor, review.id),
    auditStatement(actor, "scim_review_dismiss", connection + ":" + review.userId + ":" + review.action, "succeeded")
  ];
  if (review.action === "deprovision")
    // Recorded like keep-active, for the directory's current cause: replays of this deprovisioning
    // leave the administrator alone; a new deprovision change opens a new review.
    statements.push(statement("UPDATE nathan_scim_users SET override_cause=CASE WHEN deleted=1 THEN 'deleted' ELSE 'deactivated' END, override_by=?, override_at=unixepoch(), " +
      "updated_at=unixepoch() WHERE connection_id=? AND scim_id=? AND user_id=?", actor, connection, review.scimId, review.userId));
  else
    statements.push(statement("UPDATE nathan_scim_users SET link_hold=?, link_note=?, updated_at=unixepoch() WHERE connection_id=? AND scim_id=?",
      "Link to " + review.email + " dismissed by an administrator; not linked automatically", "Link dismissed by an administrator", connection, review.scimId));
  await commit(env, statements);
  return { review: review.id, action: review.action, state: "dismissed",
    note: review.action === "link" ? "Not linked; this directory user is not linked automatically again." : "Kept active; a new deprovision change from the directory opens a new review." };
}

async function keepActive(env: AuthEnv, connection: string, input: any, actor: string) {
  const user = await linkedUser(env, connection, input.scimId);
  if (input.confirm !== "CONFIRM KEEP ACTIVE " + user.email) throw reject("Exact confirmation required");
  if (user.state !== "deprovisioned") throw reject("The directory reports this user active; nothing to keep active");
  const cause = user.deleted === 1 ? "deleted" : "deactivated";
  await commit(env, [
    // Only Nathan's own SCIM ban is lifted; an administrator's ban stays.
    statement('UPDATE "user" SET "banned"=0, "banReason"=NULL, "banExpires"=NULL, "updatedAt"=? WHERE "id"=? AND "banned" IN (1,\'1\') AND "banReason"=?',
      new Date().toISOString(), user.userId, scimBanReason(connection)),
    statement("UPDATE nathan_scim_users SET override_cause=?, override_by=?, override_at=unixepoch(), scim_banned=0, link_note=?, updated_at=unixepoch() WHERE connection_id=? AND scim_id=?",
      cause, actor, "Kept active by an administrator", connection, user.scimId),
    statement("UPDATE nathan_scim_reviews SET state='dismissed', decided_by=?, decided_at=unixepoch() WHERE connection_id=? AND scim_id=? AND action='deprovision' AND state IN ('pending','approved')",
      actor, connection, user.scimId),
    changeStatement({ kind: "user.scim_override", principalType: "user", principalId: user.userId, detail: { connection, cause }, actor }),
    auditStatement(actor, "scim_user_keep_active", connection + ":" + user.userId + ":" + cause, "succeeded")
  ]);
  return { user: user.email, keptActive: true, cause,
    note: "Unblocked. Sessions and tokens revoked earlier are not restored. Replays and resyncs keep this; a new deprovision change from the directory applies again." };
}

async function unlink(env: AuthEnv, connection: string, input: any, actor: string) {
  const user = await linkedUser(env, connection, input.scimId);
  if (input.confirm !== "CONFIRM UNLINK " + user.email) throw reject("Exact confirmation required");
  const mapped = "SELECT group_id FROM nathan_scim_group_mappings WHERE connection_id=?";
  await commit(env, [
    statement("INSERT INTO nathan_rbac_changes(kind,principal_type,principal_id,detail,actor) SELECT 'member.removed','user',user_id," +
      "json_object('group',group_id,'source','scim','cause','user.scim_unlinked'),? FROM nathan_group_members WHERE user_id=? AND group_id IN (" + mapped + ") ORDER BY group_id",
      actor, user.userId, connection),
    statement("DELETE FROM nathan_group_members WHERE user_id=? AND group_id IN (" + mapped + ")", user.userId, connection),
    statement("UPDATE nathan_scim_users SET user_id=NULL, link_state='unlinked', link_method=NULL, linked_email=NULL, linked_at=NULL, scim_banned=0, " +
      "override_cause=NULL, override_by=NULL, override_at=NULL, link_hold=?, link_note=?, updated_at=unixepoch() WHERE connection_id=? AND scim_id=?",
      "Unlinked by an administrator; not linked automatically again", "Unlinked by an administrator", connection, user.scimId),
    statement("UPDATE nathan_scim_reviews SET state='superseded', decided_by=?, decided_at=unixepoch() WHERE connection_id=? AND scim_id=? AND state IN ('pending','approved')",
      actor, connection, user.scimId),
    changeStatement({ kind: "user.unlinked", principalType: "user", principalId: user.userId, detail: { connection }, actor }),
    auditStatement(actor, "scim_user_unlink", connection + ":" + user.userId, "succeeded")
  ]);
  return { user: user.email, unlinked: true,
    note: "Directory-maintained group memberships were removed. A block the directory caused stays until an administrator lifts it (keep active before unlinking, or Users)." };
}

/** The head of a connection's reconciliation queue, with what each entry would change. */
export async function scimOutboxView(env: AuthEnv, id: unknown) {
  const connection = await requireConnection(env, id);
  const result = await directory(env, connection, "outbox");
  if (!result.ok) throw reject("SCIM directory unavailable");
  return { connection, ...result.body };
}

/** Skips the failing head entry an administrator reviewed (exact kind, id and sequence). */
export async function skipScimOutbox(env: AuthEnv, input: any, actor: string) {
  const target = [input?.connection, input?.kind, input?.id, input?.seq].filter(v => v !== undefined).join(":").slice(0, 200);
  return guarded(env, actor, "scim_outbox_skip", target, async () => {
    const connection = await requireConnection(env, input?.connection);
    if (input.op !== "skip" || (input.kind !== "User" && input.kind !== "Group") || typeof input.id !== "string" || !UUID.test(input.id) || !Number.isSafeInteger(input.seq))
      throw reject("Invalid outbox entry");
    if (input.confirm !== "CONFIRM SKIP " + input.kind.toUpperCase() + " " + input.id) throw reject("Exact confirmation required");
    const result = await directory(env, connection, "skip", { kind: input.kind, id: input.id, seq: input.seq });
    if (!result.ok) throw reject(typeof result.body?.detail === "string" ? result.body.detail : "SCIM directory unavailable");
    const skipped = result.body.skipped;
    await recordError(env, connection, input.kind, input.id, "Skipped by administrator " + actor + " after " + skipped.attempts +
      " failed attempts; Nathan did not apply this change (last error: " + (skipped.lastError ?? "none") + ")");
    await env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(), actor, "scim_outbox_skip", target, "succeeded").run();
    return { connection, skipped, pending: result.body.pending,
      warning: "Nathan did not apply this change. If it deactivated or deleted a user, that user is NOT blocked: block them in Users. " +
        "It is applied again when the resource changes in the directory or on a resync." };
  });
}
