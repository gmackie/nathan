/**
 * NATH-11: Identity Studio operations for SCIM lifecycle: per-connection linking and just-in-time
 * toggles, explicit SCIM group → Nathan group mappings, and the connection status view.
 * Callers (src/auth/worker.ts) have already required an enrolled, stepped-up administrator and a
 * same-origin JSON request. Every attempt is audited: succeeded, failed, or rejected before writing.
 */
import type { AuthEnv } from "../env";
import { audit } from "../admin-service";
import { isGroupId } from "../../shared/policy.mjs";
import { changeStatement, auditStatement } from "../../shared/rbac-store.mjs";
import { isVerifiedDomain } from "./lifecycle";

const CID = /^[a-z][a-z0-9-]{1,62}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Messages safe to show an administrator; anything else becomes a generic rejection. */
export const SCIM_ADMIN_ERRORS = /^(Unknown SCIM connection|Exact confirmation|Invalid|Just-in-time creation needs|Map an empty|Only Identity Studio groups|This Nathan group|That SCIM group|Unknown group|No mapping)/;

export class Rejected extends Error {}
export const reject = (message: string) => new Rejected(message);
export async function guarded<T>(env: AuthEnv, actor: string, action: string, target: string, fn: () => Promise<T>): Promise<T> {
  try { return await fn(); }
  catch (error) {
    await audit(env, actor, action, target.slice(0, 200) || "-", error instanceof Rejected ? "rejected" : "failed").catch(() => {});
    throw error;
  }
}
export async function requireConnection(env: AuthEnv, id: unknown) {
  if (typeof id !== "string" || !CID.test(id)) throw reject("Invalid SCIM connection id");
  const row = await env.DB.prepare("SELECT id FROM nathan_scim_connections WHERE id=?").bind(id).first();
  if (!row) throw reject("Unknown SCIM connection");
  return id;
}
/** Asks the connection's Durable Object to re-apply every staged resource (forced, idempotent). */
export async function resyncConnection(env: AuthEnv, connectionId: string): Promise<{ applied: boolean; pending?: number }> {
  if (!env.SCIM_DIRECTORY) return { applied: false };
  try {
    const response = await env.SCIM_DIRECTORY.getByName("connection:" + connectionId).fetch(new Request("https://scim.internal/__nathan/resync", {
      method: "POST",
      headers: { "X-Nathan-SCIM-Base": new URL(env.NATHAN_ISSUER).origin + "/scim/v2/" + connectionId, "X-Nathan-SCIM-Admin": "resync" }
    }));
    const body: any = await response.json().catch(() => ({}));
    // `pending` > 0 with 200: a large directory continues in the background (the connection's alarm).
    return response.ok ? { applied: true, pending: Number(body?.pending ?? 0) } : { applied: false, pending: Number(body?.pending ?? 0) };
  } catch { return { applied: false }; }
}

export async function updateScimSettings(env: AuthEnv, input: any, actor: string) {
  const target = String(input?.id ?? "-");
  return guarded(env, actor, "scim_settings_update", target, async () => {
    const id = await requireConnection(env, input?.id);
    if (typeof input.linking !== "boolean" || typeof input.jit !== "boolean") throw reject("Invalid SCIM settings");
    if (input.confirm !== "CONFIRM SCIM SETTINGS " + id) throw reject("Exact confirmation required");
    if (input.jit && !input.linking) throw reject("Just-in-time creation needs linking enabled");
    await env.DB.batch([
      env.DB.prepare("UPDATE nathan_scim_connections SET linking_enabled=?, jit_enabled=?, updated_at=unixepoch() WHERE id=?")
        .bind(input.linking ? 1 : 0, input.jit ? 1 : 0, id),
      env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
        .bind(crypto.randomUUID(), actor, "scim_settings_update", id + ":linking=" + input.linking + ",jit=" + input.jit, "succeeded")
    ]);
    // Staged users and groups are re-applied under the new policy (links are never undone here).
    return { id, linking: input.linking, jit: input.jit, resync: await resyncConnection(env, id) };
  });
}

export async function changeScimMapping(env: AuthEnv, input: any, actor: string) {
  if (input?.op === "unmap") return unmapGroup(env, input, actor);
  const target = [input?.connection, input?.ref, input?.group].filter(v => typeof v === "string").join(":");
  return guarded(env, actor, "scim_group_map", target, async () => {
    if (input?.op !== "map") throw reject("Invalid mapping operation");
    const connection = await requireConnection(env, input.connection);
    if (input.refType !== "id" && input.refType !== "externalId") throw reject("Invalid SCIM group reference: use its SCIM id or externalId");
    const ref = input.ref;
    if (typeof ref !== "string" || ref.length < 1 || ref.length > 256 || /[\x00-\x1f\x7f]/.test(ref) || (input.refType === "id" && !UUID.test(ref)))
      throw reject("Invalid SCIM group reference");
    if (!isGroupId(input.group)) throw reject("Invalid group id");
    if (input.confirm !== "CONFIRM MAP " + connection + "/" + ref + " TO " + input.group) throw reject("Exact confirmation required");
    const group = await env.DB.prepare("SELECT id, source, (SELECT count(*) FROM nathan_group_members WHERE group_id=g.id) AS members FROM nathan_groups g WHERE id=?")
      .bind(input.group).first<{ id: string; source: string; members: number }>();
    if (!group) throw reject("Unknown group");
    if (await env.DB.prepare("SELECT 1 FROM nathan_scim_group_mappings WHERE group_id=?").bind(group.id).first())
      throw reject("This Nathan group is already fed by a SCIM group");
    if (await env.DB.prepare("SELECT 1 FROM nathan_scim_group_mappings WHERE connection_id=? AND ref_type=? AND ref_value=?").bind(connection, input.refType, ref).first())
      throw reject("That SCIM group is already mapped");
    if (group.source !== "studio") throw reject("Only Identity Studio groups can be mapped");
    if (Number(group.members) > 0) throw reject("Map an empty group: its membership will be maintained by the directory");
    await env.DB.batch([
      env.DB.prepare("INSERT INTO nathan_scim_group_mappings(id,connection_id,ref_type,ref_value,group_id,created_by) VALUES (?,?,?,?,?,?)")
        .bind(crypto.randomUUID(), connection, input.refType, ref, group.id, actor),
      env.DB.prepare("UPDATE nathan_groups SET source='scim', updated_at=unixepoch() WHERE id=?").bind(group.id),
      ...[changeStatement({ kind: "group.scim_mapped", principalType: "group", principalId: group.id, detail: { connection, refType: input.refType, ref }, actor }),
        auditStatement(actor, "scim_group_map", connection + ":" + ref.slice(0, 100) + ":" + group.id, "succeeded")]
        .map(s => env.DB.prepare(s.sql).bind(...s.params))
    ]);
    return { connection, refType: input.refType, ref, group: group.id, resync: await resyncConnection(env, connection),
      note: "Mapping grants nothing by itself; grant roles to the group in Roles and access" };
  });
}
async function unmapGroup(env: AuthEnv, input: any, actor: string) {
  return guarded(env, actor, "scim_group_unmap", String(input?.group ?? "-"), async () => {
    const connection = await requireConnection(env, input.connection);
    if (!isGroupId(input.group)) throw reject("Invalid group id");
    if (input.confirm !== "CONFIRM UNMAP " + input.group) throw reject("Exact confirmation required");
    const mapping = await env.DB.prepare("SELECT id FROM nathan_scim_group_mappings WHERE connection_id=? AND group_id=?")
      .bind(connection, input.group).first<{ id: string }>();
    if (!mapping) throw reject("No mapping for that group in this connection");
    // Directory-derived memberships go with the mapping; the group and its grants stay.
    await env.DB.batch([
      env.DB.prepare("INSERT INTO nathan_rbac_changes(kind,principal_type,principal_id,detail,actor) " +
        "SELECT 'member.removed','user',user_id,json_object('group',group_id,'source','scim','cause','group.scim_unmapped'),? FROM nathan_group_members WHERE group_id=? ORDER BY user_id")
        .bind(actor, input.group),
      env.DB.prepare("DELETE FROM nathan_group_members WHERE group_id=?").bind(input.group),
      env.DB.prepare("DELETE FROM nathan_scim_group_mappings WHERE id=?").bind(mapping.id),
      env.DB.prepare("UPDATE nathan_groups SET source='studio', updated_at=unixepoch() WHERE id=?").bind(input.group),
      ...[changeStatement({ kind: "group.scim_unmapped", principalType: "group", principalId: input.group, detail: { connection }, actor }),
        auditStatement(actor, "scim_group_unmap", connection + ":" + input.group, "succeeded")].map(s => env.DB.prepare(s.sql).bind(...s.params))
    ]);
    return { connection, group: input.group, unmapped: true };
  });
}

/** Studio view of one connection: policy, link status, mappings, last sync, error log, logout queue. */
export async function scimConnectionView(env: AuthEnv, id: unknown) {
  if (typeof id !== "string" || !CID.test(id)) throw reject("Invalid SCIM connection id");
  const [connections, users, groups, mappings, errors, deliveries, reviews] = (await env.DB.batch([
    env.DB.prepare("SELECT id, domain, organization_id AS organizationId, enabled, linking_enabled AS linking, jit_enabled AS jit, " +
      "last_sync_at AS lastSyncAt, last_error_at AS lastErrorAt FROM nathan_scim_connections WHERE id=?").bind(id),
    env.DB.prepare('SELECT s.scim_id AS scimId, s.external_id AS externalId, s.user_name AS userName, s.active, s.deleted, s.link_state AS linkState, ' +
      's.link_method AS linkMethod, s.link_note AS note, s.user_id AS userId, u."email" AS email, s.link_hold AS linkHold, ' +
      's.override_cause AS overrideCause, s.override_by AS overrideBy, s.override_at AS overrideAt, s.updated_at AS updatedAt ' +
      'FROM nathan_scim_users s LEFT JOIN "user" u ON u."id"=s.user_id WHERE s.connection_id=? ORDER BY s.user_name LIMIT 500').bind(id),
    env.DB.prepare("SELECT scim_id AS scimId, external_id AS externalId, display_name AS displayName, members, deleted, updated_at AS updatedAt " +
      "FROM nathan_scim_groups WHERE connection_id=? ORDER BY display_name LIMIT 500").bind(id),
    env.DB.prepare("SELECT m.ref_type AS refType, m.ref_value AS ref, m.group_id AS \"group\", g.name AS groupName, m.created_by AS createdBy, m.created_at AS createdAt " +
      "FROM nathan_scim_group_mappings m JOIN nathan_groups g ON g.id=m.group_id WHERE m.connection_id=? ORDER BY m.group_id").bind(id),
    env.DB.prepare("SELECT resource_type AS resourceType, resource_id AS resourceId, message, created_at AS createdAt FROM nathan_scim_errors " +
      "WHERE connection_id=? ORDER BY created_at DESC LIMIT 50").bind(id),
    env.DB.prepare("SELECT state, count(*) AS n FROM nathan_backchannel_deliveries WHERE connection_id=? GROUP BY state").bind(id),
    env.DB.prepare('SELECT r.id, r.scim_id AS scimId, s.user_name AS userName, r.user_id AS userId, u."email" AS email, r.action, r.cause, r.reason, r.state, ' +
      'r.created_at AS createdAt, r.decided_by AS decidedBy, r.decided_at AS decidedAt FROM nathan_scim_reviews r LEFT JOIN "user" u ON u."id"=r.user_id ' +
      "LEFT JOIN nathan_scim_users s ON s.connection_id=r.connection_id AND s.scim_id=r.scim_id " +
      "WHERE r.connection_id=? ORDER BY r.state IN ('pending','approved') DESC, r.created_at DESC LIMIT 100").bind(id)
  ])).map(r => (r.results ?? []) as any[]);
  const c = connections[0];
  if (!c) throw reject("Unknown SCIM connection");
  return {
    connection: {
      id: c.id, domain: c.domain, enabled: c.enabled === 1, linking: c.linking === 1, jit: c.jit === 1,
      domainVerified: await isVerifiedDomain(env, String(c.domain).toLowerCase(), c.organizationId ?? null),
      lastSyncAt: c.lastSyncAt ? new Date(c.lastSyncAt * 1000).toISOString() : null,
      lastErrorAt: c.lastErrorAt ? new Date(c.lastErrorAt * 1000).toISOString() : null,
      baseUrl: new URL("/scim/v2/" + c.id, env.NATHAN_ISSUER).href
    },
    users: users.map(u => ({ ...u, active: u.active === 1, deleted: u.deleted === 1 })),
    groups: groups.map(g => ({ ...g, deleted: g.deleted === 1 })),
    mappings, errors,
    // Directory changes held for an administrator (src/auth/scim/reviews.ts): pending first.
    reviews,
    logoutDeliveries: Object.fromEntries(deliveries.map(d => [d.state, d.n]))
  };
}
