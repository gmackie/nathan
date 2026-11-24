import { decodeJwt } from "jose";
import type { SchemaClient } from "@better-auth/oauth-provider";
import { APIError } from "better-auth/api";
import { makeSignature } from "better-auth/crypto";
import type { AuthEnv } from "./env";
import { issuerOf } from "./rbac";

async function storeParticipation(env: AuthEnv, user: string, client: string, session: string, rpSub: string,
    rpSid: string | null, offlineAgentGrant: boolean) {
  const recorded = await env.DB.prepare(
    "INSERT INTO nathan_app_rp_sessions(user_id,client_id,session_id,rp_subject,rp_sid) " +
    "SELECT id,?1,?2,?3,?4 FROM user WHERE id=?5 AND ((?6=1 AND ?2='') OR EXISTS(" +
    "SELECT 1 FROM session s WHERE s.userId=user.id AND s.id=?2 AND (?6=1 OR " +
    "CASE WHEN typeof(s.expiresAt)='text' THEN unixepoch(s.expiresAt) WHEN s.expiresAt<100000000000 THEN s.expiresAt " +
    "ELSE s.expiresAt/1000 END>unixepoch()))) " +
    "ON CONFLICT(user_id,client_id,session_id,rp_subject) DO UPDATE SET rp_sid=COALESCE(excluded.rp_sid,rp_sid) RETURNING user_id"
  ).bind(client, session, rpSub, rpSid, user, Number(offlineAgentGrant)).first();
  // Concurrent erasure either captures this participation or wins before issuance.
  if (!recorded) throw Error("Application session ended");
}

/** Grants have passed the provider's authorization and our membership checks here, but Better
 * Auth has not rotated the refresh credential yet. Its ID token uses this same client snapshot
 * and session. A storage failure leaves the presented refresh token usable for a retry. */
export async function recordAppRefreshSession(env: AuthEnv, user: string, client: Pick<SchemaClient,
    "clientId" | "subjectType" | "redirectUris" | "enableEndSession" | "backchannelLogoutUri">, session: string | null, agent: boolean) {
  try {
    // Better Auth 1.7.14 derives the pairwise subject from the first registered redirect host.
    let rpSub = user;
    if (client.subjectType === "pairwise" && env.NATHAN_PAIRWISE_SECRET) {
      const sector = new URL(client.redirectUris?.[0] ?? "").host;
      rpSub = await makeSignature(sector + "." + user, env.NATHAN_PAIRWISE_SECRET);
    }
    const rpSid = client.enableEndSession || client.backchannelLogoutUri ? session : null;
    await storeParticipation(env, user, client.clientId, session ?? "", rpSub, rpSid, agent);
  } catch {
    throw new APIError("SERVICE_UNAVAILABLE", { error: "temporarily_unavailable" });
  }
}

/** A successful authorization-code response from this issuer. The access token identifies Nathan's
 * user; the ID token holds the public or pairwise subject the relying party receives. */
export async function recordAppRpSession(env: AuthEnv, response: Response) {
  const { id_token, access_token } = await response.clone().json<{ id_token?: string; access_token: string }>();
  if (id_token === undefined) return;
  const id = decodeJwt(id_token), access = decodeJwt(access_token), issuer = issuerOf(env);
  const rpSid = id.sid ?? null, session = access.sid ?? rpSid ?? "";
  if (id.iss !== issuer || access.iss !== issuer || typeof id.aud !== "string" || id.aud !== access.client_id ||
      typeof access.sub !== "string" || !access.sub || typeof id.sub !== "string" || !id.sub ||
      typeof session !== "string" || !session || (rpSid !== null && rpSid !== session) ||
      (access.principal_kind !== "agent" && access.principal_kind !== "user"))
    throw Error("Invalid issued application session");
  // Initial code exchange, including an agent's delegation, belongs to the issuing browser
  // session. Offline refresh is the only path that may record after browser session deletion.
  await storeParticipation(env, access.sub, id.aud, session, id.sub, rpSid, false);
}
