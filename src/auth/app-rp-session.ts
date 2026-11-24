import { decodeJwt } from "jose";
import type { AuthEnv } from "./env";
import { issuerOf } from "./rbac";

/** Called exclusively on a successful token response from the private issuer's own handler,
 * before the RP can receive the tokens. The access token identifies Nathan's user; a pairwise
 * ID token can give the RP a different subject. Preserve what the RP actually received. */
export async function recordAppRpSession(env: AuthEnv, response: Response) {
  const { id_token, access_token } = await response.clone().json<{ id_token?: string; access_token: string }>();
  if (id_token === undefined) return;
  const id = decodeJwt(id_token), access = decodeJwt(access_token), issuer = issuerOf(env);
  const session = access.sid ?? id.sid ?? "";
  if (id.iss !== issuer || access.iss !== issuer || typeof id.aud !== "string" || id.aud !== access.client_id ||
      typeof access.sub !== "string" || !access.sub || typeof id.sub !== "string" || !id.sub ||
      typeof session !== "string" || (id.sid !== undefined && id.sid !== session) ||
      (access.principal_kind !== "agent" && (access.principal_kind !== "user" || !session)))
    throw Error("Invalid issued application session");
  // Registered agents can refresh offline. Only a human user grant requires its live Nathan
  // session here; both still require the underlying user when recording what the RP receives.
  const recorded = await env.DB.prepare(
    "INSERT INTO nathan_app_rp_sessions(user_id,client_id,session_id,rp_subject,rp_sid) " +
    "SELECT id,?1,?2,?3,?4 FROM user WHERE id=?5 AND (?6=1 OR EXISTS(SELECT 1 FROM session s WHERE s.userId=user.id AND s.id=?2)) " +
    "ON CONFLICT(user_id,client_id,session_id,rp_subject) DO UPDATE SET rp_sid=COALESCE(excluded.rp_sid,rp_sid) RETURNING user_id"
  ).bind(id.aud, session, id.sub, id.sid ?? null, access.sub, Number(access.principal_kind === "agent")).first();
  // Erasure concurrent with token issuance either captures this participation or wins first.
  if (!recorded) throw Error("Application session ended");
}
