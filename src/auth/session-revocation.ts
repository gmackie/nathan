/** Revoke every pre-existing session and token, including offline grants. Callers
 * enqueue logout deliveries first, while the tokens still carry their session IDs. */
export function revokeUserSessions(userId: string, now: string) {
  return [
    { sql: 'UPDATE "oauthAccessToken" SET revoked=? WHERE userId=? AND revoked IS NULL', params: [now, userId] },
    { sql: 'UPDATE "oauthRefreshToken" SET revoked=? WHERE userId=? AND revoked IS NULL', params: [now, userId] },
    { sql: 'DELETE FROM "session" WHERE userId=?', params: [userId] }
  ];
}

/** Retire the access a provisional account held before proving its mailbox. The
 * promotion transaction includes this cleanup and preserves administrator-assigned roles. */
export function retireUnverifiedAccess(db: D1Database, userId: string) {
  return [
    db.prepare("INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,session_id,reason) " +
      "SELECT lower(hex(randomblob(16))),c.clientId,?1,t.sessionId,'email-otp-promotion' FROM (" +
      "SELECT clientId,sessionId FROM oauthAccessToken WHERE userId=?1 AND sessionId IS NOT NULL UNION " +
      "SELECT clientId,sessionId FROM oauthRefreshToken WHERE userId=?1 AND sessionId IS NOT NULL UNION " +
      "SELECT a.clientId,s.id FROM oauthConsent a JOIN session s ON s.userId=a.userId WHERE a.userId=?1) t " +
      "JOIN oauthClient c ON c.clientId=t.clientId WHERE c.backchannelLogoutUri IS NOT NULL AND COALESCE(c.disabled,0)=0").bind(userId),
    db.prepare("DELETE FROM oauthConsent WHERE userId=?").bind(userId),
    // Grant deletion cascades to refresh tokens. Consent tickets and unused codes
    // precede grant creation and carry their owning subject in the stored artifact.
    db.prepare("DELETE FROM nathan_mcp_artifacts WHERE kind IN ('consent','code') AND json_extract(data,'$.userId')=?").bind(userId),
    db.prepare("DELETE FROM nathan_mcp_grants WHERE user_id=?").bind(userId),
    db.prepare("DELETE FROM account WHERE userId=?").bind(userId),
    ...revokeUserSessions(userId, new Date().toISOString()).map(({ sql, params }) => db.prepare(sql).bind(...params))
  ];
}
