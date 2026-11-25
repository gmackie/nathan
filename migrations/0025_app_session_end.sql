-- Only an explicit customer sign-out arms the session. Expiring an OP session
-- alone must not end every RP session that was established through it.
CREATE TABLE nathan_app_session_ends (
  session_id TEXT PRIMARY KEY REFERENCES "session"(id) ON DELETE CASCADE
);

-- A code exchange can finish after sign-out has started. The exchange records
-- participation while the OP session still exists, before returning tokens.
-- Capture any such final RP in the transaction that actually deletes the session.
CREATE TRIGGER nathan_capture_ending_session BEFORE DELETE ON "session"
WHEN EXISTS (SELECT 1 FROM nathan_app_session_ends WHERE session_id=OLD.id)
BEGIN
  INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,issued_subject,session_id,reason)
    SELECT json_array('app-session-end',OLD.id,p.client_id,p.rp_subject),p.client_id,OLD.userId,p.rp_subject,OLD.id,'app-session-end'
    FROM nathan_app_rp_sessions p JOIN oauthClient c ON c.clientId=p.client_id
    WHERE p.user_id=OLD.userId AND p.session_id=OLD.id AND p.rp_sid=OLD.id
      AND p.rp_subject<>'' AND c.backchannelLogoutUri IS NOT NULL AND COALESCE(c.disabled,0)=0
    ON CONFLICT(id) DO NOTHING;
END;
