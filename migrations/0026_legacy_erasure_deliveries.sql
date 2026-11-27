-- 0022 joined every consent to every session of the erased user. 0023 captures
-- the actual RP participants. Its stored-token fallback can still have a NULL
-- issued_subject, so that column alone cannot date a pending notification.
--
-- Wrangler and the hosted installer each record migration completion in the
-- same D1 transaction as the schema change. Make both standard ledgers readable
-- on all installations without inserting or altering any migration receipts.
CREATE TABLE IF NOT EXISTS d1_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS nathan_release_migrations (
  name TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL,
  applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- The ledgers and the queue have second precision. A strictly later capture is
-- from the corrected trigger. At the cutover second, or on a manual installation
-- with no receipt, a stored-token fallback and a consent guess can be identical.
WITH cutover AS (
  SELECT MIN(applied) AS applied FROM (
    SELECT unixepoch(applied_at,'auto') AS applied FROM d1_migrations WHERE name='0023_app_rp_sessions.sql'
    UNION ALL
    SELECT applied_at FROM nathan_release_migrations WHERE name='0023_app_rp_sessions.sql'
  )
), uncertain AS (
  SELECT d.id, c.clientId IS NOT NULL AND COALESCE(c.backchannelLogoutSessionRequired,0)=0 AS accepts_subject
  FROM nathan_backchannel_deliveries d LEFT JOIN oauthClient c ON c.clientId=d.client_id
  WHERE d.state='pending' AND d.reason='app-account-erased' AND d.issued_subject IS NULL
    AND NOT EXISTS (SELECT 1 FROM cutover WHERE applied<d.created_at)
    AND (d.session_id IS NOT NULL OR c.clientId IS NULL OR c.backchannelLogoutSessionRequired=1)
    AND NOT EXISTS (SELECT 1 FROM nathan_app_rp_participation p
      WHERE p.user_id=d.user_id AND p.client_id=d.client_id AND p.session_id=d.session_id)
)
UPDATE nathan_backchannel_deliveries AS d
SET session_id=CASE WHEN uncertain.accepts_subject THEN NULL ELSE d.session_id END,
    state=CASE WHEN uncertain.accepts_subject THEN 'pending' ELSE 'failed' END,
    last_status=CASE WHEN uncertain.accepts_subject THEN d.last_status ELSE 'unproven_erasure_session' END,
    updated_at=unixepoch()
FROM uncertain WHERE d.id=uncertain.id;

INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
SELECT 'migration:0026:'||id,'system:migration','backchannel_logout_retired',id,'refused'
FROM nathan_backchannel_deliveries WHERE reason='app-account-erased' AND state='failed' AND last_status='unproven_erasure_session'
ON CONFLICT(id) DO NOTHING;
