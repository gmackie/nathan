-- A JWT-only authorization can leave neither a consent nor a stored token.
-- Keep the exact identifiers received by that RP, even after its Nathan
-- session expires. Deleting the client or the underlying identity removes them.
CREATE TABLE nathan_app_rp_sessions (
  user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES oauthClient(clientId) ON DELETE CASCADE,
  session_id TEXT NOT NULL,
  rp_subject TEXT NOT NULL,
  rp_sid TEXT,
  PRIMARY KEY(user_id, client_id, session_id, rp_subject)
);

-- Preserve participation that an existing token or consent already proves
-- before a later session cleanup nulls those foreign keys. An empty session
-- marks a subject-only legacy grant. An empty subject marks a legacy pairwise
-- identifier whose derivation requires the installation secret at delivery.
CREATE VIEW nathan_stored_rp_grants AS
SELECT userId AS user_id,clientId AS client_id,sessionId AS session_id FROM oauthAccessToken
UNION ALL SELECT userId,clientId,sessionId FROM oauthRefreshToken
UNION ALL SELECT userId,clientId,NULL FROM oauthConsent;

INSERT INTO nathan_app_rp_sessions(user_id,client_id,session_id,rp_subject,rp_sid)
SELECT g.user_id,g.client_id,COALESCE(g.session_id,''),CASE WHEN c.subjectType='pairwise' THEN '' ELSE g.user_id END,g.session_id
FROM nathan_stored_rp_grants g JOIN nathan_app_provisions p ON p.user_id=g.user_id
JOIN oauthClient c ON c.clientId=g.client_id WHERE g.user_id IS NOT NULL ON CONFLICT DO NOTHING;

-- A pairwise subject's sector can change between sign-in and erasure. Queue
-- the exact issued subject when available; previous queue records retain the
-- existing sector calculation.
ALTER TABLE nathan_backchannel_deliveries ADD COLUMN issued_subject TEXT;

CREATE VIEW nathan_app_rp_participation AS
SELECT p.user_id,p.client_id,p.rp_subject AS issued_subject,p.rp_sid AS session_id
FROM nathan_app_rp_sessions p WHERE p.rp_subject<>''
UNION
-- Older installations can prove client participation through a stored grant
-- or consent. Only a token row can also prove which session the client used.
SELECT t.user_id,t.client_id,NULL AS issued_subject,t.session_id
FROM (
  SELECT user_id,client_id,session_id FROM nathan_stored_rp_grants
  UNION ALL SELECT user_id,client_id,rp_sid FROM nathan_app_rp_sessions WHERE rp_subject=''
) t WHERE NOT EXISTS(SELECT 1 FROM nathan_app_rp_sessions p WHERE p.user_id=t.user_id AND p.client_id=t.client_id
  AND p.rp_subject<>'' AND (t.session_id IS NULL OR p.session_id=t.session_id));

CREATE VIEW nathan_app_erasure_recipients AS
SELECT DISTINCT e.user_id,e.client_id,e.issued_subject,
  CASE WHEN c.backchannelLogoutSessionRequired=1 THEN e.session_id END AS session_id
FROM nathan_app_rp_participation e JOIN oauthClient c ON c.clientId=e.client_id
WHERE c.backchannelLogoutUri IS NOT NULL AND COALESCE(c.disabled,0)=0
  AND (COALESCE(c.backchannelLogoutSessionRequired,0)=0 OR e.session_id IS NOT NULL)
  AND (c.backchannelLogoutSessionRequired=1 OR e.issued_subject IS NOT NULL OR NOT EXISTS(
    SELECT 1 FROM nathan_app_rp_sessions p WHERE p.user_id=e.user_id AND p.client_id=e.client_id AND p.rp_subject<>''));

-- A pending erasure captured under 0022 may have associated consent with
-- unrelated sessions of the same user. A subject-capable RP can revoke them all.
UPDATE nathan_backchannel_deliveries SET session_id=NULL WHERE reason='app-account-erased' AND state='pending'
  AND EXISTS(SELECT 1 FROM oauthClient c WHERE c.clientId=client_id AND COALESCE(c.backchannelLogoutSessionRequired,0)=0);

DROP TRIGGER nathan_erase_app_credentials;
CREATE TRIGGER nathan_erase_app_credentials BEFORE DELETE ON "user"
WHEN EXISTS (SELECT 1 FROM nathan_app_provisions WHERE user_id=OLD.id)
BEGIN
  INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,issued_subject,session_id,reason)
    SELECT lower(hex(randomblob(16))),client_id,user_id,issued_subject,session_id,'app-account-erased'
    FROM nathan_app_erasure_recipients WHERE user_id=OLD.id;
  DELETE FROM verification WHERE identifier IN (
    SELECT 'nathan-email:'||generation FROM nathan_email_sign_ins WHERE subject_id=OLD.id OR email=OLD.email
    UNION SELECT 'hosted-email-'||generation FROM nathan_email_sign_ins WHERE subject_id=OLD.id OR email=OLD.email
  ) OR CASE WHEN json_valid(value) THEN json_extract(value,'$.userId') END=OLD.id;
  DELETE FROM nathan_email_sign_ins WHERE subject_id=OLD.id OR email=OLD.email;
  DELETE FROM nathan_email_delivery_order WHERE email=OLD.email;
  DELETE FROM nathan_mcp_artifacts WHERE kind IN ('consent','code') AND json_extract(data,'$.userId')=OLD.id;
END;
