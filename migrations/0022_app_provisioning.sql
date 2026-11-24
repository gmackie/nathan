-- The external ID belongs to the calling application's user store. Its hash is
-- scoped to that application; a matching email alone can never acquire a mapping.
CREATE TABLE nathan_app_provisions (
  -- Keep the source binding when an operator removes the application registry
  -- row. That action withdraws admission rather than converting the subject
  -- into a normal verified account with independent email sign-in.
  app_id TEXT NOT NULL,
  external_id_hash TEXT NOT NULL,
  -- Allows exact erasure retries without retaining the deleted live subject.
  subject_hash TEXT NOT NULL,
  user_id TEXT UNIQUE REFERENCES "user"(id) ON DELETE SET NULL,
  email TEXT,
  grant_revision INTEGER NOT NULL DEFAULT 0 CHECK(grant_revision>=0),
  desired_roles TEXT NOT NULL DEFAULT '["member"]' CHECK(json_valid(desired_roles) AND json_type(desired_roles)='array'),
  erased_revision INTEGER CHECK(erased_revision IS NULL OR erased_revision=grant_revision),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (app_id, external_id_hash)
);

-- Preserve the idempotency key after deletion without retaining the mailbox.
CREATE TRIGGER nathan_retire_app_provision AFTER UPDATE OF user_id ON nathan_app_provisions
WHEN NEW.user_id IS NULL
BEGIN
  UPDATE nathan_app_provisions SET email=NULL WHERE app_id=NEW.app_id AND external_id_hash=NEW.external_id_hash;
END;

-- Better Auth cascades sessions, credentials, OAuth tokens and consents on user
-- deletion. Capture logout recipients before those foreign keys run, including
-- offline grants with no live session. Remove in-flight proofs in the same delete.
CREATE TRIGGER nathan_erase_app_credentials BEFORE DELETE ON "user"
WHEN EXISTS (SELECT 1 FROM nathan_app_provisions WHERE user_id=OLD.id)
BEGIN
  INSERT INTO nathan_backchannel_deliveries(id,client_id,user_id,session_id,reason)
    SELECT lower(hex(randomblob(16))),t.clientId,OLD.id,t.sessionId,'app-account-erased' FROM (
      SELECT clientId,sessionId FROM oauthAccessToken WHERE userId=OLD.id UNION
      SELECT clientId,sessionId FROM oauthRefreshToken WHERE userId=OLD.id UNION
      SELECT c.clientId,s.id FROM oauthConsent c LEFT JOIN session s ON s.userId=c.userId WHERE c.userId=OLD.id
    ) t JOIN oauthClient c ON c.clientId=t.clientId WHERE c.backchannelLogoutUri IS NOT NULL AND COALESCE(c.disabled,0)=0;
  DELETE FROM verification WHERE identifier IN (
    SELECT 'nathan-email:'||generation FROM nathan_email_sign_ins WHERE subject_id=OLD.id OR email=OLD.email
    UNION SELECT 'hosted-email-'||generation FROM nathan_email_sign_ins WHERE subject_id=OLD.id OR email=OLD.email
  ) OR CASE WHEN json_valid(value) THEN json_extract(value,'$.userId') END=OLD.id;
  DELETE FROM nathan_email_sign_ins WHERE subject_id=OLD.id OR email=OLD.email;
  DELETE FROM nathan_email_delivery_order WHERE email=OLD.email;
  DELETE FROM nathan_mcp_artifacts WHERE kind IN ('consent','code') AND json_extract(data,'$.userId')=OLD.id;
END;

CREATE VIEW nathan_provisionable_apps AS
SELECT a.id,a.hostname FROM nathan_applications a
JOIN nathan_rbac_roles r ON r.app_id=a.id AND r.key='member'
WHERE a.enabled=1 AND a.access_mode='approved' AND NOT EXISTS(
  SELECT 1 FROM nathan_rbac_role_permissions WHERE app_id=a.id AND role_key='member' AND permission_key<>'profile:read'
);

CREATE VIEW nathan_app_provision_subjects AS
SELECT p.app_id,p.external_id_hash,p.user_id,p.email,p.grant_revision,p.desired_roles,a.hostname
FROM nathan_app_provisions p
JOIN "user" u ON u.id=p.user_id AND u.email=p.email
JOIN nathan_provisionable_apps a ON a.id=p.app_id
WHERE COALESCE(u.banned,0)=0 AND COALESCE(u.role,'user')='user'
  AND NOT EXISTS (SELECT 1 FROM nathan_admin_grants WHERE user_id=u.id AND enabled=1)
  AND NOT EXISTS (SELECT 1 FROM nathan_bootstrap_status WHERE admin_user_id=u.id OR admin_email=u.email COLLATE NOCASE)
  AND NOT EXISTS (SELECT 1 FROM nathan_scim_users WHERE user_id=u.id AND link_state='deprovisioned' AND override_cause IS NULL);

-- Email admission and live app decisions require a current membership and
-- cannot be recovered by replaying a grant or by changing a user's email.
CREATE VIEW nathan_active_app_provisions AS
SELECT p.* FROM nathan_app_provision_subjects p
JOIN nathan_rbac_grants g ON g.app_id=p.app_id AND g.role_key='member'
  AND g.principal_type='user' AND g.principal_id=p.user_id
WHERE p.desired_roles<>'[]';

-- The compare-and-swap on the source revision, the grant changes and their feed
-- events are a single write. A Studio grant for the same subject remains owned
-- by Studio, even if a later source revision includes or removes that role.
CREATE TRIGGER nathan_reconcile_app_grants AFTER UPDATE OF grant_revision ON nathan_app_provisions
WHEN NEW.grant_revision>OLD.grant_revision
BEGIN
  INSERT INTO nathan_rbac_changes(kind,app_id,principal_type,principal_id,detail,actor)
    SELECT 'grant.revoked',app_id,'user',principal_id,json_object('role',role_key),created_by
    FROM nathan_rbac_grants WHERE app_id=NEW.app_id AND principal_type='user' AND principal_id=NEW.user_id
      AND created_by='app-provision:'||NEW.app_id AND role_key NOT IN (SELECT value FROM json_each(NEW.desired_roles));
  DELETE FROM nathan_rbac_grants WHERE app_id=NEW.app_id AND principal_type='user' AND principal_id=NEW.user_id
    AND created_by='app-provision:'||NEW.app_id AND role_key NOT IN (SELECT value FROM json_each(NEW.desired_roles));
  INSERT INTO nathan_rbac_changes(kind,app_id,principal_type,principal_id,detail,actor)
    SELECT 'grant.created',NEW.app_id,'user',NEW.user_id,json_object('role',wanted.value),'app-provision:'||NEW.app_id
    FROM json_each(NEW.desired_roles) wanted WHERE NOT EXISTS(
      SELECT 1 FROM nathan_rbac_grants WHERE app_id=NEW.app_id AND role_key=wanted.value AND principal_type='user' AND principal_id=NEW.user_id
    );
  INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by)
    SELECT lower(hex(randomblob(16))),NEW.app_id,wanted.value,'user',NEW.user_id,'app-provision:'||NEW.app_id
    FROM json_each(NEW.desired_roles) wanted WHERE true ON CONFLICT(app_id,role_key,principal_type,principal_id) DO NOTHING;
END;
