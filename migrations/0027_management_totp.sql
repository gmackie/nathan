-- Evidence of a successful management TOTP challenge. Removing the session or
-- replacing the verified authenticator invalidates its evidence immediately.
CREATE TABLE nathan_management_totp (
  session_id TEXT PRIMARY KEY NOT NULL REFERENCES "session"(id) ON DELETE CASCADE,
  factor_id TEXT NOT NULL REFERENCES "twoFactor"(id) ON DELETE CASCADE,
  verified_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX nathan_management_totp_factor ON nathan_management_totp(factor_id);

-- Remember accepted time steps across session expiry and sign-out.
CREATE TABLE nathan_management_totp_steps (
  factor_id TEXT PRIMARY KEY NOT NULL REFERENCES "twoFactor"(id) ON DELETE CASCADE,
  last_step INTEGER NOT NULL,
  passkey_proof_until INTEGER NOT NULL
);
-- Close the interval between checking enrollment policy and Better Auth's activation write.
CREATE TRIGGER nathan_management_totp_activate BEFORE UPDATE OF verified ON "twoFactor"
WHEN OLD.verified IS NOT 1 AND NEW.verified=1
  AND EXISTS(SELECT 1 FROM nathan_management_totp_steps WHERE factor_id=NEW.id AND passkey_proof_until<unixepoch())
  AND EXISTS(SELECT 1 FROM passkey WHERE userId=NEW.userId)
BEGIN
  SELECT RAISE(ABORT,'Verify your enrolled passkey before activating this authenticator');
END;

ALTER TABLE nathan_admin_grants ADD COLUMN grant_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nathan_bootstrap_status ADD COLUMN owner_invitation_id TEXT REFERENCES nathan_invitations(id);
-- Older installations keep their invitation history. Ambiguous histories use operator promotion.
UPDATE nathan_bootstrap_status AS b SET owner_invitation_id=(
  SELECT min(i.id) FROM nathan_invitations i WHERE i.email=b.admin_email AND i.created_by=b.cloudflare_user_id
  HAVING count(*)=1 AND count(i.revoked_at)=0
) WHERE b.state='pending' AND b.admin_user_id IS NULL;
