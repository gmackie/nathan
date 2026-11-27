-- Evidence of a successful management TOTP challenge. Removing the session or
-- replacing the verified authenticator invalidates its evidence immediately.
CREATE TABLE nathan_management_totp (
  session_id TEXT PRIMARY KEY NOT NULL REFERENCES "session"(id) ON DELETE CASCADE,
  factor_id TEXT NOT NULL REFERENCES "twoFactor"(id) ON DELETE CASCADE,
  verified_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX nathan_management_totp_factor ON nathan_management_totp(factor_id);

-- Keep each accepted step through the code's validity window, even after sign-out.
CREATE TABLE nathan_management_totp_steps (
  factor_id TEXT NOT NULL REFERENCES "twoFactor"(id) ON DELETE CASCADE,
  step INTEGER NOT NULL,
  PRIMARY KEY (factor_id, step)
);

-- An old NULL verification flag denotes enrollment only if the account enabled 2FA.
-- Discard unfinished duplicate setups. Keep every possibly active secret for operator
-- recovery if more than one survives; never select one of those secrets by row order.
DELETE FROM "twoFactor" WHERE verified=0 AND userId IN (
  SELECT userId FROM "twoFactor" GROUP BY userId HAVING count(*)>1
) AND (userId IN (SELECT id FROM "user" WHERE twoFactorEnabled IS NOT 1)
       OR userId IN (SELECT userId FROM "twoFactor" WHERE verified IS NOT 0));
UPDATE "twoFactor" SET verified=1 WHERE verified IS NULL AND userId IN (SELECT id FROM "user" WHERE twoFactorEnabled=1)
  AND userId IN (SELECT userId FROM "twoFactor" GROUP BY userId HAVING count(*)=1);

-- The provider supports one authenticator per user. A trigger also protects new
-- enrollments on installations that still have ambiguous historical rows.
CREATE TRIGGER nathan_totp_single_enrollment BEFORE INSERT ON "twoFactor"
WHEN EXISTS(SELECT 1 FROM "twoFactor" WHERE userId=NEW.userId)
BEGIN
  SELECT RAISE(ABORT,'Authenticator setup already exists');
END;
CREATE TRIGGER nathan_totp_protect_enrollment BEFORE UPDATE OF verified,secret,userId ON "twoFactor"
BEGIN
  SELECT RAISE(ABORT,'Authenticator enrollment changed')
    WHERE OLD.userId<>NEW.userId OR (OLD.verified=1 AND NEW.verified IS NOT 1);
  DELETE FROM nathan_management_totp WHERE factor_id=OLD.id AND NEW.secret<>OLD.secret;
END;

ALTER TABLE nathan_admin_grants ADD COLUMN grant_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nathan_bootstrap_status ADD COLUMN owner_invitation_id TEXT REFERENCES nathan_invitations(id);
-- Older installations keep their invitation history. Ambiguous histories use operator promotion.
UPDATE nathan_bootstrap_status AS b SET owner_invitation_id=(
  SELECT min(i.id) FROM nathan_invitations i WHERE i.email=b.admin_email AND i.created_by=b.cloudflare_user_id
  HAVING count(*)=1 AND count(i.revoked_at)=0
) WHERE b.state='pending' AND b.admin_user_id IS NULL;
