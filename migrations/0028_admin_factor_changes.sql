-- Retain consumed codes for replay protection even if the enrolled factor changes.
ALTER TABLE nathan_admin_totp_assurance ADD COLUMN invalidated INTEGER NOT NULL DEFAULT 0 CHECK(invalidated IN (0,1));
-- Previously recorded proofs did not track in-place changes to the Better Auth factor.
UPDATE nathan_admin_totp_assurance SET invalidated=1;
CREATE TRIGGER nathan_invalidate_changed_totp AFTER UPDATE OF secret, verified, userId ON twoFactor
WHEN OLD.secret IS NOT NEW.secret OR OLD.userId IS NOT NEW.userId OR NEW.verified IS NOT 1
BEGIN
  UPDATE nathan_admin_totp_assurance SET invalidated=1 WHERE factor_id=OLD.id AND invalidated=0;
END;

CREATE VIEW nathan_enabled_admin_subjects AS
  SELECT admin_user_id AS user_id FROM nathan_bootstrap_status WHERE id='primary' AND admin_user_id IS NOT NULL
  UNION SELECT user_id FROM nathan_admin_grants WHERE enabled=1;

-- Serialize last-key removal with grants and policy tightening. Account deletion can cascade.
CREATE TRIGGER nathan_keep_required_admin_passkey BEFORE DELETE ON passkey
WHEN EXISTS(SELECT 1 FROM nathan_security_overrides WHERE id='primary' AND require_recent_admin_passkey=1)
  AND EXISTS(SELECT 1 FROM user WHERE id=OLD.userId)
  AND EXISTS(SELECT 1 FROM nathan_enabled_admin_subjects WHERE user_id=OLD.userId)
  AND NOT EXISTS(SELECT 1 FROM passkey WHERE userId=OLD.userId AND id<>OLD.id)
BEGIN
  SELECT RAISE(ABORT, 'Enroll another passkey before removing the last administrator passkey');
END;
