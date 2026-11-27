-- Dedicated management hosts admit a delegate through Access before first-key enrollment.
-- Only shared issuers with the passkey-or-TOTP policy use pre-enrollment on promotion.
ALTER TABLE nathan_security_overrides ADD COLUMN protect_last_passkey INTEGER NOT NULL DEFAULT 0 CHECK(protect_last_passkey IN (0,1));
DROP TRIGGER nathan_keep_required_admin_passkey;
CREATE TRIGGER nathan_keep_required_admin_passkey BEFORE DELETE ON passkey
WHEN EXISTS(SELECT 1 FROM nathan_security_overrides WHERE id='primary' AND require_recent_admin_passkey=1 AND protect_last_passkey=1)
  AND EXISTS(SELECT 1 FROM user WHERE id=OLD.userId)
  AND EXISTS(SELECT 1 FROM nathan_enabled_admin_subjects WHERE user_id=OLD.userId)
  AND NOT EXISTS(SELECT 1 FROM passkey WHERE userId=OLD.userId AND id<>OLD.id)
BEGIN
  SELECT RAISE(ABORT, 'Enroll another passkey before removing the last administrator passkey');
END;
