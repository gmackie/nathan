-- One parameterized INSERT from the privileged Cloudflare D1 API claims the owner.
-- The view stores no data. SQLite rolls back every trigger write if the statement fails.
CREATE VIEW IF NOT EXISTS nathan_operator_owner_claim (user_id, email, seed, audit_id)
AS SELECT NULL, NULL, NULL, NULL WHERE 0;

CREATE TRIGGER IF NOT EXISTS nathan_claim_owner
INSTEAD OF INSERT ON nathan_operator_owner_claim
BEGIN
  SELECT RAISE(ABORT, 'Verified account and seed must match the installation owner')
  WHERE NOT EXISTS (
    SELECT 1 FROM "user" u JOIN nathan_bootstrap_status b ON b.id = 'primary'
    WHERE u.id = NEW.user_id AND lower(u.email) = NEW.email AND u.emailVerified = 1
      AND coalesce(u.banned, 0) = 0 AND b.admin_email = lower(u.email)
      AND b.cloudflare_user_id = NEW.seed AND (b.admin_user_id IS NULL OR b.admin_user_id = u.id)
      AND b.state IN ('pending', 'identity_verified', 'authenticators_enrolled', 'complete')
      AND (SELECT count(*) FROM "user" other WHERE lower(other.email) = lower(u.email)) = 1
  );

  INSERT INTO nathan_security_audit(id, actor, action, target, outcome)
  SELECT NEW.audit_id, CASE WHEN NEW.seed LIKE 'forgegraph:%' THEN 'operator:' || NEW.seed ELSE NEW.seed END,
         'admin_bootstrap', NEW.user_id, 'succeeded'
  WHERE EXISTS (SELECT 1 FROM "user" WHERE id = NEW.user_id AND role IS NOT 'admin')
     OR EXISTS (SELECT 1 FROM nathan_bootstrap_status WHERE id = 'primary' AND (admin_user_id IS NULL OR state = 'pending'));

  UPDATE nathan_bootstrap_status SET admin_user_id = NEW.user_id,
      state = CASE WHEN state = 'pending' THEN 'identity_verified' ELSE state END,
      updated_at = unixepoch()
  WHERE id = 'primary' AND (admin_user_id IS NULL OR state = 'pending');

  UPDATE "user" SET role = 'admin' WHERE id = NEW.user_id AND role IS NOT 'admin';

  SELECT RAISE(ABORT, 'Owner claim did not complete')
  WHERE NOT EXISTS (SELECT 1 FROM nathan_bootstrap_status b JOIN "user" u ON u.id = b.admin_user_id
                    WHERE b.id = 'primary' AND b.state <> 'pending' AND u.id = NEW.user_id AND u.role = 'admin');
END;
