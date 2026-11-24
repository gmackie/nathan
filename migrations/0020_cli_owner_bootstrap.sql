-- The account operator reserves an email before the first sign-in. Repeating an
-- existing reservation leaves both the owner and the original audit row intact.
CREATE TRIGGER nathan_cli_owner_initialized AFTER INSERT ON nathan_bootstrap_status
WHEN NEW.state = 'pending' AND substr(NEW.cloudflare_user_id, 1, 4) = 'cli:'
BEGIN
  INSERT INTO nathan_security_audit(id, actor, action, target, outcome)
  VALUES (lower(hex(randomblob(16))), NEW.cloudflare_user_id, 'admin_bootstrap_init', 'primary', 'succeeded');
END;

-- D1 REST accepts a parameterized SQL statement. This command view makes the
-- eligibility check, user binding, role change and audit a single SQLite write.
CREATE VIEW nathan_cli_owner_claim(actor, email, user_id) AS
  SELECT cloudflare_user_id, admin_email, admin_user_id FROM nathan_bootstrap_status WHERE 0;

CREATE TRIGGER nathan_claim_cli_owner INSTEAD OF INSERT ON nathan_cli_owner_claim
BEGIN
  SELECT RAISE(ABORT, 'Verified account does not match the reserved bootstrap owner')
  WHERE NOT EXISTS (
    SELECT 1 FROM "user" u JOIN nathan_bootstrap_status b ON b.id = 'primary'
    WHERE u.id = NEW.user_id AND lower(u.email) = NEW.email AND u.emailVerified = 1
      AND coalesce(u.banned, 0) = 0 AND b.admin_email = NEW.email
      AND b.cloudflare_user_id = NEW.actor AND substr(NEW.actor, 1, 4) = 'cli:'
      AND (b.admin_user_id IS NULL OR b.admin_user_id = u.id)
      AND (SELECT count(*) FROM "user" other WHERE lower(other.email) = lower(u.email)) = 1
  );
  INSERT INTO nathan_security_audit(id, actor, action, target, outcome)
    SELECT lower(hex(randomblob(16))), NEW.actor, 'admin_bootstrap', NEW.user_id, 'succeeded'
    FROM "user" u JOIN nathan_bootstrap_status b ON b.id = 'primary'
    WHERE u.id = NEW.user_id AND (u.role IS NOT 'admin' OR b.admin_user_id IS NULL OR b.state = 'pending');
  UPDATE nathan_bootstrap_status SET admin_user_id = NEW.user_id,
    state = CASE WHEN state = 'pending' THEN 'identity_verified' ELSE state END, updated_at = unixepoch()
    WHERE id = 'primary' AND (admin_user_id IS NULL OR state = 'pending');
  UPDATE "user" SET role = 'admin' WHERE id = NEW.user_id AND role IS NOT 'admin';
END;
