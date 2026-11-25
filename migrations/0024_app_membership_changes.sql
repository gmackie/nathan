-- An independently owned grant can survive suspension. Consumers still need to
-- invalidate the app decision when the source withdraws or restores membership.
CREATE TRIGGER nathan_app_membership_changes AFTER UPDATE OF desired_roles ON nathan_app_provisions
WHEN NEW.user_id IS NOT NULL AND NEW.erased_revision IS NULL
  AND (json_array_length(NEW.desired_roles)=0) <> (json_array_length(OLD.desired_roles)=0)
BEGIN
  INSERT INTO nathan_rbac_changes(kind,app_id,principal_type,principal_id,detail,actor)
    VALUES (CASE WHEN json_array_length(NEW.desired_roles)=0 THEN 'app.membership_suspended' ELSE 'app.membership_restored' END,
      NEW.app_id,'user',NEW.user_id,json_object('revision',NEW.grant_revision),'app-provision:'||NEW.app_id);
END;
