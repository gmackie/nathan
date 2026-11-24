-- Better Auth creates OAuth clients before responding to the caller. Its admin
-- create endpoint does not persist a disabled flag. Tag a managed registration
-- with its reservation so the client is disabled in the same D1 insert.
ALTER TABLE nathan_realm_clients ADD COLUMN registration_id TEXT;
CREATE UNIQUE INDEX nathan_realm_registration_id ON nathan_realm_clients(registration_id)
  WHERE registration_id IS NOT NULL;

CREATE TRIGGER nathan_realm_client_starts_disabled AFTER INSERT ON "oauthClient"
WHEN EXISTS (
  SELECT 1 FROM nathan_realm_clients
  WHERE registration_id = CASE WHEN json_valid(NEW."metadata") THEN json_extract(NEW."metadata", '$.nathan_realm_registration') END
    AND status = 'creating'
) OR EXISTS (
  -- An older Worker may finish an untagged reservation during deployment.
  SELECT 1 FROM nathan_realm_clients
  WHERE registration_id IS NULL AND status = 'creating' AND requested_by = NEW."userId"
    AND NEW."redirectUris" = json_array(callback_uri)
    AND (CASE WHEN json_valid(NEW."metadata") THEN json_extract(NEW."metadata", '$.nathan_registration_kind') END) IS NOT 'independent'
)
BEGIN
  UPDATE "oauthClient" SET "disabled" = 1 WHERE "id" = NEW."id";
END;

-- During a rolling upgrade the old Worker can link a client inserted before
-- this migration. Its inventory update and the provider disable must commit together.
CREATE TRIGGER nathan_realm_client_link_disabled AFTER UPDATE OF oauth_client_id ON nathan_realm_clients
WHEN NEW.status = 'disabled' AND NEW.oauth_client_id IS NOT NULL
BEGIN
  UPDATE "oauthClient" SET "disabled" = 1 WHERE "clientId" = NEW.oauth_client_id AND "disabled" IS NOT 1;
END;

-- Reconcile clients whose realm inventory records a prior disable. An explicit
-- enable sets the realm status to 'registered' and remains in effect.
INSERT INTO nathan_security_audit(id, actor, action, target, outcome)
  SELECT lower(hex(randomblob(16))), 'migration:0019', 'realm_client_activation_reconciled', c."clientId", 'succeeded'
  FROM "oauthClient" c JOIN nathan_realm_clients r ON r.oauth_client_id = c."clientId"
  WHERE r.status = 'disabled' AND c."disabled" IS NOT 1;
UPDATE "oauthClient" SET "disabled" = 1
  WHERE "disabled" IS NOT 1 AND "clientId" IN (
    SELECT oauth_client_id FROM nathan_realm_clients WHERE status = 'disabled'
  );

-- The old Worker could stop after creating the OAuth client, before recording
-- its ID. Hold unlinked candidates for review. Older clients and linked RPs
-- keep their status. Never infer ownership or complete a reservation by URL.
CREATE VIEW nathan_unlinked_realm_candidates AS
  SELECT c."clientId" FROM "oauthClient" c JOIN nathan_realm_clients r
    ON r.requested_by = c."userId" AND c."redirectUris" = json_array(r.callback_uri)
  WHERE r.status = 'creating' AND r.oauth_client_id IS NULL
    AND NOT EXISTS (SELECT 1 FROM nathan_realm_clients linked WHERE linked.oauth_client_id = c."clientId")
    AND coalesce(CASE WHEN typeof(c."createdAt") IN ('integer','real') THEN
          CASE WHEN c."createdAt" > 9999999999 THEN c."createdAt" / 1000 ELSE c."createdAt" END
        ELSE unixepoch(c."createdAt") END, r.created_at) >= r.created_at;
INSERT INTO nathan_security_audit(id, actor, action, target, outcome)
  SELECT lower(hex(randomblob(16))), 'migration:0019', 'realm_client_review_required', "clientId", 'held'
  FROM nathan_unlinked_realm_candidates;
UPDATE "oauthClient" SET "disabled" = 1 WHERE "clientId" IN (SELECT "clientId" FROM nathan_unlinked_realm_candidates);
DROP VIEW nathan_unlinked_realm_candidates;
