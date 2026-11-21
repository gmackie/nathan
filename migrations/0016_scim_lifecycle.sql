-- NATH-11: production inbound SCIM lifecycle. The per-connection Durable Object stays the
-- transactional staging area; these tables hold what reconciliation applied to D1: identity links,
-- explicit group mappings, per-connection policy and status, and the back-channel logout queue.
-- Linking and just-in-time creation are off by default. SCIM records never grant access by
-- themselves: a mapped group only carries the roles an administrator grants it (NATH-1, NATH-13).
ALTER TABLE nathan_scim_connections ADD COLUMN linking_enabled INTEGER NOT NULL DEFAULT 0 CHECK(linking_enabled IN (0,1));
ALTER TABLE nathan_scim_connections ADD COLUMN jit_enabled INTEGER NOT NULL DEFAULT 0 CHECK(jit_enabled IN (0,1));
ALTER TABLE nathan_scim_connections ADD COLUMN last_sync_at INTEGER;
ALTER TABLE nathan_scim_connections ADD COLUMN last_error_at INTEGER;
-- One applied-state row per staged SCIM User. A link is keyed by (connection, externalId) among live
-- (non-deleted) rows, so a rehire with the same externalId can take over a deleted identity's link in
-- the same connection; a Nathan user is linked to at most one SCIM identity, and a link never moves to
-- another connection. linked_email and linked_at survive the Nathan user's deletion (user_id becomes
-- NULL): such an orphaned link is never re-made automatically, here or in another connection.
CREATE TABLE IF NOT EXISTS nathan_scim_users (
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  external_id TEXT NOT NULL,
  user_name TEXT NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
  user_id TEXT REFERENCES "user"("id") ON DELETE SET NULL,
  link_state TEXT NOT NULL DEFAULT 'unlinked' CHECK(link_state IN ('unlinked','linked','deprovisioned')),
  link_method TEXT CHECK(link_method IS NULL OR link_method IN ('email','jit','approved')),
  link_note TEXT,
  linked_email TEXT,
  -- Set when an administrator unlinked this identity: it is not linked again automatically.
  link_hold TEXT,
  scim_banned INTEGER NOT NULL DEFAULT 0 CHECK(scim_banned IN (0,1)),
  applied_revision INTEGER NOT NULL DEFAULT 0,
  -- Compare-and-set guard: each application bumps apply_seq from the value it read; a writer that lost
  -- a race sets -1, which fails the CHECK and rolls its whole D1 batch back.
  apply_seq INTEGER NOT NULL DEFAULT 0 CHECK(apply_seq >= 0),
  linked_at INTEGER,
  -- Administrator override (keep active / unban) of a directory deprovisioning with this cause; only a
  -- new deprovision change from the directory (reactivate then deactivate, or a DELETE) applies again.
  override_cause TEXT CHECK(override_cause IS NULL OR override_cause IN ('deactivated','deleted')),
  override_by TEXT,
  override_at INTEGER,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(connection_id,scim_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS nathan_scim_users_external ON nathan_scim_users(connection_id,external_id) WHERE deleted=0;
CREATE UNIQUE INDEX IF NOT EXISTS nathan_scim_users_user ON nathan_scim_users(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS nathan_scim_users_orphan ON nathan_scim_users(linked_email) WHERE user_id IS NULL AND linked_email IS NOT NULL;
-- Directory changes that touch a Nathan administrator (global admin role, an admin grant, the bootstrap
-- owner or NATHAN_ADMIN_EMAILS) and re-links of deleted accounts are never applied automatically: they
-- wait here for an administrator, who approves (step-up, exact confirmation, audited) or dismisses them.
CREATE TABLE IF NOT EXISTS nathan_scim_reviews (
  id TEXT PRIMARY KEY NOT NULL,
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  action TEXT NOT NULL CHECK(action IN ('link','deprovision')),
  cause TEXT,
  reason TEXT NOT NULL,
  revision INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','applied','dismissed','superseded')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  decided_by TEXT,
  decided_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS nathan_scim_reviews_open ON nathan_scim_reviews(connection_id,scim_id,action) WHERE state IN ('pending','approved');
CREATE INDEX IF NOT EXISTS nathan_scim_reviews_connection ON nathan_scim_reviews(connection_id,state,created_at);
CREATE TABLE IF NOT EXISTS nathan_scim_groups (
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  external_id TEXT,
  display_name TEXT NOT NULL,
  members INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
  applied_revision INTEGER NOT NULL DEFAULT 0,
  apply_seq INTEGER NOT NULL DEFAULT 0 CHECK(apply_seq >= 0),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(connection_id,scim_id)
);
-- Administrator-configured mapping of one SCIM group (by its SCIM id or externalId) to one Nathan
-- group, which becomes source='scim' and is then maintained only by reconciliation.
CREATE TABLE IF NOT EXISTS nathan_scim_group_mappings (
  id TEXT PRIMARY KEY NOT NULL,
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  ref_type TEXT NOT NULL CHECK(ref_type IN ('id','externalId')),
  ref_value TEXT NOT NULL,
  group_id TEXT NOT NULL UNIQUE REFERENCES nathan_groups(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(connection_id,ref_type,ref_value)
);
CREATE TABLE IF NOT EXISTS nathan_scim_errors (
  id TEXT PRIMARY KEY NOT NULL,
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_scim_errors_connection ON nathan_scim_errors(connection_id,created_at);
-- OIDC Back-Channel Logout deliveries, enqueued in the same D1 batch as the revocation they announce
-- and retried with backoff. The token is signed at send time; the client's URI is read at send time.
CREATE TABLE IF NOT EXISTS nathan_backchannel_deliveries (
  id TEXT PRIMARY KEY NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  connection_id TEXT,
  reason TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','delivered','failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_status TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_backchannel_due ON nathan_backchannel_deliveries(state,next_attempt_at);
-- Whose ban is it. Nathan's SCIM ban is permanent (banExpires NULL) and carries the reason
-- 'SCIM deprovisioned (connection <id>)' (src/auth/scim/lifecycle.ts scimBanReason). Only lifting
-- that ban outside SCIM (Better Auth's admin unban, or by hand) is an administrator override: it is
-- recorded here, on every path, at the moment it happens. When the ban is replaced instead (an
-- administrator's ban, possibly with an expiry), it is no longer Nathan's: scim_banned is cleared, so
-- that ban lapsing later is not an override and the next resync bans the deprovisioned user again.
CREATE TRIGGER IF NOT EXISTS nathan_scim_ban_changed AFTER UPDATE OF "banned","banReason","banExpires" ON "user"
  WHEN OLD."banned" IN (1,'1') AND OLD."banExpires" IS NULL AND OLD."banReason" LIKE 'SCIM deprovisioned (connection %)'
    AND NOT (NEW."banned" IN (1,'1') AND NEW."banExpires" IS NULL AND NEW."banReason" IS OLD."banReason")
BEGIN
  INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
    SELECT lower(hex(randomblob(16))), 'scim:' || s.connection_id, 'scim_override_detected', s.connection_id || ':' || NEW."id", 'recorded'
    FROM nathan_scim_users s
    WHERE s.user_id=NEW."id" AND s.scim_banned=1 AND s.link_state='deprovisioned' AND s.override_cause IS NULL
      AND OLD."banReason"='SCIM deprovisioned (connection ' || s.connection_id || ')' AND ifnull(NEW."banned" IN (1,'1'),0)=0;
  UPDATE nathan_scim_users SET scim_banned=0,
    override_cause=CASE WHEN ifnull(NEW."banned" IN (1,'1'),0) THEN override_cause WHEN deleted=1 THEN 'deleted' ELSE 'deactivated' END,
    override_by=CASE WHEN ifnull(NEW."banned" IN (1,'1'),0) THEN override_by ELSE 'out-of-band unban (Better Auth admin API or D1)' END,
    override_at=CASE WHEN ifnull(NEW."banned" IN (1,'1'),0) THEN override_at ELSE unixepoch() END,
    updated_at=unixepoch()
  WHERE user_id=NEW."id" AND scim_banned=1 AND link_state='deprovisioned' AND override_cause IS NULL
    AND OLD."banReason"='SCIM deprovisioned (connection ' || connection_id || ')';
END;
