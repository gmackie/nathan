-- NATH-11: production inbound SCIM lifecycle. The per-connection Durable Object stays the
-- transactional staging area; these tables hold what reconciliation applied to D1: identity links,
-- explicit group mappings, per-connection policy and status, and the back-channel logout queue.
-- Linking and just-in-time creation are off by default. SCIM records never grant access by
-- themselves: a mapped group only carries the roles an administrator grants it (NATH-1, NATH-13).
ALTER TABLE nathan_scim_connections ADD COLUMN linking_enabled INTEGER NOT NULL DEFAULT 0 CHECK(linking_enabled IN (0,1));
ALTER TABLE nathan_scim_connections ADD COLUMN jit_enabled INTEGER NOT NULL DEFAULT 0 CHECK(jit_enabled IN (0,1));
ALTER TABLE nathan_scim_connections ADD COLUMN last_sync_at INTEGER;
ALTER TABLE nathan_scim_connections ADD COLUMN last_error_at INTEGER;
-- One applied-state row per staged SCIM User. A link is keyed by (connection, externalId) and a
-- Nathan user is linked to at most one SCIM identity in one connection; a link never moves.
CREATE TABLE IF NOT EXISTS nathan_scim_users (
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  external_id TEXT NOT NULL,
  user_name TEXT NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
  user_id TEXT REFERENCES "user"("id") ON DELETE SET NULL,
  link_state TEXT NOT NULL DEFAULT 'unlinked' CHECK(link_state IN ('unlinked','linked','deprovisioned')),
  link_method TEXT CHECK(link_method IS NULL OR link_method IN ('email','jit')),
  link_note TEXT,
  scim_banned INTEGER NOT NULL DEFAULT 0 CHECK(scim_banned IN (0,1)),
  applied_revision INTEGER NOT NULL DEFAULT 0,
  linked_at INTEGER,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(connection_id,scim_id),
  UNIQUE(connection_id,external_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS nathan_scim_users_user ON nathan_scim_users(user_id) WHERE user_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS nathan_scim_groups (
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  scim_id TEXT NOT NULL,
  external_id TEXT,
  display_name TEXT NOT NULL,
  members INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),
  applied_revision INTEGER NOT NULL DEFAULT 0,
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
