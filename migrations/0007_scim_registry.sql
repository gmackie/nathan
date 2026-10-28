-- Credentials and policy live in D1; transactional SCIM directory resources
-- live in a SQLite-backed Durable Object per connection. Directory-only does
-- not link identities or grant permissions automatically.
CREATE TABLE IF NOT EXISTS nathan_scim_connections (
  id TEXT PRIMARY KEY NOT NULL,
  domain TEXT NOT NULL,
  organization_id TEXT,
  mode TEXT NOT NULL DEFAULT 'directory-only' CHECK(mode='directory-only'),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS nathan_scim_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  connection_id TEXT NOT NULL REFERENCES nathan_scim_connections(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER,
  revoked_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_scim_credentials_connection ON nathan_scim_credentials(connection_id,revoked_at,expires_at);
