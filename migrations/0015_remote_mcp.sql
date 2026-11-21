-- NATH-14: remote MCP servers protected by Nathan, with granular per-scope consent.
-- An MCP server is a Nathan application registered as a token audience (NATH-15). Its scopes are
-- the application's NATH-13 permission keys; this table and nathan_mcp_scopes add catalog metadata.
-- Removing the audience or the application removes the resource and every grant for it.
CREATE TABLE IF NOT EXISTS nathan_mcp_resources (
  identifier TEXT PRIMARY KEY NOT NULL REFERENCES nathan_token_audiences(identifier) ON DELETE CASCADE,
  app_id TEXT NOT NULL REFERENCES nathan_applications(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  -- Optional Full access marker (for example notes:full): covers every non-sensitive scope, including later ones.
  full_scope TEXT,
  -- JSON object alias -> [scope]; aliases never contain sensitive scopes.
  aliases TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
-- Optional per-scope metadata. A permission without a row is a plain, non-sensitive scope.
-- Sensitive scopes are never implied (alias, Full access, requires); admin-only implies sensitive.
CREATE TABLE IF NOT EXISTS nathan_mcp_scopes (
  resource TEXT NOT NULL REFERENCES nathan_mcp_resources(identifier) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  group_key TEXT NOT NULL DEFAULT 'general',
  requires TEXT NOT NULL DEFAULT '[]',
  sensitive INTEGER NOT NULL DEFAULT 0 CHECK(sensitive IN (0,1)),
  admin_only INTEGER NOT NULL DEFAULT 0 CHECK(admin_only IN (0,1)),
  CHECK(admin_only=0 OR sensitive=1),
  PRIMARY KEY(resource, scope)
);
-- Public MCP clients from RFC 7591 dynamic registration. They exist only for the MCP authorization
-- server: they are not Better Auth OAuth clients and cannot use /api/auth endpoints or OIDC scopes.
CREATE TABLE IF NOT EXISTS nathan_mcp_clients (
  client_id TEXT PRIMARY KEY NOT NULL,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  scope TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nathan_mcp_clients_expiry ON nathan_mcp_clients(expires_at);
-- A user's consent for one client and resource. `scope` is the canonical stored selection (it may
-- hold the Full access marker); the user may edit it. Deleting the row revokes every token of it.
CREATE TABLE IF NOT EXISTS nathan_mcp_grants (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES nathan_mcp_clients(client_id) ON DELETE CASCADE,
  resource TEXT NOT NULL REFERENCES nathan_mcp_resources(identifier) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nathan_mcp_grants_user ON nathan_mcp_grants(user_id);
CREATE INDEX IF NOT EXISTS nathan_mcp_grants_expiry ON nathan_mcp_grants(expires_at);
-- One-time artifacts, keyed by SHA-256 of the secret value (never stored raw): consent tickets,
-- authorization codes and refresh tokens, plus markers of used codes and refresh tokens for reuse
-- detection. Consumed with DELETE ... RETURNING.
CREATE TABLE IF NOT EXISTS nathan_mcp_artifacts (
  hash TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('consent','code','used_code','refresh','used_refresh')),
  grant_id TEXT REFERENCES nathan_mcp_grants(id) ON DELETE CASCADE,
  data TEXT NOT NULL DEFAULT '{}',
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nathan_mcp_artifacts_expiry ON nathan_mcp_artifacts(expires_at);
CREATE INDEX IF NOT EXISTS nathan_mcp_artifacts_grant ON nathan_mcp_artifacts(grant_id);
