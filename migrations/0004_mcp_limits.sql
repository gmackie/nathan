-- Rate limit every authenticated MCP principal, not just the Better Auth OAuth endpoints.
CREATE TABLE IF NOT EXISTS nathan_mcp_limits (
  id TEXT PRIMARY KEY NOT NULL,
  request_count INTEGER NOT NULL CHECK(request_count>=0),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nathan_mcp_limits_expiry ON nathan_mcp_limits(expires_at);
