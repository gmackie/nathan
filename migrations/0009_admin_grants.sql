-- Explicit, revocable admin allowlist for additional administrators.
-- Cloudflare-installer bootstrap account remains a separately verified root owner.
CREATE TABLE IF NOT EXISTS nathan_admin_grants (
  user_id TEXT PRIMARY KEY NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  email TEXT NOT NULL,
  granted_by TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_admin_grants_active ON nathan_admin_grants(enabled,email);
