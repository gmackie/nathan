-- Nathan-owned application registry only.
-- Better Auth core/plugin tables MUST be generated using the matching Better Auth CLI and applied before deployment.
CREATE TABLE IF NOT EXISTS nathan_applications (
  id TEXT PRIMARY KEY NOT NULL,
  hostname TEXT NOT NULL,
  roles TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_applications_hostname_idx ON nathan_applications(hostname);
