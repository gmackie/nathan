-- Nathan's runtime-configurable OAuth providers.
-- Client secrets are AES-256-GCM-encrypted by the Worker-held NATHAN_CONFIG_KEY.
-- A disabled record deliberately overrides legacy Worker secret bindings.
CREATE TABLE IF NOT EXISTS nathan_oauth_providers (
  id TEXT PRIMARY KEY NOT NULL CHECK(id IN ('google','github')),
  client_id TEXT NOT NULL,
  secret_cipher TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nathan_bootstrap_status (
  id TEXT PRIMARY KEY NOT NULL DEFAULT 'primary' CHECK(id='primary'),
  cloudflare_user_id TEXT NOT NULL,
  admin_email TEXT NOT NULL,
  admin_user_id TEXT,
  state TEXT NOT NULL CHECK(state IN ('pending','identity_verified','authenticators_enrolled','complete')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  completed_at INTEGER
);
CREATE INDEX IF NOT EXISTS nathan_bootstrap_user ON nathan_bootstrap_status(admin_user_id);
