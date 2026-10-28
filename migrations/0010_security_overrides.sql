-- Runtime policy can only tighten the immutable deployment security baseline.
-- Downgrading assurance requires a reviewed operator-controlled deployment.
CREATE TABLE IF NOT EXISTS nathan_security_overrides (
  id TEXT PRIMARY KEY NOT NULL DEFAULT 'primary' CHECK(id='primary'),
  require_both_admin_authenticators INTEGER NOT NULL DEFAULT 0 CHECK(require_both_admin_authenticators IN (0,1)),
  require_recent_admin_passkey INTEGER NOT NULL DEFAULT 0 CHECK(require_recent_admin_passkey IN (0,1)),
  modified_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
