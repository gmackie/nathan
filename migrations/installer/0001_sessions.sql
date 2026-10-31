-- Dedicated D1 for the hosted installer. The installer does not share IdP credentials or identity tables.
CREATE TABLE IF NOT EXISTS nathan_installer_state (
  state_hash TEXT NOT NULL PRIMARY KEY,
  verifier_cipher TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS nathan_installer_sessions (
  session_hash TEXT NOT NULL PRIMARY KEY,
  token_cipher TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_installer_state_exp ON nathan_installer_state(expires_at);
CREATE INDEX IF NOT EXISTS nathan_installer_session_exp ON nathan_installer_sessions(expires_at);
