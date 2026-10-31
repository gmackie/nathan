-- Isolated database for an individual Nathan gateway deployment.
-- All session IDs are high-entropy opaque handles; only SHA-256 digests are persisted.
CREATE TABLE IF NOT EXISTS nathan_gateway_sessions (
  id_hash TEXT PRIMARY KEY NOT NULL,
  subject TEXT NOT NULL,
  email TEXT,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  acr TEXT,
  sid TEXT,
  auth_time INTEGER,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_gateway_sessions_sid ON nathan_gateway_sessions(sid);
CREATE INDEX IF NOT EXISTS nathan_gateway_sessions_subject ON nathan_gateway_sessions(subject, issuer, client_id);
CREATE TABLE IF NOT EXISTS nathan_gateway_logout_jti (
  jti TEXT PRIMARY KEY NOT NULL,
  exp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nathan_gateway_logout_jti_exp ON nathan_gateway_logout_jti(exp);
CREATE INDEX IF NOT EXISTS nathan_gateway_sessions_expires ON nathan_gateway_sessions(expires_at);
