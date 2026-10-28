-- Verified WebAuthn/passkey authentication evidence keyed to a Better Auth session.
-- Enrollment itself is never sufficient. Admin writes require recent evidence.
CREATE TABLE IF NOT EXISTS nathan_admin_assurance (
  session_id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  method TEXT NOT NULL CHECK(method='passkey'),
  verified_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_admin_assurance_user ON nathan_admin_assurance(user_id,verified_at);
