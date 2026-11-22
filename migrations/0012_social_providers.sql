-- NATH-9: guided social login for Google, GitHub, Apple, Discord, Twitch and X.
-- SQLite cannot alter a CHECK constraint, so the provider table is rebuilt and swapped.
-- nathan_oauth_providers now holds only credentials saved in Identity Studio or by the
-- installer. Existing google/github rows keep their v1 client-secret ciphertext in
-- secret_cipher until the next rotation. New writes store every secret field as v2 AES-GCM
-- ciphertext (AAD bound to provider and field) in secret_fields, and non-secret fields
-- (Apple Team ID, Key ID) in config.
CREATE TABLE nathan_oauth_providers_v2 (
  id TEXT PRIMARY KEY NOT NULL CHECK(id IN ('google','github','apple','discord','twitch','twitter')),
  client_id TEXT NOT NULL,
  secret_cipher TEXT,
  config TEXT NOT NULL DEFAULT '{}',
  secret_fields TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_by TEXT NOT NULL,
  CHECK(secret_cipher IS NOT NULL OR secret_fields <> '{}')
);
-- Enabled flag and test record for every provider, wherever its credentials live (D1 row,
-- NATHAN_PROVIDER_<ID> Worker secret or legacy Worker secrets). No credentials are stored
-- here. A test record counts only while tested_version equals the keyed digest of the
-- provider's current credentials; tested_by is the administrator who started the test and
-- tested_user the account that completed the provider sign-in.
CREATE TABLE IF NOT EXISTS nathan_provider_state (
  id TEXT PRIMARY KEY NOT NULL CHECK(id IN ('google','github','apple','discord','twitch','twitter')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_by TEXT NOT NULL,
  tested_at INTEGER,
  tested_by TEXT,
  tested_user TEXT,
  tested_version TEXT,
  CHECK((tested_at IS NULL) = (tested_version IS NULL))
);
INSERT INTO nathan_oauth_providers_v2(id,client_id,secret_cipher,updated_at,updated_by)
  SELECT id,client_id,secret_cipher,updated_at,updated_by FROM nathan_oauth_providers;
INSERT INTO nathan_provider_state(id,enabled,updated_at,updated_by)
  SELECT id,enabled,updated_at,updated_by FROM nathan_oauth_providers;
DROP TABLE nathan_oauth_providers;
ALTER TABLE nathan_oauth_providers_v2 RENAME TO nathan_oauth_providers;
-- Single-use test sign-in tickets. Only a SHA-256 digest of the ticket is stored, with the
-- credential version the test was started for.
CREATE TABLE IF NOT EXISTS nathan_provider_test_tickets (
  ticket_hash TEXT PRIMARY KEY NOT NULL,
  provider TEXT NOT NULL,
  admin_user_id TEXT NOT NULL,
  credential_version TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
-- Evidence that a session was created by a social provider callback, and with which
-- credential version (short-lived).
CREATE TABLE IF NOT EXISTS nathan_provider_signins (
  session_id TEXT PRIMARY KEY NOT NULL,
  provider TEXT NOT NULL,
  user_id TEXT NOT NULL,
  credential_version TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_provider_signins_created ON nathan_provider_signins(created_at);
