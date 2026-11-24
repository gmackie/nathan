-- NATH-51: "Sign in with Nathan", a parent Nathan instance as an upstream sign-in provider.
-- It is stored like the six social providers: credentials in nathan_oauth_providers (the client
-- secret AES-GCM-encrypted under NATHAN_CONFIG_KEY with AAD bound to provider and field; the
-- issuer, button name and the email-trust flag in config), enabled flag and test record in
-- nathan_provider_state. SQLite cannot alter a CHECK constraint, so both tables are rebuilt with
-- 'nathan' admitted and swapped, keeping every existing row.
CREATE TABLE nathan_oauth_providers_v3 (
  id TEXT PRIMARY KEY NOT NULL CHECK(id IN ('google','github','apple','discord','twitch','twitter','nathan')),
  client_id TEXT NOT NULL,
  secret_cipher TEXT,
  config TEXT NOT NULL DEFAULT '{}',
  secret_fields TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_by TEXT NOT NULL,
  CHECK(secret_cipher IS NOT NULL OR secret_fields <> '{}')
);
INSERT INTO nathan_oauth_providers_v3(id,client_id,secret_cipher,config,secret_fields,updated_at,updated_by)
  SELECT id,client_id,secret_cipher,config,secret_fields,updated_at,updated_by FROM nathan_oauth_providers;
DROP TABLE nathan_oauth_providers;
ALTER TABLE nathan_oauth_providers_v3 RENAME TO nathan_oauth_providers;
CREATE TABLE nathan_provider_state_v2 (
  id TEXT PRIMARY KEY NOT NULL CHECK(id IN ('google','github','apple','discord','twitch','twitter','nathan')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_by TEXT NOT NULL,
  tested_at INTEGER,
  tested_by TEXT,
  tested_user TEXT,
  tested_version TEXT,
  CHECK((tested_at IS NULL) = (tested_version IS NULL))
);
INSERT INTO nathan_provider_state_v2(id,enabled,updated_at,updated_by,tested_at,tested_by,tested_user,tested_version)
  SELECT id,enabled,updated_at,updated_by,tested_at,tested_by,tested_user,tested_version FROM nathan_provider_state;
DROP TABLE nathan_provider_state;
ALTER TABLE nathan_provider_state_v2 RENAME TO nathan_provider_state;
