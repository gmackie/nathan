-- Realm coverage is a verified Cloudflare DNS-zone ownership claim, NOT a
-- wildcard OAuth redirect registration or implicit authorization.
CREATE TABLE IF NOT EXISTS nathan_domain_realms (
  apex TEXT PRIMARY KEY NOT NULL,
  issuer_hostname TEXT NOT NULL UNIQUE,
  account_id TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  registered_by TEXT NOT NULL,
  include_apex INTEGER NOT NULL DEFAULT 1 CHECK(include_apex=1),
  include_subdomains INTEGER NOT NULL DEFAULT 1 CHECK(include_subdomains=1),
  registration_mode TEXT NOT NULL DEFAULT 'approved-only' CHECK(registration_mode='approved-only'),
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS nathan_realm_clients (
  hostname TEXT PRIMARY KEY NOT NULL,
  realm_apex TEXT NOT NULL REFERENCES nathan_domain_realms(apex) ON DELETE RESTRICT,
  kind TEXT NOT NULL CHECK(kind IN ('web','worker','gateway','external')),
  callback_uri TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('creating','registered','disabled')),
  oauth_client_id TEXT UNIQUE,
  requested_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_realm_clients_apex ON nathan_realm_clients(realm_apex,status);
