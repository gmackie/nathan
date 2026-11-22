-- NATH-12: Nathan as a SAML 2.0 identity provider for downstream service providers (AWS IAM
-- Identity Center, Salesforce, Grafana, any SAML SP). Nathan stays authentication + minimal RBAC:
-- every SP is bound to one Nathan application, and NATH-13's evaluator decides who may sign in.

-- IdP signing keys. The private key is RSA, generated in the Worker, encrypted under
-- NATHAN_CONFIG_KEY with AAD "nathan:saml-idp-key:v1:<id>" and never returned by any API.
-- Rotation: 'next' is published in metadata before it signs (overlap), activation turns the old
-- 'active' key into 'previous' (still published), retiring removes it from metadata and deletes
-- its private key. At most one key per published status.
CREATE TABLE IF NOT EXISTS nathan_saml_idp_keys (
  id TEXT PRIMARY KEY NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('next','active','previous','retired')),
  bits INTEGER NOT NULL CHECK(bits >= 2048),
  certificate TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,
  private_key TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  activated_at INTEGER,
  retired_at INTEGER,
  CHECK(status='retired' OR private_key IS NOT NULL),
  CHECK(status<>'retired' OR private_key IS NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS nathan_saml_idp_keys_status ON nathan_saml_idp_keys(status) WHERE status IN ('next','active','previous');

-- Registered service providers. Disabled by default; exact HTTPS ACS URLs (JSON array, the first is
-- the default) with their AssertionConsumerServiceIndex values (JSON array, same order: the SP
-- metadata's index attributes, or 0, 1, ... when entered by hand); persistent pairwise NameIDs
-- unless an administrator chooses email.
CREATE TABLE IF NOT EXISTS nathan_saml_service_providers (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  entity_id TEXT NOT NULL UNIQUE,
  app_id TEXT NOT NULL REFERENCES nathan_applications(id),
  acs_urls TEXT NOT NULL,
  acs_indexes TEXT NOT NULL,
  name_id_format TEXT NOT NULL DEFAULT 'persistent' CHECK(name_id_format IN ('persistent','email')),
  attributes TEXT NOT NULL DEFAULT '[]',
  want_requests_signed INTEGER NOT NULL DEFAULT 0 CHECK(want_requests_signed IN (0,1)),
  certificates TEXT NOT NULL DEFAULT '[]',
  sign_response INTEGER NOT NULL DEFAULT 0 CHECK(sign_response IN (0,1)),
  require_passkey INTEGER NOT NULL DEFAULT 0 CHECK(require_passkey IN (0,1)),
  allow_idp_initiated INTEGER NOT NULL DEFAULT 0 CHECK(allow_idp_initiated IN (0,1)),
  default_relay_state TEXT,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  CHECK(want_requests_signed=0 OR certificates<>'[]')
);
CREATE INDEX IF NOT EXISTS nathan_saml_service_providers_app ON nathan_saml_service_providers(app_id);

-- Single-use AuthnRequest IDs per SP (replay cache). Kept past the request's freshness window.
CREATE TABLE IF NOT EXISTS nathan_saml_idp_request_ids (
  sp_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY(sp_id, request_id)
);
CREATE INDEX IF NOT EXISTS nathan_saml_idp_request_ids_expiry ON nathan_saml_idp_request_ids(expires_at);

-- A validated AuthnRequest waiting for the browser's Nathan session (sign-in, then resume). The
-- browser holds a signed random handle in a __Host- cookie; only its SHA-256 is stored. Single use.
-- `signed`: the request carried a valid SP signature naming Nathan as Destination. An unsigned
-- request answered with a session older than the request (requested_at_ms, Worker clock) needs
-- the user's confirmation: confirm_hash is the SHA-256 of the token on that page, bound to
-- confirm_session and valid until confirm_expires.
CREATE TABLE IF NOT EXISTS nathan_saml_idp_pending (
  id_hash TEXT PRIMARY KEY NOT NULL,
  sp_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  acs_url TEXT NOT NULL,
  relay_state TEXT,
  force_authn INTEGER NOT NULL DEFAULT 0 CHECK(force_authn IN (0,1)),
  is_passive INTEGER NOT NULL DEFAULT 0 CHECK(is_passive IN (0,1)),
  signed INTEGER NOT NULL DEFAULT 0 CHECK(signed IN (0,1)),
  requested_at_ms INTEGER NOT NULL,
  confirm_hash TEXT,
  confirm_session TEXT,
  confirm_expires INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1))
);
CREATE INDEX IF NOT EXISTS nathan_saml_idp_pending_expiry ON nathan_saml_idp_pending(expires_at);

-- Persistent pairwise NameIDs: random, opaque, one per (SP, user), stable across secret rotation.
CREATE TABLE IF NOT EXISTS nathan_saml_idp_subjects (
  sp_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  name_id TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(sp_id, user_id),
  UNIQUE(sp_id, name_id)
);
