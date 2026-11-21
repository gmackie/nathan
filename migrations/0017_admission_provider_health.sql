-- NATH-16: account admission. Whether a new Nathan account may be created at all (separate from
-- application access and from administrator privilege). One installation-wide mode:
--   invitation-only (the default, also when this row is missing or unreadable) or self-service.
-- It applies to every way an account is created: password sign-up, social sign-in, SAML and
-- SCIM just-in-time provisioning (src/auth/admission-policy.mjs).
CREATE TABLE IF NOT EXISTS nathan_admission_settings (
  id TEXT PRIMARY KEY NOT NULL DEFAULT 'primary' CHECK(id='primary'),
  mode TEXT NOT NULL DEFAULT 'invitation-only' CHECK(mode IN ('invitation-only','self-service')),
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
-- Invitations: created by an administrator, bound to one email address, single use, expiring and
-- revocable. Rows are never deleted (they are the record of who admitted whom). `uses` is the
-- single-use guard: claiming sets it to 1; a claim of an invitation that is used, revoked or expired
-- sets it to 2, which fails the CHECK and rolls back the whole D1 batch that would create the account.
CREATE TABLE IF NOT EXISTS nathan_invitations (
  id TEXT PRIMARY KEY NOT NULL,
  email TEXT NOT NULL CHECK(email=lower(trim(email)) AND length(email) BETWEEN 3 AND 254),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL,
  uses INTEGER NOT NULL DEFAULT 0 CHECK(uses IN (0,1)),
  used_at INTEGER,
  used_method TEXT,
  used_by_user TEXT,
  revoked_at INTEGER,
  revoked_by TEXT
);
-- At most one open invitation per email (creating a new one supersedes the old one).
CREATE UNIQUE INDEX IF NOT EXISTS nathan_invitations_open ON nathan_invitations(email) WHERE uses=0 AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS nathan_invitations_created ON nathan_invitations(created_at);


-- NATH-17: a configured, enabled social provider whose credentials cannot be used (an undecryptable
-- D1 row, a malformed Worker secret, an Apple key that cannot sign) is skipped instead of failing
-- every request. This row marks it unavailable for Studio and /healthz; it holds no secret, only a
-- reason code. audited_at limits the audit trail to one row per provider per hour.
CREATE TABLE IF NOT EXISTS nathan_provider_health (
  id TEXT PRIMARY KEY NOT NULL,
  reason TEXT NOT NULL CHECK(reason IN ('decrypt_failed','invalid_worker_secret','unusable_credentials')),
  first_failed_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_failed_at INTEGER NOT NULL DEFAULT (unixepoch()),
  audited_at INTEGER
);
