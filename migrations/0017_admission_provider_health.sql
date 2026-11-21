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
-- A password sign-up proves nothing about its address, so it claims no invitation when the account
-- is created. In invitation-only mode it is admitted provisionally: this row marks the account, and
-- the invitation (still open) is claimed only when the address is verified. A provisional account
-- that has never signed in is superseded (deleted, audited) when the invitee proves the address
-- through another method, so nobody can lock the real person out by signing up first.
CREATE TABLE IF NOT EXISTS nathan_admission_pending (
  email TEXT PRIMARY KEY NOT NULL CHECK(email=lower(trim(email)) AND length(email) BETWEEN 3 AND 254),
  user_id TEXT REFERENCES "user"("id") ON DELETE CASCADE,
  method TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
-- Upgrading to 0017 switches admission to invitation-only. Record that once, and whether the
-- installation already had accounts (then Identity Studio shows a one-time notice, and SCIM
-- just-in-time connections stop creating accounts until invitations or self-service are set).
INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
  SELECT lower(hex(randomblob(16))),'system:migration-0017','admission_default_invitation_only',
    CASE WHEN EXISTS (SELECT 1 FROM "user") THEN 'existing-users' ELSE 'no-existing-users' END,'applied'
  WHERE NOT EXISTS (SELECT 1 FROM nathan_security_audit WHERE action='admission_default_invitation_only')
    AND NOT EXISTS (SELECT 1 FROM nathan_admission_settings);


-- NATH-17: a configured, enabled social provider whose credentials cannot be used (an undecryptable
-- D1 row, a malformed Worker secret, an Apple key that cannot sign) is skipped instead of failing
-- every request. This row marks it unavailable for Studio (/healthz only counts it); it holds no secret, only a
-- reason code. audited_at limits the audit trail to one row per provider per hour.
CREATE TABLE IF NOT EXISTS nathan_provider_health (
  id TEXT PRIMARY KEY NOT NULL,
  reason TEXT NOT NULL CHECK(reason IN ('decrypt_failed','invalid_worker_secret','unusable_credentials')),
  first_failed_at INTEGER NOT NULL DEFAULT (unixepoch()),
  last_failed_at INTEGER NOT NULL DEFAULT (unixepoch()),
  audited_at INTEGER
);
