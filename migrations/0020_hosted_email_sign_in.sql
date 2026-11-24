CREATE INDEX IF NOT EXISTS nathan_user_email_nocase ON "user"(email COLLATE NOCASE);

-- One live hosted email flow per address. The private id binds the browser cookie to the public flow id.
-- Better Auth holds the one-time credential separately. A request remembers the particular
-- invitation or provisioned user and the issuer-signed OIDC query it was opened for.
CREATE TABLE IF NOT EXISTS nathan_email_sign_ins (
  id TEXT PRIMARY KEY NOT NULL,
  email TEXT NOT NULL UNIQUE,
  generation TEXT NOT NULL UNIQUE,
  subject_id TEXT,
  invitation_id TEXT,
  oauth_query TEXT,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  second_factor TEXT
);
CREATE INDEX IF NOT EXISTS nathan_email_sign_ins_expiry ON nathan_email_sign_ins(expires_at);

-- Earlier code-only sessions remain ineligible for Studio. Only a new hosted
-- sign-in can supply method evidence for a resource token.
ALTER TABLE nathan_email_otp_sessions ADD COLUMN hosted INTEGER NOT NULL DEFAULT 0 CHECK(hosted IN (0,1));

-- Instances that ran the earlier hosted draft recorded the session ID alone.
-- Resolve the subject from the live session and retire that draft table on upgrade.
CREATE TABLE IF NOT EXISTS nathan_email_sessions (
  session_id TEXT PRIMARY KEY NOT NULL REFERENCES "session"("id") ON DELETE CASCADE
);
INSERT INTO nathan_email_otp_sessions(session_id,user_id,hosted)
  SELECT s.id,s.userId,1 FROM "session" s JOIN nathan_email_sessions e ON e.session_id=s.id
  WHERE true ON CONFLICT(session_id) DO UPDATE SET hosted=1;
DROP TABLE nathan_email_sessions;

-- Better Auth assigns the reserved n-email- id only after an email OTP proves a new
-- invitee's mailbox. Claim its pinned invitation in the very same INSERT transaction.
CREATE TRIGGER IF NOT EXISTS nathan_claim_email_invitation AFTER INSERT ON "user" WHEN NEW.id GLOB 'n-email-*'
BEGIN
  UPDATE nathan_invitations SET uses=1, used_at=unixepoch(), used_method='email-otp', used_by_user=NEW.id
    WHERE id=(SELECT invitation_id FROM nathan_email_sign_ins WHERE generation=substr(NEW.id,9)
      AND subject_id IS NULL AND email=NEW.email AND expires_at>unixepoch())
    AND email=NEW.email AND NEW.emailVerified=1 AND uses=0 AND revoked_at IS NULL AND expires_at>unixepoch();
  SELECT RAISE(ABORT,'Email sign-in invitation unavailable') WHERE changes()<>1;
  INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
    VALUES (lower(hex(randomblob(16))),'system:admission','account_admission','email-otp','admitted_invitation');
END;
