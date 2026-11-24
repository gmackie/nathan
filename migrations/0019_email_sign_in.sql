-- One live hosted email flow per address. The private id binds the browser cookie to the public flow id.
-- Better Auth holds the one-time credential separately. A request remembers the particular
-- invitation or provisioned user and the issuer-signed OIDC query it was opened for.
CREATE TABLE nathan_email_sign_ins (
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
CREATE INDEX nathan_email_sign_ins_expiry ON nathan_email_sign_ins(expires_at);

-- Mailbox possession is evidence about a live session. Admin assurance remains passkey-only.
CREATE TABLE nathan_email_sessions (
  session_id TEXT PRIMARY KEY NOT NULL REFERENCES "session"("id") ON DELETE CASCADE
);

-- Better Auth assigns the reserved n-email- id only after an email OTP proves a new
-- invitee's mailbox. Claim its pinned invitation in the very same INSERT transaction.
CREATE TRIGGER nathan_claim_email_invitation AFTER INSERT ON "user" WHEN NEW.id GLOB 'n-email-*'
BEGIN
  UPDATE nathan_invitations SET uses=1, used_at=unixepoch(), used_method='email-otp', used_by_user=NEW.id
    WHERE id=(SELECT invitation_id FROM nathan_email_sign_ins WHERE generation=substr(NEW.id,9)
      AND subject_id IS NULL AND email=NEW.email AND expires_at>unixepoch())
    AND email=NEW.email AND NEW.emailVerified=1 AND uses=0 AND revoked_at IS NULL AND expires_at>unixepoch();
  SELECT RAISE(ABORT,'Email sign-in invitation unavailable') WHERE changes()<>1;
  INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
    VALUES (lower(hex(randomblob(16))),'system:admission','account_admission','email-otp','admitted_invitation');
END;
