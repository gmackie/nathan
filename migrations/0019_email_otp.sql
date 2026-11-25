-- NATH-49: passwordless email sign-in codes (Better Auth emailOTP; the codes themselves live in
-- Better Auth's "verification" table, hashed).

-- Sessions created by an email code. mayAdminister refuses them: an emailed code never opens
-- Identity Studio, whatever the security profile. Removed with the session.
CREATE TABLE IF NOT EXISTS nathan_email_otp_sessions (
  session_id TEXT PRIMARY KEY NOT NULL REFERENCES "session"("id") ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Fixed-window counters: per address (SHA-256 keys, never an address) and the instance-wide budget
-- of refused codes. Pruned by the scheduled handler once their window has ended.
CREATE TABLE IF NOT EXISTS nathan_email_otp_limits (
  key TEXT PRIMARY KEY NOT NULL,
  count INTEGER NOT NULL CHECK(count >= 0),
  window_start INTEGER NOT NULL,
  window_seconds INTEGER NOT NULL CHECK(window_seconds > 0)
);
CREATE INDEX IF NOT EXISTS nathan_email_otp_limits_end ON nathan_email_otp_limits(window_start);
