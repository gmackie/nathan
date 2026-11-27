-- Separate from WebAuthn evidence consumed by the token and SAML issuers.
-- A consumed code survives sign-out until it expires. Removing the factor invalidates its proofs.
CREATE TABLE nathan_admin_totp_assurance (
  factor_id TEXT NOT NULL REFERENCES twoFactor(id) ON DELETE CASCADE,
  code_tag BLOB NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  verified_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (factor_id, code_tag)
);
CREATE INDEX nathan_admin_totp_session ON nathan_admin_totp_assurance(session_id, user_id, verified_at);
CREATE INDEX nathan_admin_totp_expiry ON nathan_admin_totp_assurance(verified_at);
