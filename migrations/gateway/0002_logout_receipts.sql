-- Older rows retain created_at as their issuance fallback.
ALTER TABLE nathan_gateway_sessions ADD COLUMN issued_at INTEGER;

CREATE TABLE nathan_gateway_logout_receipts (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  issuer TEXT NOT NULL,
  client_id TEXT NOT NULL,
  jti TEXT NOT NULL,
  sid TEXT,
  subject TEXT,
  event_time INTEGER,
  exp INTEGER NOT NULL,
  UNIQUE (issuer, client_id, jti),
  CHECK (sid IS NOT NULL OR subject IS NOT NULL)
);
CREATE INDEX nathan_gateway_logout_receipts_sid ON nathan_gateway_logout_receipts(issuer, client_id, sid) WHERE sid IS NOT NULL;
CREATE INDEX nathan_gateway_logout_receipts_subject ON nathan_gateway_logout_receipts(issuer, client_id, subject) WHERE sid IS NULL;
CREATE INDEX nathan_gateway_logout_receipts_exp ON nathan_gateway_logout_receipts(exp);

-- The original replay records lack recipient and target data. Preserve their
-- single-gateway scope until the sender's retry window has elapsed.
UPDATE nathan_gateway_logout_jti SET exp = max(exp, unixepoch() + 172800) WHERE exp > unixepoch();
