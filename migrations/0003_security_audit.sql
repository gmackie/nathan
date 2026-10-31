-- Append-only by application convention; export for tamper-evident regulated evidence.
CREATE TABLE IF NOT EXISTS nathan_security_audit (
  id TEXT NOT NULL PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  outcome TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_security_audit_created_idx ON nathan_security_audit(created_at DESC);
