-- Preserve the most recently accepted send even when an older provider call finishes later.
-- Keep the ordering record through redemption so a late mail cannot reopen that sign-in.
CREATE TABLE nathan_email_delivery_order (
  email TEXT PRIMARY KEY NOT NULL,
  requested INTEGER NOT NULL,
  delivered INTEGER NOT NULL DEFAULT 0,
  delivered_generation TEXT,
  expires_at INTEGER NOT NULL
);
CREATE INDEX nathan_email_delivery_expiry ON nathan_email_delivery_order(expires_at);

-- A previous Worker may still be waiting on its sender at cutover. Its upsert must
-- not overwrite or reopen a challenge published by the new Worker during this window.
-- Leave old verification identifiers in place so either Worker can read its own proofs.
CREATE TRIGGER nathan_email_delivery_before_insert BEFORE INSERT ON nathan_email_sign_ins
WHEN EXISTS (SELECT 1 FROM nathan_email_delivery_order d WHERE d.email=NEW.email
  AND d.delivered_generation<>NEW.generation AND d.expires_at>unixepoch())
BEGIN
  SELECT RAISE(IGNORE);
END;

-- A delayed promotion logout must target only the session that predates verification.
ALTER TABLE nathan_backchannel_deliveries ADD COLUMN session_id TEXT;
