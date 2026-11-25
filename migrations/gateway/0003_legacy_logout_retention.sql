-- The old Worker treats each JTI as seen until its pruning job physically removes it.
-- Retain even expired rows it still recognizes, including writes made during 0002.
UPDATE nathan_gateway_logout_jti SET exp = max(exp, unixepoch() + 172800);

-- Preserve a late legacy write for the same redelivery period as a scoped receipt.
CREATE TRIGGER nathan_gateway_retain_legacy_logout AFTER INSERT ON nathan_gateway_logout_jti
WHEN NEW.exp < unixepoch() + 172800
BEGIN
  UPDATE nathan_gateway_logout_jti SET exp = unixepoch() + 172800 WHERE jti = NEW.jti;
END;
