-- Apply to the stock gateway's D1 before closing ingress or draining its Worker.
CREATE TRIGGER IF NOT EXISTS nathan_gateway_pause_session_creation
BEFORE INSERT ON nathan_gateway_sessions
BEGIN
  SELECT RAISE(ABORT, 'gateway session creation paused');
END;
