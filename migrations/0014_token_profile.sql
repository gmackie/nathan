-- NATH-15: Gatekeeper-ready access tokens.
-- Token audiences are RFC 8707 resource identifiers (for example Gatekeeper's API) that Nathan
-- issues JWT access tokens for. Better Auth's oauthResource row holds the issuance policy (lifetime,
-- scopes); this row adds Nathan's binding to an application, whose NATH-13 roles the token's
-- optional `roles` hint is computed for. NULL app_id: no roles claim.
CREATE TABLE IF NOT EXISTS nathan_token_audiences (
  identifier TEXT PRIMARY KEY NOT NULL,
  app_id TEXT REFERENCES nathan_applications(id) ON DELETE SET NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
-- Administrator-set principal kind for an OAuth client. Only 'agent' (agents and MCP clients);
-- clients without a row are classified by grant: a user session is 'user', client credentials
-- are 'machine'. Never 'user' by attribute.
CREATE TABLE IF NOT EXISTS nathan_client_principals (
  client_id TEXT PRIMARY KEY NOT NULL REFERENCES "oauthClient"("clientId") ON DELETE CASCADE,
  principal_kind TEXT NOT NULL CHECK(principal_kind IN ('agent')),
  set_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
