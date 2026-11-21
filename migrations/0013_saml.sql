-- Nathan's management layer for inbound enterprise SAML (NATH-10).
-- The @better-auth/sso plugin owns the protocol and the "ssoProvider" row;
-- this table owns Nathan policy: a connection is disabled by default, can only
-- be enabled after Better Auth's DNS TXT domain verification, and never
-- creates accounts unless provisioning is explicitly 'just-in-time'.
-- certificates is a JSON array of validated signing certificates (base64 DER
-- plus fingerprint/validity) from which Nathan rebuilds the IdP metadata.
CREATE TABLE IF NOT EXISTS nathan_saml_connections (
  provider_id TEXT PRIMARY KEY NOT NULL,
  domain TEXT NOT NULL,
  idp_entity_id TEXT NOT NULL,
  sso_url TEXT NOT NULL,
  sso_post_url TEXT,
  certificates TEXT NOT NULL,
  provisioning TEXT NOT NULL DEFAULT 'invitation-only' CHECK(provisioning IN ('invitation-only','just-in-time')),
  attribute_preset TEXT NOT NULL DEFAULT 'generic' CHECK(attribute_preset IN ('generic','okta','entra','google')),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_saml_connections_domain ON nathan_saml_connections(domain,enabled);
