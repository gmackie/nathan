-- Optional SCIM directory connection requested by the initial Cloudflare wizard.
-- The bearer token is never persisted in installer jobs; it is shown only once.
ALTER TABLE nathan_install_jobs ADD COLUMN scim_requested INTEGER NOT NULL DEFAULT 0 CHECK(scim_requested IN (0,1));
ALTER TABLE nathan_install_jobs ADD COLUMN scim_connection_id TEXT;
ALTER TABLE nathan_install_jobs ADD COLUMN scim_domain TEXT;
