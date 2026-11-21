-- A per-claim lease token makes stage completion compare-and-set: a request whose lease
-- expired (or that read a stale stage) cannot advance or rewind the job.
ALTER TABLE nathan_install_jobs ADD COLUMN lease_token TEXT;
-- Set immediately before the installer asks Cloudflare to create the D1 database, so an
-- interrupted create can later adopt that exact, still-empty database instead of failing forever.
ALTER TABLE nathan_install_jobs ADD COLUMN database_create_started INTEGER NOT NULL DEFAULT 0
  CHECK (database_create_started IN (0,1));
