-- A per-claim lease token makes stage completion compare-and-set: a request whose lease
-- expired (or that read a stale stage) cannot advance or rewind the job.
ALTER TABLE nathan_install_jobs ADD COLUMN lease_token TEXT;
-- Set (unixepoch) immediately before the installer asks Cloudflare to create the D1 database
-- and cleared if Cloudflare definitively rejects it. An interrupted create can later adopt a
-- database only if Cloudflare created it after this time and it is still completely empty.
ALTER TABLE nathan_install_jobs ADD COLUMN database_create_started_at INTEGER;
