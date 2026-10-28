-- One installer job per signed-in Cloudflare identity, scoped to a customer account.
CREATE TABLE IF NOT EXISTS nathan_install_jobs (
  id TEXT PRIMARY KEY NOT NULL,
  owner_user_id TEXT NOT NULL,
  owner_email TEXT NOT NULL,
  account_id TEXT NOT NULL,
  zone_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  worker_name TEXT NOT NULL,
  admin_email TEXT NOT NULL,
  profile TEXT NOT NULL CHECK(profile IN ('standard','business')),
  release_id TEXT NOT NULL,
  stage TEXT NOT NULL DEFAULT 'database',
  database_id TEXT,
  error TEXT,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  CHECK(stage IN ('database','schema','upload','domain','activate','verify','bootstrap','complete'))
);
CREATE UNIQUE INDEX IF NOT EXISTS nathan_install_job_unique_target ON nathan_install_jobs(account_id,worker_name);
CREATE INDEX IF NOT EXISTS nathan_install_job_owner ON nathan_install_jobs(owner_user_id,account_id,created_at);
