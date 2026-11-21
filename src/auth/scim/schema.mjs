/** Per-connection SCIM directory schema. All mutations run under Durable Object transactionSync. */
export const DIRECTORY_SCHEMA="CREATE TABLE IF NOT EXISTS scim_users (\n  id TEXT PRIMARY KEY NOT NULL,\n  external_id TEXT NOT NULL UNIQUE,\n  user_name TEXT NOT NULL UNIQUE,\n  display_name TEXT NOT NULL,\n  emails_json TEXT NOT NULL,\n  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),\n  deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),\n  revision INTEGER NOT NULL DEFAULT 1,\n  created_at INTEGER NOT NULL,\n  updated_at INTEGER NOT NULL\n);\nCREATE INDEX IF NOT EXISTS scim_user_search ON scim_users(user_name,external_id,deleted);\nCREATE TABLE IF NOT EXISTS scim_groups (\n  id TEXT PRIMARY KEY NOT NULL,\n  display_name TEXT NOT NULL UNIQUE,\n  external_id TEXT,\n  revision INTEGER NOT NULL DEFAULT 1,\n  deleted INTEGER NOT NULL DEFAULT 0 CHECK(deleted IN (0,1)),\n  created_at INTEGER NOT NULL,\n  updated_at INTEGER NOT NULL\n);\nCREATE TABLE IF NOT EXISTS scim_group_members (\n  group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,\n  user_id TEXT NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE,\n  PRIMARY KEY(group_id,user_id)\n);\nCREATE INDEX IF NOT EXISTS scim_group_member_user ON scim_group_members(user_id);\nCREATE TABLE IF NOT EXISTS scim_request_rates (\n  bucket INTEGER PRIMARY KEY NOT NULL,\n  count INTEGER NOT NULL CHECK(count >= 0)\n);\nCREATE TABLE IF NOT EXISTS scim_events (\n  id TEXT PRIMARY KEY NOT NULL,\n  kind TEXT NOT NULL,\n  resource_id TEXT NOT NULL,\n  event TEXT NOT NULL,\n  created_at INTEGER NOT NULL\n);\n";
/**
 * NATH-11 additions, applied after DIRECTORY_SCHEMA and after a directory created before NATH-11
 * gained scim_groups.external_id (the Durable Object adds that column when it is missing).
 * scim_outbox is the ordered queue of staged changes still to be applied to D1: a row is removed only
 * after reconciliation committed it, so a failed application is retried, never lost.
 */
export const DIRECTORY_LIFECYCLE_SCHEMA="CREATE UNIQUE INDEX IF NOT EXISTS scim_group_external ON scim_groups(external_id) WHERE external_id IS NOT NULL;\n"+
"CREATE TABLE IF NOT EXISTS scim_outbox (\n  seq INTEGER PRIMARY KEY AUTOINCREMENT,\n  kind TEXT NOT NULL CHECK(kind IN ('User','Group')),\n"+
"  resource_id TEXT NOT NULL,\n  revision INTEGER NOT NULL,\n  force INTEGER NOT NULL DEFAULT 0 CHECK(force IN (0,1)),\n"+
"  attempts INTEGER NOT NULL DEFAULT 0,\n  last_error TEXT,\n  created_at INTEGER NOT NULL\n);\n"+
"CREATE INDEX IF NOT EXISTS scim_outbox_resource ON scim_outbox(kind,resource_id);\n"+
"CREATE TABLE IF NOT EXISTS scim_meta (\n  key TEXT PRIMARY KEY NOT NULL,\n  value TEXT NOT NULL\n);\n";
