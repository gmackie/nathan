-- NATH-13: per-application roles and a minimal RBAC.
-- Applications declare permission strings, roles bundle permissions, and roles are granted per
-- application to users or groups. Deny by default. Better Auth's global "admin" role stays for
-- Nathan administration only and no longer grants application access by itself.
-- NATH-1 access modes: 'approved' (grants only; no grants = nobody) and 'any_signed_in'.
ALTER TABLE nathan_applications ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'approved' CHECK(access_mode IN ('approved','any_signed_in'));
CREATE TABLE IF NOT EXISTS nathan_rbac_permissions (
  app_id TEXT NOT NULL REFERENCES nathan_applications(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'studio' CHECK(source IN ('studio','code','legacy')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(app_id,key)
);
CREATE TABLE IF NOT EXISTS nathan_rbac_roles (
  app_id TEXT NOT NULL REFERENCES nathan_applications(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'studio' CHECK(source IN ('studio','code','legacy')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(app_id,key)
);
CREATE TABLE IF NOT EXISTS nathan_rbac_role_permissions (
  app_id TEXT NOT NULL,
  role_key TEXT NOT NULL,
  permission_key TEXT NOT NULL,
  PRIMARY KEY(app_id,role_key,permission_key),
  FOREIGN KEY(app_id,role_key) REFERENCES nathan_rbac_roles(app_id,key) ON DELETE CASCADE,
  FOREIGN KEY(app_id,permission_key) REFERENCES nathan_rbac_permissions(app_id,key) ON DELETE CASCADE
);
-- Groups are Nathan-managed. 'scim' is reserved for explicit SCIM group mapping (NATH-11).
CREATE TABLE IF NOT EXISTS nathan_groups (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'studio' CHECK(source IN ('studio','legacy','scim')),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS nathan_group_members (
  group_id TEXT NOT NULL REFERENCES nathan_groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  added_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY(group_id,user_id)
);
CREATE INDEX IF NOT EXISTS nathan_group_members_user ON nathan_group_members(user_id);
-- principal_id is a Better Auth user id or a nathan_groups id; the Worker deletes a group's grants with the group.
CREATE TABLE IF NOT EXISTS nathan_rbac_grants (
  id TEXT PRIMARY KEY NOT NULL,
  app_id TEXT NOT NULL,
  role_key TEXT NOT NULL,
  principal_type TEXT NOT NULL CHECK(principal_type IN ('user','group')),
  principal_id TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(app_id,role_key,principal_type,principal_id),
  FOREIGN KEY(app_id,role_key) REFERENCES nathan_rbac_roles(app_id,key) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS nathan_rbac_grants_principal ON nathan_rbac_grants(principal_type,principal_id,app_id);
-- Ordered change feed of RBAC writes for Gatekeeper's policy-information point. Written in the
-- same batch as each change; entries older than 30 days are pruned and pruned_through marks the gap.
CREATE TABLE IF NOT EXISTS nathan_rbac_changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  app_id TEXT,
  principal_type TEXT CHECK(principal_type IS NULL OR principal_type IN ('user','group')),
  principal_id TEXT,
  detail TEXT NOT NULL DEFAULT '{}',
  actor TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS nathan_rbac_changes_created ON nathan_rbac_changes(created_at);
CREATE TABLE IF NOT EXISTS nathan_rbac_feed_state (
  id TEXT PRIMARY KEY NOT NULL DEFAULT 'primary' CHECK(id='primary'),
  pruned_through INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO nathan_rbac_feed_state(id,pruned_through) VALUES ('primary',0);
-- Legacy migration. Before NATH-13 an enabled app with an empty role list admitted every signed-in
-- user, and a non-empty list admitted users whose single global Better Auth role (NULL = 'user')
-- was listed. Keep those decisions: empty lists become 'any_signed_in'; each listed role becomes an
-- app role granted to a snapshot group of the users holding that global role today. Later changes
-- to a user's global role no longer change application access. Malformed lists grant nothing.
UPDATE nathan_applications SET access_mode='any_signed_in'
  WHERE json_valid(roles) AND json_type(roles)='array' AND json_array_length(roles)=0;
INSERT OR IGNORE INTO nathan_rbac_roles(app_id,key,description,source)
  SELECT a.id, r.value, 'Migrated from the legacy required-role list', 'legacy'
  FROM nathan_applications a, json_each(CASE WHEN json_valid(a.roles) AND json_type(a.roles)='array' THEN a.roles ELSE '[]' END) r
  WHERE r.type='text' AND r.value GLOB '[a-z]*' AND NOT r.value GLOB '*[^a-z0-9_-]*' AND length(r.value)<=63;
INSERT OR IGNORE INTO nathan_groups(id,name,description,source,created_by)
  SELECT DISTINCT 'legacy-role-'||key, 'Legacy global role '||key, 'Users who held the global Better Auth role at migration 0011', 'legacy', 'migration:0011'
  FROM nathan_rbac_roles WHERE source='legacy';
INSERT OR IGNORE INTO nathan_group_members(group_id,user_id,added_by)
  SELECT g.id, u."id", 'migration:0011'
  FROM nathan_groups g JOIN "user" u ON 'legacy-role-'||COALESCE(u."role",'user')=g.id
  WHERE g.source='legacy';
-- Grant ids are length-prefixed ('legacy-<len(app)>-<app>-<role>') so (a, b-c) and (a-b, c) differ.
INSERT OR IGNORE INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by)
  SELECT 'legacy-'||length(app_id)||'-'||app_id||'-'||key, app_id, key, 'group', 'legacy-role-'||key, 'migration:0011'
  FROM nathan_rbac_roles WHERE source='legacy';
INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
  SELECT lower(hex(randomblob(16))), 'migration:0011', 'rbac_legacy_migration',
    (SELECT count(*) FROM nathan_rbac_grants WHERE created_by='migration:0011')||' legacy grants', 'succeeded';
