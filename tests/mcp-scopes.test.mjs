import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { isReservedScope, validateResourceConfig, buildCatalog, parseRequestedScopes, concreteScopes,
  formatGrant, parseGrant, offeredScopes, selectScopes, effectiveScopes, scopeString, narrowScopes,
  validateRedirectUri, parseRegistration, MCP_ACCESS_TOKEN_SECONDS,
  MCP_UNUSED_CLIENT_SECONDS, MCP_UNUSED_CLIENT_LIMIT, MCP_CLIENT_SECONDS } from "../src/shared/mcp-scopes.mjs";

const PERMISSIONS = [
  { key: "notes:read", description: "Read notes" },
  { key: "notes:write", description: "Write notes" },
  { key: "notes:share", description: "Share notes" },
  { key: "notes:export", description: "Export every note" },
  { key: "nathan:admin", description: "reserved, never a scope" }
];
const CONFIG = {
  name: "Notes",
  full: "notes:full",
  aliases: { "notes:basic": ["notes:read", "notes:write"] },
  scopes: {
    "notes:read": { label: "Read notes", description: "List and read your notes." },
    "notes:write": { label: "Write notes", description: "Create and edit notes.", requires: ["notes:read"] },
    "notes:share": { label: "Share notes", description: "Share notes with others.", requires: ["notes:write"] },
    "notes:export": { label: "Export all notes", description: "Download every note at once.", sensitive: true }
  }
};
const config = validateResourceConfig(CONFIG, PERMISSIONS.map(p => p.key));
const catalog = buildCatalog({ ...config, permissions: PERMISSIONS, metadata: config.scopes });
const set = (...values) => new Set(values);
const sorted = s => [...s].sort();

test("reserved OIDC and Nathan scopes are never MCP scopes", () => {
  for (const s of ["openid", "profile", "email", "offline_access", "nathan:admin", "nathan:read", "nathan:api"]) assert.ok(isReservedScope(s), s);
  assert.ok(!isReservedScope("notes:read"));
  assert.deepEqual(catalog.entries.map(e => e.scope), ["notes:export", "notes:read", "notes:share", "notes:write"]);
  assert.equal(catalog.byScope.get("notes:read").label, "Read notes");
});

test("catalog validation refuses unsafe metadata", () => {
  const keys = PERMISSIONS.map(p => p.key);
  for (const [bad, message] of [
    [{ ...CONFIG, name: "" }, /name/],
    [{ ...CONFIG, full: "notes:read" }, /Full access/],
    [{ ...CONFIG, full: "openid" }, /Full access/],
    [{ ...CONFIG, aliases: { "notes:all": ["notes:export"] } }, /sensitive/],
    [{ ...CONFIG, aliases: { "notes:read": ["notes:write"] } }, /alias/i],
    [{ ...CONFIG, aliases: { "notes:x": ["notes:missing"] } }, /Unknown/],
    [{ ...CONFIG, scopes: { ...CONFIG.scopes, "notes:read": { requires: ["notes:export"] } } }, /sensitive/],
    [{ ...CONFIG, scopes: { "notes:missing": { label: "x" } } }, /Unknown/],
    [{ ...CONFIG, scopes: { "nathan:admin": { label: "x" } } }, /reserved/],
    [{ ...CONFIG, scopes: { "notes:read": { label: "a\u0000b" } } }, /label/],
    [{ ...CONFIG, scopes: { "notes:read": { requires: ["notes:read"] } } }, /itself/]
  ]) assert.throws(() => validateResourceConfig(bad, keys), message, JSON.stringify(bad));
  const admin = validateResourceConfig({ name: "N", scopes: { "notes:export": { adminOnly: true } } }, keys);
  assert.equal(admin.scopes.find(s => s.scope === "notes:export").sensitive, true, "admin-only implies sensitive");
});

test("requests expand aliases, full access and prerequisites, never into sensitive scopes", () => {
  assert.deepEqual(sorted(parseRequestedScopes(catalog, "notes:share")), ["notes:read", "notes:share", "notes:write"]);
  assert.deepEqual(sorted(parseRequestedScopes(catalog, "notes:share", { prerequisites: false })), ["notes:share"]);
  assert.deepEqual(sorted(parseRequestedScopes(catalog, "notes:basic offline_access")), ["notes:read", "notes:write"]);
  assert.deepEqual(sorted(concreteScopes(catalog, parseRequestedScopes(catalog, "notes:full"))), ["notes:read", "notes:share", "notes:write"]);
  assert.deepEqual(sorted(parseRequestedScopes(catalog, "notes:export")), ["notes:export"], "sensitive scopes only by name");
  assert.equal(parseRequestedScopes(catalog, "notes:read openid"), null);
  assert.equal(parseRequestedScopes(catalog, "notes:delete"), null);
  assert.equal(parseRequestedScopes(catalog, "nathan:admin"), null);
  assert.equal(parseRequestedScopes(catalog, "x".repeat(5000)), null);
  assert.deepEqual(sorted(parseRequestedScopes(catalog, "")), []);
});

test("full access is stored as a marker and covers scopes added later but never sensitive ones", () => {
  const stored = formatGrant(catalog, set("notes:full", "notes:read", "notes:export"));
  assert.equal(stored, "notes:full notes:export");
  const later = buildCatalog({ ...config, permissions: [...PERMISSIONS, { key: "notes:tag", description: "" }], metadata: config.scopes });
  assert.deepEqual(sorted(parseGrant(later, stored)), ["notes:export", "notes:read", "notes:share", "notes:tag", "notes:write"]);
  assert.deepEqual(sorted(parseGrant(catalog, "notes:full")), ["notes:read", "notes:share", "notes:write"]);
  assert.deepEqual(sorted(parseGrant(catalog, "notes:read notes:gone")), ["notes:read"], "removed permissions drop out");
  assert.equal(formatGrant(catalog, set("notes:write", "notes:read")), "notes:read notes:write");
});

test("consent selection: offered scopes only, prerequisites added, sensitive only when ticked, empty refused", () => {
  const perms = set("notes:read", "notes:write", "notes:share", "notes:export");
  const offered = offeredScopes(catalog, perms, { admin: false });
  assert.deepEqual(sorted(offered), ["notes:export", "notes:read", "notes:share", "notes:write"]);
  assert.equal(selectScopes(catalog, ["notes:share"], offered).stored, "notes:read notes:share notes:write");
  assert.equal(selectScopes(catalog, ["notes:full"], offered).stored, "notes:full");
  assert.equal(selectScopes(catalog, ["notes:full", "notes:export"], offered).stored, "notes:full notes:export");
  assert.throws(() => selectScopes(catalog, [], offered), /at least one/);
  assert.throws(() => selectScopes(catalog, ["notes:read", "notes:read"], offered), /Invalid scope selection/);
  assert.throws(() => selectScopes(catalog, ["openid"], offered), /Invalid scope selection/);
  const readOnly = offeredScopes(catalog, set("notes:read"), { admin: false });
  assert.throws(() => selectScopes(catalog, ["notes:write"], readOnly), /Invalid scope selection/);
  // A prerequisite the user cannot hold is not added.
  assert.equal(selectScopes(catalog, ["notes:write"], set("notes:write")).stored, "notes:write");
  const adminCatalog = buildCatalog({ ...config, permissions: PERMISSIONS,
    metadata: [...config.scopes.filter(s => s.scope !== "notes:export"), { scope: "notes:export", label: "", description: "", group: "general", requires: [], sensitive: true, adminOnly: true }] });
  assert.ok(!offeredScopes(adminCatalog, perms, { admin: false }).has("notes:export"));
  assert.ok(offeredScopes(adminCatalog, perms, { admin: true }).has("notes:export"));
});

test("effective scopes are the grant intersected with the user's current permissions", () => {
  const granted = parseGrant(catalog, "notes:full notes:export");
  assert.deepEqual(sorted(effectiveScopes(catalog, granted, set("notes:read", "notes:export"), { admin: false })), ["notes:export", "notes:read"]);
  assert.deepEqual(sorted(effectiveScopes(catalog, granted, set(), { admin: false })), []);
  assert.equal(scopeString(catalog, set("notes:write", "notes:read")), "notes:read notes:write");
});

test("refresh narrowing intersects with what the grant holds now; only nothing-left is an error", () => {
  const granted = set("notes:read", "notes:write");
  assert.deepEqual(sorted(narrowScopes(catalog, "notes:read", granted)), ["notes:read"]);
  assert.deepEqual(sorted(narrowScopes(catalog, "notes:share notes:read", granted)), ["notes:read"], "scopes the grant lost are dropped");
  assert.deepEqual(sorted(narrowScopes(catalog, "notes:share", granted)), [], "nothing remains");
  assert.equal(narrowScopes(catalog, "notes:nope", granted), null, "unknown scope");
  assert.deepEqual(sorted(narrowScopes(catalog, "notes:full", granted)), ["notes:read", "notes:write"]);
});

test("public-client registration: exact https or loopback redirects, no secrets, no reserved scopes", () => {
  for (const ok of ["https://client.example/callback", "http://127.0.0.1:33418/callback", "http://localhost/cb", "http://[::1]:9/cb"])
    assert.equal(validateRedirectUri(ok), ok, ok);
  for (const bad of ["http://client.example/cb", "https://client.example/cb#x", "https://user:pw@client.example/cb", "javascript:alert(1)",
    "https://*.example/cb", "", "x".repeat(3000), "http://127.0.0.1.evil.example/cb", "data:text/html,hi", "com.example.app:/oauth"])
    assert.equal(validateRedirectUri(bad), null, bad);
  const ok = parseRegistration({ client_name: "Agent", redirect_uris: ["http://127.0.0.1:1/cb"], token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], scope: "notes:read" }, set("notes:read"));
  assert.deepEqual(ok, { client_name: "Agent", redirect_uris: ["http://127.0.0.1:1/cb"], scope: "notes:read" });
  for (const [bad, code] of [
    [{ redirect_uris: [] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["http://evil.example/cb"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["https://a.example/cb"], token_endpoint_auth_method: "client_secret_basic" }, "invalid_client_metadata"],
    [{ redirect_uris: ["https://a.example/cb"], grant_types: ["client_credentials"] }, "invalid_client_metadata"],
    [{ redirect_uris: ["https://a.example/cb"], scope: "openid notes:read" }, "invalid_client_metadata"],
    [{ redirect_uris: ["https://a.example/cb"], scope: "nathan:admin" }, "invalid_client_metadata"],
    [{ redirect_uris: ["https://a.example/cb"], client_name: "a\u0007" }, "invalid_client_metadata"],
    [{ redirect_uris: ["https://a.example/cb"], client_name: "a".repeat(65) }, "invalid_client_metadata"],
    [{ redirect_uris: ["https://a.example/1", "https://a.example/2", "https://a.example/3", "https://a.example/4", "https://a.example/5", "https://a.example/6"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["https://a.example/" + "x".repeat(495)] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["https://a.example/cb"], scope: "notes:read ".repeat(100) }, "invalid_client_metadata"]
  ]) assert.throws(() => parseRegistration(bad, set("notes:read")), e => e.code === code, JSON.stringify(bad));
  assert.ok(MCP_ACCESS_TOKEN_SECONDS <= 900);
});

test("registration stores only bounded, known metadata; unused clients are short-lived and capped", () => {
  // Unknown and informational fields are dropped, not stored (RFC 7591 §2 lets a server ignore them).
  const stored = parseRegistration({ client_name: "a".repeat(64), redirect_uris: ["https://a.example/" + "x".repeat(494)],
    jwks_uri: "https://a.example/jwks", logo_uri: "https://a.example/logo.png", software_statement: "x".repeat(4000), extra: { deep: [1, 2, 3] } }, set("notes:read"));
  assert.deepEqual(stored, { client_name: "a".repeat(64), redirect_uris: ["https://a.example/" + "x".repeat(494)] });
  const worst = parseRegistration({ client_name: "a".repeat(64), redirect_uris: [1, 2, 3, 4, 5].map(i => "https://a.example/" + i + "x".repeat(493)),
    scope: Array(93).fill("notes:read").join(" ") }, set("notes:read"));
  assert.ok(JSON.stringify(worst).length < 4096, "a stored registration stays under 4 KB");
  assert.ok(MCP_UNUSED_CLIENT_SECONDS <= 24 * 3600, "a client that never obtained a grant is pruned within a day");
  assert.ok(MCP_UNUSED_CLIENT_LIMIT > 0 && MCP_UNUSED_CLIENT_LIMIT <= 2000);
  assert.ok(MCP_CLIENT_SECONDS >= MCP_UNUSED_CLIENT_SECONDS);
});

test("migration 0015 stores MCP resources, clients, grants and one-time artifacts with cascades", () => {
  const migrations = readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort();
  assert.equal(migrations.filter(f => f.startsWith("0015")).length, 1);
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of migrations) db.exec(readFileSync("migrations/" + file, "utf8"));
  const run = (sql, ...p) => db.prepare(sql).run(...p);
  run("INSERT INTO nathan_applications(id,hostname) VALUES ('notes','notes.example.test')");
  run('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u1\',\'u\',\'u@x\',1,0,0)');
  run("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES ('https://notes.example.test/mcp','notes','admin')");
  run("INSERT INTO nathan_mcp_resources(identifier,app_id,name,created_by) VALUES ('https://notes.example.test/mcp','notes','Notes','admin')");
  run("INSERT INTO nathan_mcp_scopes(resource,scope,sensitive,admin_only) VALUES ('https://notes.example.test/mcp','notes:read',0,0)");
  assert.throws(() => run("INSERT INTO nathan_mcp_scopes(resource,scope,sensitive,admin_only) VALUES ('https://notes.example.test/mcp','notes:x',0,1)"), "admin-only must be sensitive");
  run("INSERT INTO nathan_mcp_clients(client_id,client_name,redirect_uris,expires_at) VALUES ('c1','A','[]',unixepoch()+60)");
  assert.equal(db.prepare("SELECT first_grant_at FROM nathan_mcp_clients WHERE client_id='c1'").get().first_grant_at, null, "unused until its first grant");
  assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='nathan_mcp_clients_unused'").get(), "unused clients are counted and pruned by index");
  run("INSERT INTO nathan_mcp_grants(id,user_id,client_id,resource,scope,expires_at) VALUES ('g1','u1','c1','https://notes.example.test/mcp','notes:read',unixepoch()+60)");
  run("INSERT INTO nathan_mcp_artifacts(hash,kind,grant_id,expires_at) VALUES ('h1','refresh','g1',unixepoch()+60)");
  assert.throws(() => run("INSERT INTO nathan_mcp_artifacts(hash,kind,expires_at) VALUES ('h2','password',unixepoch())"));
  run("DELETE FROM nathan_mcp_grants WHERE id='g1'");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_mcp_artifacts").get().n, 0, "revoking a grant removes its tokens");
  run("INSERT INTO nathan_mcp_grants(id,user_id,client_id,resource,scope,expires_at) VALUES ('g2','u1','c1','https://notes.example.test/mcp','notes:read',unixepoch()+60)");
  run("DELETE FROM nathan_token_audiences WHERE identifier='https://notes.example.test/mcp'");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_mcp_grants").get().n, 0, "removing the audience removes the resource and its grants");
  assert.equal(db.prepare("SELECT count(*) AS n FROM nathan_mcp_scopes").get().n, 0);
});
