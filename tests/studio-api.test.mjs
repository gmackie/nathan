/**
 * NATH-24: Identity Studio JSON API v1 (/studio/api/v1). Runs the real router, authorization and
 * service functions against every migration on node:sqlite, with a stand-in for Better Auth's
 * session lookup and admin client endpoints.
 *
 * Covered: every route refuses unauthenticated, non-admin and missing-step-up requests (and writes
 * refuse cross-origin and non-JSON requests) before any service runs; schema failures give 400
 * validation_failed; and representative writes leave exactly the audit rows of the shared service
 * function the legacy /studio/api/* route calls.
 */
import "./fixtures/ts-modules.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { d1, migratedDatabase } from "./fixtures/d1-sqlite.mjs";

const { handleStudioApiV1, STUDIO_API_V1_ROUTES, STUDIO_API_V1 } = await import("../src/auth/studio-api/index.ts");
const schemas = await import("../src/auth/studio-api/schemas.ts");
const { grantAdmin, createOAuthClient } = await import("../src/auth/admin-service.ts");
const { setOAuthClientStatus } = await import("../src/auth/studio-api/clients.ts");
const { applyRbacOperation } = await import("../src/auth/rbac.ts");
const { applyAdmissionOperation } = await import("../src/auth/admission.ts");

const ISSUER = "https://login.example.test";
const ADMIN = { id: "u-admin", email: "admin@example.test", emailVerified: true, role: "admin", name: "Admin" };
const PLAIN = { id: "u-user", email: "user@example.test", emailVerified: true, role: "user", name: "User" };
const SESSIONS = {
  admin: { user: ADMIN, session: { id: "s-admin" } },      // enrolled, recent passkey step-up
  nostep: { user: ADMIN, session: { id: "s-nostep" } },    // enrolled, no step-up for this session
  user: { user: PLAIN, session: { id: "s-user" } }
};

function setup({ bootstrapState = "complete" } = {}) {
  const db = migratedDatabase();
  const run = (sql, ...params) => db.prepare(sql).run(...params);
  const user = (u, verified = 1) => run('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,?,0,0,?)',
    u.id, u.name, u.email, verified, u.role);
  user(ADMIN); user(PLAIN);
  for (const { session, user: owner } of Object.values(SESSIONS))
    run('INSERT INTO "session"(id, token, userId, expiresAt, createdAt, updatedAt) VALUES (?,?,?,unixepoch()+3600,unixepoch(),unixepoch())', session.id, session.id, owner.id);
  user({ id: "u-bob", email: "bob@example.test", name: "Bob", role: "user" });
  run("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf-1',?,?,?)", ADMIN.email, ADMIN.id, bootstrapState);
  run('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (\'pk1\',\'k\',?,\'cred\',0,\'singleDevice\',0)', ADMIN.id);
  run('INSERT INTO "twoFactor"("id","secret","backupCodes","userId","verified") VALUES (\'tf1\',\'s\',\'[]\',?,1)', ADMIN.id);
  run("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES ('s-admin',?,'passkey')", ADMIN.id);
  const created = [], updated = [];
  const auth = {
    api: {
      getSession: async ({ headers }) => SESSIONS[headers.get("Cookie") ?? ""] ?? null,
      adminCreateOAuthClient: async ({ body }) => {
        const client_id = "client-" + (created.length + 1);
        run('INSERT INTO "oauthClient"("id","clientId","name","redirectUris","disabled","createdAt") VALUES (?,?,?,?,0,?)',
          client_id, client_id, body.client_name ?? "", JSON.stringify(body.redirect_uris ?? []), String(created.length));
        created.push(body);
        return { client_id, client_secret: "secret-" + client_id };
      },
      adminUpdateOAuthClient: async ({ body }) => {
        run('UPDATE "oauthClient" SET "disabled"=? WHERE "clientId"=?', body.update.disabled ? 1 : 0, body.client_id);
        updated.push(body);
        return {};
      }
    }
  };
  const env = {
    DB: d1(db), NATHAN_ISSUER: ISSUER, NATHAN_ADMIN_EMAILS: ADMIN.email, NATHAN_BOOTSTRAP_REQUIRED: "true",
    NATHAN_SECURITY_PROFILE: "business", NATHAN_ADMIN_STEPUP_REQUIRED: "true", ENTERPRISE_SSO: "false", ENABLE_PASSWORD: "false"
  };
  const auditRows = () => db.prepare("SELECT actor,action,target,outcome FROM nathan_security_audit ORDER BY rowid").all().map(r => ({ ...r }));
  return { db, run, env, auth, auditRows, created, updated };
}

function request(path, { method = "GET", session, body, origin = ISSUER, contentType = "application/json", headers = {} } = {}) {
  const h = new Headers(headers);
  if (session) h.set("Cookie", session);
  if (method !== "GET") {
    if (origin) h.set("Origin", origin);
    if (contentType) h.set("Content-Type", contentType);
  }
  return new Request(ISSUER + STUDIO_API_V1 + path, { method, headers: h, body: method === "GET" ? undefined : typeof body === "string" ? body : JSON.stringify(body ?? {}) });
}
async function call(t, path, options) {
  const response = await handleStudioApiV1(request(path, options), t.env, t.auth);
  const json = await response.json();
  return { status: response.status, json, headers: response.headers };
}

// ---- Route table ----------------------------------------------------------------------------------

test("every legacy /studio/api/* route has a v1 route with the same path and method", () => {
  const sources = ["src/auth/worker.ts", "src/auth/saml-routes.ts", "src/auth/saml-idp.ts"].map(f => readFileSync(f, "utf8")).join("\n");
  const legacy = new Set([...sources.matchAll(/"\/studio\/api\/(?!v1)([a-z0-9/_-]+)"/g)].map(m => "/" + m[1]));
  const v1 = new Set(STUDIO_API_V1_ROUTES.map(r => r.path));
  const missing = [...legacy].filter(p => !v1.has(p));
  assert.deepEqual(missing, [], "legacy Studio routes without a v1 route");
  assert.ok(legacy.size >= 40, "found the legacy routes (" + legacy.size + ")");
});

test("route actions are unique and every route has an input schema", () => {
  const actions = STUDIO_API_V1_ROUTES.map(r => r.action);
  assert.equal(new Set(actions).size, actions.length);
  for (const route of STUDIO_API_V1_ROUTES) {
    assert.equal(typeof route.input?.safeParse, "function", route.action);
    if (route.method === "POST") assert.ok(route.maxBytes > 0, route.action + " has a body limit");
  }
});

test("every error code the API returns is a published, stable code", () => {
  const sources = readdirSync("src/auth/studio-api").filter(f => f.endsWith(".ts") && f !== "schemas.ts")
    .map(f => readFileSync("src/auth/studio-api/" + f, "utf8")).join("\n");
  const used = new Set([...sources.matchAll(/\(\d{3}, "([a-z_]+)"/g)].map(m => m[1]));
  for (const call of sources.matchAll(/deny\(\d{3}, "([a-z_]+)"/g)) used.add(call[1]);
  assert.ok(used.size >= 10, [...used].join(","));
  for (const code of used) assert.ok(schemas.STUDIO_ERROR_CODES.includes(code), code + " is not in STUDIO_ERROR_CODES");
});

// ---- Authorization --------------------------------------------------------------------------------

test("every v1 route refuses unauthenticated, non-admin and missing-step-up requests before any service runs", async () => {
  const t = setup();
  const before = t.db.prepare("SELECT count(*) AS n FROM nathan_security_audit").get().n;
  for (const route of STUDIO_API_V1_ROUTES) {
    const options = { method: route.method, body: {} };
    const anon = await call(t, route.path, options);
    assert.equal(anon.status, 401, route.action);
    assert.deepEqual(anon.json, { ok: false, error: { code: "unauthenticated", message: anon.json.error.message } }, route.action);

    const plain = await call(t, route.path, { ...options, session: "user" });
    assert.equal(plain.status, 403, route.action);
    assert.equal(plain.json.error.code, "not_admin", route.action);

    const nostep = await call(t, route.path, { ...options, session: "nostep" });
    assert.equal(nostep.status, 403, route.action);
    assert.equal(nostep.json.error.code, "step_up_required", route.action);

    if (route.method === "POST") {
      const cross = await call(t, route.path, { ...options, session: "admin", origin: "https://evil.example" });
      assert.equal(cross.status, 403, route.action);
      assert.equal(cross.json.error.code, "cross_origin", route.action);
      const site = await call(t, route.path, { ...options, session: "admin", headers: { "Sec-Fetch-Site": "cross-site" } });
      assert.equal(site.json.error.code, "cross_origin", route.action);
      const form = await call(t, route.path, { ...options, session: "admin", contentType: "application/x-www-form-urlencoded" });
      assert.equal(form.status, 415, route.action);
      assert.equal(form.json.error.code, "unsupported_media_type", route.action);
    }
  }
  assert.equal(t.db.prepare("SELECT count(*) AS n FROM nathan_security_audit").get().n, before, "no refused request reached a service");
  assert.equal(t.created.length + t.updated.length, 0);
});

test("an administrator whose bootstrap is incomplete gets enrollment_incomplete", async () => {
  const t = setup({ bootstrapState: "identity_verified" });
  const r = await call(t, "/users", { session: "admin" });
  assert.equal(r.status, 403);
  // The bootstrap owner is not an admin principal until bootstrap completes (isAdminPrincipal).
  assert.equal(r.json.error.code, "not_admin");
  const granted = setup();
  granted.run("UPDATE nathan_bootstrap_status SET admin_user_id='someone-else'");
  granted.run("INSERT INTO nathan_admin_grants(user_id,email,granted_by) VALUES (?,?,'root')", ADMIN.id, ADMIN.email);
  granted.run("UPDATE nathan_bootstrap_status SET state='identity_verified'");
  const g = await call(granted, "/users", { session: "admin" });
  assert.equal(g.status, 403);
  assert.equal(g.json.error.code, "enrollment_incomplete");
});

test("the Studio API requires a current non-email administrator session", async () => {
  const t = setup();
  t.run("INSERT INTO nathan_email_otp_sessions(session_id,user_id) VALUES (?,?)", "s-admin", ADMIN.id);
  assert.equal((await call(t, "/users", { session: "admin" })).json.error.code, "not_admin");
  t.run('DELETE FROM "session" WHERE id=?', "s-admin");
  assert.equal((await call(t, "/users", { session: "admin" })).json.error.code, "not_admin");
});

test("Studio registers a public native client with its exact callback", async () => {
  const t = setup();
  const redirectUri = "io.example.mobile:/oauth";
  const result = await call(t, "/clients", {
    method: "POST", session: "admin", body: { name: "Mobile", kind: "native", publicClient: true, redirectUri }
  });
  assert.equal(result.status, 200);
  assert.equal(t.created[0].application_type, "native");
  assert.equal(t.created[0].token_endpoint_auth_method, "none");
  assert.equal(t.created[0].require_pkce, true);
  assert.deepEqual(t.created[0].redirect_uris, [redirectUri]);
});

test("a stepped-up administrator reads every GET route with the ok envelope", async () => {
  const t = setup();
  const query = { "/rbac": "?app=demo", "/rbac/group": "?id=team", "/scim/connection": "?id=acme", "/scim/outbox": "?id=acme" };
  t.run("INSERT INTO nathan_applications(id,hostname) VALUES ('demo','demo.example.test')");
  for (const route of STUDIO_API_V1_ROUTES.filter(r => r.method === "GET")) {
    const r = await call(t, route.path + (query[route.path] ?? ""), { session: "admin" });
    assert.equal(r.headers.get("Cache-Control"), "no-store", route.action);
    if (r.json.ok) { assert.equal(r.status, 200, route.action); assert.ok("data" in r.json, route.action); }
    else assert.ok(["not_found", "unavailable", "operation_rejected", "validation_failed"].includes(r.json.error.code), route.action + " " + JSON.stringify(r.json));
  }
  const users = await call(t, "/users", { session: "admin" });
  assert.deepEqual(users.json.data.users.map(u => u.email).sort(), ["admin@example.test", "bob@example.test", "user@example.test"]);
  const policy = await call(t, "/security-policy", { session: "admin" });
  assert.equal(policy.json.data.requireRecentPasskey, true);
});

// ---- Errors and validation ------------------------------------------------------------------------

test("unknown routes, wrong methods, bad JSON and oversized bodies have stable codes", async () => {
  const t = setup();
  const baseline = t.auditRows().length;
  const unknown = await call(t, "/nope", { session: "admin" });
  assert.equal(unknown.status, 404); assert.equal(unknown.json.error.code, "not_found");
  const method = await call(t, "/users", { method: "POST", session: "admin" });
  assert.equal(method.status, 405); assert.equal(method.json.error.code, "method_not_allowed");
  assert.equal(method.headers.get("Allow"), "GET");
  const json = await call(t, "/admins/grant", { method: "POST", session: "admin", body: "{not json" });
  assert.equal(json.status, 400); assert.equal(json.json.error.code, "invalid_json");
  const large = await call(t, "/admins/grant", { method: "POST", session: "admin", body: JSON.stringify({ email: "x".repeat(5000) }) });
  assert.equal(large.status, 413); assert.equal(large.json.error.code, "payload_too_large");
  assert.equal(t.auditRows().length, baseline, "nothing reached a service");
});

test("schema failures give 400 validation_failed with issue paths and no submitted values", async () => {
  const t = setup();
  const r = await call(t, "/clients", { method: "POST", session: "admin", body: { name: 42, kind: "nope", redirectUri: "https://app.example.test/cb", secret: "s3cr3t-value" } });
  assert.equal(r.status, 400);
  assert.equal(r.json.error.code, "validation_failed");
  assert.deepEqual(r.json.error.issues.map(i => i.path).sort(), ["kind", "name"]);
  assert.doesNotMatch(JSON.stringify(r.json), /s3cr3t-value/);
  assert.equal(t.created.length, 0, "the service refused it too: no client was created");

  for (const route of STUDIO_API_V1_ROUTES.filter(r => r.method === "POST")) {
    const bad = await call(t, route.path, { method: "POST", session: "admin", body: [] });
    assert.equal(bad.status, 400, route.action + " " + JSON.stringify(bad.json));
    assert.equal(bad.json.error.code, "validation_failed", route.action);
  }
  assert.equal(t.created.length + t.updated.length, 0);
});

test("a refused change is 409 operation_rejected with the service's safe message", async () => {
  const t = setup();
  const r = await call(t, "/admins/grant", { method: "POST", session: "admin", body: { email: "nobody@example.test", confirm: "CONFIRM GRANT ADMIN nobody@example.test" } });
  assert.equal(r.status, 409);
  assert.deepEqual(r.json.error, { code: "operation_rejected", message: "Admin grant/revocation denied; check verified identity, confirmation and recovery policy" });
  const rbac = await call(t, "/rbac", { method: "POST", session: "admin", body: { op: "role.upsert", app: "missing", key: "viewer", permissions: [] } });
  assert.equal(rbac.status, 409);
  assert.equal(rbac.json.error.code, "operation_rejected");
});

// ---- Audit parity ---------------------------------------------------------------------------------

/** Runs `direct` on one fresh database and the v1 request on another; both must audit the same rows. */
async function parity(prepare, direct, path, body) {
  const a = setup(), b = setup();
  await prepare?.(a); await prepare?.(b);
  const baseA = a.auditRows().length, baseB = b.auditRows().length;
  let directResult, directError;
  try { directResult = await direct(a); } catch (e) { directError = e; }
  const v1 = await call(b, path, { method: "POST", session: "admin", body });
  const rowsA = a.auditRows().slice(baseA), rowsB = b.auditRows().slice(baseB);
  return { rowsA, rowsB, v1, directResult, directError };
}
const headers = new Headers({ Origin: ISSUER });

test("audit parity: OAuth client disable (oauth_client_disable)", async () => {
  const prepare = t => t.run('INSERT INTO "oauthClient"("id","clientId","name","redirectUris","disabled") VALUES (\'c1\',\'client-a\',\'A\',\'[]\',0)');
  const body = { clientId: "client-a", disabled: true };
  const { rowsA, rowsB, v1 } = await parity(prepare, t => setOAuthClientStatus(t.auth, t.env, headers, body, ADMIN.id), "/clients/status", body);
  assert.equal(v1.status, 200);
  assert.deepEqual(v1.json.data, { updated: true, clientId: "client-a", disabled: true });
  assert.deepEqual(rowsB, [{ actor: ADMIN.id, action: "oauth_client_disable", target: "client-a", outcome: "succeeded" }]);
  assert.deepEqual(rowsB, rowsA);
});

test("audit parity: admin grant", async () => {
  const body = { email: "bob@example.test", confirm: "CONFIRM GRANT ADMIN bob@example.test" };
  const { rowsA, rowsB, v1 } = await parity(null, t => grantAdmin(t.env, body, ADMIN.id), "/admins/grant", body);
  assert.equal(v1.status, 200);
  assert.equal(v1.json.data.enabled, true);
  assert.deepEqual(rowsB, [
    { actor: ADMIN.id, action: "admin_grant", target: "u-bob", outcome: "attempted" },
    { actor: ADMIN.id, action: "admin_grant", target: "u-bob", outcome: "succeeded" }
  ]);
  assert.deepEqual(rowsB, rowsA);
});

test("audit parity: OAuth client create", async () => {
  const body = { name: "Billing", kind: "external", redirectUri: "https://billing.example.test/callback" };
  const { rowsA, rowsB, v1 } = await parity(null, t => createOAuthClient(t.auth, t.env, headers, body, ADMIN.id), "/clients", body);
  assert.equal(v1.status, 200);
  assert.equal(v1.json.data.client_id, "client-1");
  assert.deepEqual(rowsB, [
    { actor: ADMIN.id, action: "client_create", target: "external:https://billing.example.test", outcome: "attempted" },
    { actor: ADMIN.id, action: "client_create", target: "external:https://billing.example.test", outcome: "succeeded" }
  ]);
  assert.deepEqual(rowsB, rowsA);
});

test("audit parity: RBAC role grant, and a refused RBAC operation", async () => {
  const prepare = async t => {
    t.run("INSERT INTO nathan_applications(id,hostname) VALUES ('demo','demo.example.test')");
    await applyRbacOperation(t.env, { op: "role.upsert", app: "demo", key: "viewer", permissions: [] }, ADMIN.id);
  };
  const body = { op: "grant.create", app: "demo", role: "viewer", principalType: "user", email: "bob@example.test" };
  const { rowsA, rowsB, v1 } = await parity(prepare, t => applyRbacOperation(t.env, body, ADMIN.id), "/rbac", body);
  assert.equal(v1.status, 200);
  assert.equal(v1.json.data.created, true);
  assert.deepEqual(rowsB, [{ actor: ADMIN.id, action: "rbac_grant_create", target: "demo:viewer:user:u-bob", outcome: "succeeded" }]);
  assert.deepEqual(rowsB, rowsA);

  // Refused by the schema: the service never runs (independent review 2026-11-23), and the router
  // records the refused write instead of the service's own "rejected" row.
  const invalid = { op: "grant.create", app: "demo", role: 7, principalType: "robot" };
  const refused = await parity(prepare, t => applyRbacOperation(t.env, invalid, ADMIN.id), "/rbac", invalid);
  assert.ok(refused.directError);
  assert.equal(refused.v1.status, 400);
  assert.equal(refused.v1.json.error.code, "validation_failed");
  assert.deepEqual(refused.rowsA, [{ actor: ADMIN.id, action: "rbac_grant_create", target: "demo", outcome: "rejected" }]);
  assert.deepEqual(refused.rowsB, [{ actor: ADMIN.id, action: "rbac.apply", target: "studio_api_v1", outcome: "refused_schema" }]);
});

test("audit parity: invitation create, and a refused invitation", async () => {
  const body = { op: "invite", email: "new@example.test", days: 3 };
  const { rowsA, rowsB, v1 } = await parity(null, t => applyAdmissionOperation(t.env, body, ADMIN.id), "/admission", body);
  assert.equal(v1.status, 200);
  assert.equal(v1.json.data.email, "new@example.test");
  assert.equal(rowsB.length, 1);
  assert.deepEqual({ ...rowsB[0], target: undefined }, { actor: ADMIN.id, action: "invitation_create", target: undefined, outcome: "succeeded" });
  assert.deepEqual(rowsB.map(r => ({ ...r, target: r.target.length })), rowsA.map(r => ({ ...r, target: r.target.length })));

  const invalid = { op: "invite", email: "new@example.test", days: 90 };
  const refused = await parity(null, t => applyAdmissionOperation(t.env, invalid, ADMIN.id), "/admission", invalid);
  assert.equal(refused.v1.status, 400);
  assert.equal(refused.v1.json.error.code, "validation_failed");
  assert.deepEqual(refused.rowsA, [{ actor: ADMIN.id, action: "invitation_create", target: "invalid", outcome: "rejected" }]);
  assert.deepEqual(refused.rowsB, [{ actor: ADMIN.id, action: "admission.apply", target: "studio_api_v1", outcome: "refused_schema" }]);
});

test("NATH-39: the MCP register schema accepts the scope catalog the service and Studio send", () => {
  const body = { op: "resource.register", identifier: "https://notes.example.com/mcp", app: "notes", name: "Notes", full: null,
    aliases: { "notes:basic": ["notes:read"] },
    scopes: { "notes:read": { label: "Read notes", description: "List notes.", group: "notes" }, "notes:export": { label: "Export", sensitive: true, requires: ["notes:read"] } } };
  assert.equal(schemas.mcpInput.safeParse(body).success, true, "keyed catalog, full: null (Studio's 'no full marker')");
  assert.equal(schemas.mcpInput.safeParse({ ...body, scopes: [{ scope: "notes:read", label: "Read" }] }).success, true, "array form still accepted");
  assert.equal(schemas.mcpInput.safeParse({ ...body, scopes: { "notes:read": { sensitive: "yes" } } }).success, false);
});

test("NATH-39: GET /bootstrap is an admin read returning the administrator's own setup state", () => {
  const route = STUDIO_API_V1_ROUTES.find(r => r.path === "/bootstrap");
  assert.ok(route);
  assert.equal(route.method, "GET");
  assert.equal(route.action, "bootstrap.read");
  assert.equal(route.stepUp ?? "admin-policy", "admin-policy");
});

test("schema-refused input never reaches the service (array redirectUri), and wildcard hosts are refused", async () => {
  const { createOAuthClient } = await import("../src/auth/admin-service.ts");
  const env = { DB: { prepare: () => ({ bind: () => ({ run: async () => ({}) }) }) }, NATHAN_ISSUER: "https://login.example.test" };
  for (const redirectUri of [["https://ok.example.test/a"], "https://*.example.test/cb", "https://a_b.example.test/cb"])
    await assert.rejects(createOAuthClient({ api: {} }, env, new Headers(), { name: "x", kind: "external", redirectUri }, "a"), /redirect/i, String(redirectUri));
});
