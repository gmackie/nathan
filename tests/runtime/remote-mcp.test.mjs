/**
 * NATH-14 in workerd: the built identity Worker is the authorization server for a sample remote MCP
 * server Worker built with nathanMcp() and the MCP TypeScript SDK. An SDK client goes through
 * discovery, dynamic registration, narrowed per-scope consent and a tool call; the remaining tests
 * cover resource binding, catalog and sensitive-scope rules, consent CSRF and ticket replay, refresh
 * narrowing, rotation reuse, grant edits, disconnect and permission removal, and the NATH-15
 * Gatekeeper token profile.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { bundle, migrate, randomKey, base64url, start, COMPAT } from "./helpers.mjs";
import { providerEntryFromDocs, gatekeeper, invalidCredentials } from "./gatekeeper-verifier.mjs";

const PROVIDER = providerEntryFromDocs();
const HOST = new URL(PROVIDER.issuer).host;
const ORIGIN = "https://" + HOST;
const MCP_HOST = "notes.example.com";
const RESOURCE = "https://" + MCP_HOST + "/mcp";
const REDIRECT = "http://127.0.0.1:33418/callback";
const SECRET = randomKey() + randomKey();
const SCOPES = ["notes:export", "notes:read", "notes:share", "notes:write"];
const CATALOG = {
  name: "Notes", full: "notes:full",
  aliases: { "notes:basic": ["notes:read", "notes:write"] },
  scopes: {
    "notes:read": { label: "Read notes", description: "List and read your notes.", group: "notes" },
    "notes:write": { label: "Write notes", description: "Create and edit notes.", group: "notes", requires: ["notes:read"] },
    "notes:share": { label: "Share notes", description: "Share notes with other people.", group: "notes", requires: ["notes:write"] },
    "notes:export": { label: "Export every note", description: "Download all notes at once.", group: "bulk", sensitive: true }
  }
};

let mf, db, auth, authDirect, mcp, mcpHttps, mcpOtherApp, mcpUnpinned;
after(() => mf?.dispose());
const sql = (statement, ...params) => db.prepare(statement).bind(...params).run();
const now = () => new Date().toISOString();
const count = async (statement, ...params) => (await db.prepare(statement).bind(...params).first()).n;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function signedCookie(token) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token))).toString("base64");
  return "__Secure-nathan.session_token=" + encodeURIComponent(token + "." + signature);
}
async function user(id, email, role = "user") {
  await sql('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,1,?,?,?)', id, id, email, now(), now(), role);
}
async function session(userId) {
  const id = "sess-" + crypto.randomUUID(), token = "tok" + randomKey();
  await sql('INSERT INTO "session"("id","expiresAt","token","createdAt","updatedAt","userId") VALUES (?,?,?,?,?,?)',
    id, new Date(Date.now() + 3600_000).toISOString(), token, now(), now(), userId);
  return { id, cookie: await signedCookie(token) };
}
const studioAt = (path, body, who) => auth.fetch(ORIGIN + path, {
  method: "POST", body: JSON.stringify(body),
  headers: { Cookie: who.cookie, Origin: ORIGIN, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin" }
});
const studio = (body, who) => auth.fetch(ORIGIN + "/studio/api/mcp", {
  method: "POST", body: JSON.stringify(body),
  headers: { Cookie: who.cookie, Origin: ORIGIN, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin" }
});
const form = (path, params, headers = {}) => auth.fetch(ORIGIN + path, {
  method: "POST", redirect: "manual", body: params.toString(),
  // A header given as undefined is left out (a request without it).
  headers: Object.fromEntries(Object.entries({ "Content-Type": "application/x-www-form-urlencoded", ...headers }).filter(([, v]) => v !== undefined))
});

let admin, alice, bob, carol, dave;
let ip = 0;
async function registerClient(extra = {}) {
  const response = await auth.fetch(ORIGIN + "/mcp-oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100." + (++ip % 250) },
    body: JSON.stringify({ client_name: "Agent " + ip, redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", ...extra })
  });
  return { status: response.status, body: await response.json() };
}
function authorizeUrl(clientId, { scope = "notes:read notes:write", resource = RESOURCE, verifier, state = "st-" + randomKey() } = {}) {
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const query = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, state,
    code_challenge: challenge, code_challenge_method: "S256", ...(scope === null ? {} : { scope }), ...(resource === null ? {} : { resource }) });
  return ORIGIN + "/mcp-oauth/authorize?" + query;
}
/**
 * The headers a browser sends with a same-origin HTML form POST from `page`. Under Referrer-Policy
 * no-referrer browsers send `Origin: null` even for same-origin form posts (fetch() is unaffected),
 * so the page's own policy decides what the answer carries; tests never hand-set a good Origin.
 */
function browserFormHeaders(page) {
  const policy = page.headers.get("Referrer-Policy");
  return { Origin: policy === "no-referrer" ? "null" : ORIGIN, "Sec-Fetch-Site": "same-origin" };
}
const formHeaders = new Map();
async function consentPage(who, url) {
  const page = await auth.fetch(url, { redirect: "manual", headers: { Cookie: who.cookie } });
  const html = page.status === 200 ? await page.text() : "";
  const ticket = /name="ticket" value="([^"]+)"/.exec(html)?.[1] ?? null;
  if (ticket) formHeaders.set(ticket, browserFormHeaders(page));
  return { page, html, ticket };
}
const answer = (who, ticket, scopes, decision = "allow", headers = {}) => {
  const params = new URLSearchParams({ ticket, decision });
  for (const s of scopes) params.append("scope", s);
  assert.ok(formHeaders.has(ticket), "answer a ticket from a consent page this test loaded");
  return form("/mcp-oauth/authorize", params, { Cookie: who.cookie, ...formHeaders.get(ticket), ...headers });
};
const token = params => form("/mcp-oauth/token", new URLSearchParams(params)).then(async r => ({ status: r.status, body: await r.json() }));
/** The same token request straight to the identity Worker, so it runs concurrently with dispatchFetch requests. */
const tokenAlongside = params => authDirect.fetch(ORIGIN + "/mcp-oauth/token", {
  method: "POST", body: new URLSearchParams(params).toString(), headers: { "Content-Type": "application/x-www-form-urlencoded" }
}).then(async r => ({ status: r.status, body: await r.json() }));
/** Registration, consent with `chosen`, code exchange: a whole manual flow. */
async function connect(who, chosen, { scope = "notes:read notes:write" } = {}) {
  const client = (await registerClient()).body;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const { ticket } = await consentPage(who, authorizeUrl(client.client_id, { scope, verifier }));
  assert.ok(ticket, "consent page");
  const location = new URL((await answer(who, ticket, chosen)).headers.get("Location"));
  const code = location.searchParams.get("code");
  assert.ok(code, location.href);
  const exchanged = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: client.client_id, resource: RESOURCE });
  assert.equal(exchanged.status, 200, JSON.stringify(exchanged.body));
  return { client, tokens: exchanged.body, code, verifier };
}
const call = (worker, path, accessToken) => worker.fetch("https://" + MCP_HOST + path, { headers: accessToken ? { Authorization: "Bearer " + accessToken } : {} });
const grantStatus = (accessToken, resource = RESOURCE) => form("/mcp-oauth/grant", new URLSearchParams({ resource }), { Authorization: "Bearer " + accessToken }).then(r => r.json());

before(async () => {
  const authBindings = {
    NATHAN_ISSUER: ORIGIN, NATHAN_ADMIN_EMAILS: "admin@example.test", NATHAN_SECURITY_PROFILE: "business",
    NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_INSTALL_ACTIVE: "true", NATHAN_MCP_WRITE_ENABLED: "false", NATHAN_REALM_APEX: "",
    ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false", NATHAN_ADMIN_STEPUP_REQUIRED: "true", BETTER_AUTH_SECRET: SECRET, NATHAN_CONFIG_KEY: randomKey()
  };
  const mcpBindings = { NATHAN_ISSUER: PROVIDER.issuer, MCP_RESOURCE: RESOURCE, MCP_CACHE_SECONDS: "1" };
  mf = await start({
    workers: [
      { name: "auth", modules: true, ...COMPAT, scriptPath: bundle("auth"), d1Databases: { DB: "mcp-auth-db" },
        durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } }, bindings: authBindings },
      { name: "mcp", modules: true, ...COMPAT, scriptPath: ".nathan/build-mcp/mcp-server.js",
        serviceBindings: { NATHAN: { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "notes" } } }, bindings: mcpBindings },
      // A binding pinned to another application must learn nothing about this server's tokens.
      { name: "mcp-other-app", modules: true, ...COMPAT, scriptPath: ".nathan/build-mcp/mcp-server.js",
        serviceBindings: { NATHAN: { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "billing" } } }, bindings: mcpBindings },
      { name: "mcp-unpinned", modules: true, ...COMPAT, scriptPath: ".nathan/build-mcp/mcp-server.js",
        serviceBindings: { NATHAN: { name: "auth", entrypoint: "NathanVerifier" } }, bindings: mcpBindings },
      // Same server without a service binding: JWKS and the grant check go over HTTPS to Nathan.
      { name: "mcp-https", modules: true, ...COMPAT, scriptPath: ".nathan/build-mcp/mcp-server.js", bindings: mcpBindings,
        outboundService: async request => {
          const url = new URL(request.url);
          if (url.origin !== ORIGIN) return new Response("unexpected outbound " + url.href, { status: 599 });
          return (await mf.getWorker("auth")).fetch(request);
        } }
    ]
  });
  db = await mf.getD1Database("DB", "auth");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(db, "migrations/" + file);
  // dispatchFetch reaches the first worker (auth); Miniflare's getWorker().fetch refuses Origin headers.
  auth = { fetch: (input, init) => mf.dispatchFetch(input, init) };
  authDirect = await mf.getWorker("auth");
  mcp = await mf.getWorker("mcp");
  mcpHttps = await mf.getWorker("mcp-https");
  mcpOtherApp = await mf.getWorker("mcp-other-app");
  mcpUnpinned = await mf.getWorker("mcp-unpinned");

  await user("admin-1", "admin@example.test", "admin");
  await sql("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf','admin@example.test','admin-1','complete')");
  await sql('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (\'pk1\',\'x\',\'admin-1\',\'cred\',0,\'singleDevice\',0)');
  await sql('INSERT INTO "twoFactor"("id","secret","backupCodes","userId","verified") VALUES (\'tf1\',\'x\',\'x\',\'admin-1\',1)');
  admin = await session("admin-1");
  await sql("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES (?,?,'passkey')", admin.id, "admin-1");
  await user("u-alice", "alice@example.test");
  await user("u-bob", "bob@example.test");
  alice = await session("u-alice");
  bob = await session("u-bob");
  // Carol has her own consent rate-limit budget (30 a minute per user) for the later tests.
  await user("u-carol", "carol@example.test");
  carol = await session("u-carol");
  // Dave too (the concurrency tests).
  await user("u-dave", "dave@example.test");
  dave = await session("u-dave");
  await sql("INSERT INTO nathan_applications(id,hostname,enabled,access_mode) VALUES ('notes','notes.example.com',1,'approved')");
  for (const key of [...SCOPES, "nathan:admin"]) await sql("INSERT INTO nathan_rbac_permissions(app_id,key,description) VALUES ('notes',?,?)", key, "Permission " + key);
  await sql("INSERT INTO nathan_rbac_roles(app_id,key) VALUES ('notes','editor')");
  for (const key of SCOPES) await sql("INSERT INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('notes','editor',?)", key);
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','notes','editor','user','u-alice','test')");
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g3','notes','editor','user','u-carol','test')");
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g4','notes','editor','user','u-dave','test')");
});

test("only an enrolled administrator registers an MCP server, and its catalog cannot imply sensitive scopes", async () => {
  assert.equal((await studio({ op: "resource.register", identifier: RESOURCE, app: "notes", ...CATALOG }, alice)).status, 403);
  const crossOrigin = await auth.fetch(ORIGIN + "/studio/api/mcp", { method: "POST", body: "{}",
    headers: { Cookie: admin.cookie, Origin: "https://evil.example", "Content-Type": "application/json" } });
  assert.equal(crossOrigin.status, 403);
  for (const [body, message] of [
    [{ ...CATALOG, aliases: { "notes:all": ["notes:read", "notes:export"] } }, /sensitive/],
    [{ ...CATALOG, scopes: { ...CATALOG.scopes, "notes:read": { requires: ["notes:export"] } } }, /sensitive/],
    [{ ...CATALOG, scopes: { "nathan:admin": { label: "x" } } }, /reserved/],
    [{ ...CATALOG, full: "notes:read" }, /Full access/]
  ]) {
    const response = await studio({ op: "resource.register", identifier: RESOURCE, app: "notes", ...body }, admin);
    assert.equal(response.status, 409, JSON.stringify(body));
    assert.match((await response.json()).error, message);
  }
  assert.equal((await studio({ op: "resource.register", identifier: ORIGIN + "/mcp", app: "notes", ...CATALOG }, admin)).status, 409, "Nathan's own /mcp is reserved");
  const ok = await studio({ op: "resource.register", identifier: RESOURCE, app: "notes", ...CATALOG }, admin);
  assert.equal(ok.status, 200, await ok.clone().text());
  const registered = await ok.json();
  assert.deepEqual(registered.protectedResourceMetadata, { resource: RESOURCE, authorization_servers: [ORIGIN + "/mcp-oauth"] });
  assert.equal(await count("SELECT count(*) AS n FROM nathan_token_audiences WHERE identifier=? AND app_id='notes'", RESOURCE), 1, "an NATH-15 audience bound to the app");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='mcp_resource_register' AND actor='admin-1'"), 1);
  // The tokens section cannot turn the MCP server into a Better Auth audience (or move its app binding), and vice versa.
  for (const body of [
    { op: "audience.register", identifier: RESOURCE, app: "notes" },
    { op: "audience.register", identifier: RESOURCE },
    { op: "audience.remove", identifier: RESOURCE, confirm: "CONFIRM REMOVE AUDIENCE " + RESOURCE },
    { op: "audience.link", identifier: RESOURCE, clientId: "some-client" }
  ]) {
    const refused = await studioAt("/studio/api/tokens", body, admin);
    assert.equal(refused.status, 409, body.op);
    assert.match((await refused.json()).error, /remote MCP server/, body.op);
  }
  assert.equal(await count('SELECT count(*) AS n FROM "oauthResource" WHERE "identifier"=?', RESOURCE), 0, "never a Better Auth audience");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_token_audiences WHERE identifier=? AND app_id='notes'", RESOURCE), 1, "binding unchanged");
  const plain = "https://plain.example.com/api";
  assert.equal((await studioAt("/studio/api/tokens", { op: "audience.register", identifier: plain }, admin)).status, 200);
  const crossed = await studio({ op: "resource.register", identifier: plain, app: "notes", ...CATALOG }, admin);
  assert.equal(crossed.status, 409);
  assert.match((await crossed.json()).error, /already a Better Auth token audience/);
  const overview = await (await auth.fetch(ORIGIN + "/studio/api/mcp", { headers: { Cookie: admin.cookie } })).json();
  assert.deepEqual(overview.resources[0].scopes.map(s => s.scope), SCOPES, "nathan:* permissions are never scopes");
  assert.equal(overview.resources[0].scopes.find(s => s.scope === "notes:export").sensitive, true);
  const page = await (await auth.fetch(ORIGIN + "/studio", { headers: { Cookie: admin.cookie } })).text();
  const script = [...page.matchAll(/<script nonce="[^"]+">([\s\S]*?)<\/script>/g)].map(m => m[1]).join("\n");
  assert.doesNotThrow(() => new Function(script), "studio script must be valid JavaScript");
  assert.match(script, /\/studio\/api\/mcp/);
});

test("discovery: protected-resource metadata, 401 challenges and authorization-server metadata", async () => {
  for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
    const prm = await (await call(mcp, path)).json();
    assert.equal(prm.resource, RESOURCE);
    assert.deepEqual(prm.authorization_servers, [ORIGIN + "/mcp-oauth"]);
    assert.deepEqual([...prm.scopes_supported].sort(), SCOPES);
  }
  const unauthenticated = await mcp.fetch(RESOURCE, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  assert.equal(unauthenticated.status, 401);
  assert.match(unauthenticated.headers.get("WWW-Authenticate"), /^Bearer resource_metadata="https:\/\/notes\.example\.com\/\.well-known\/oauth-protected-resource\/mcp"/);
  const invalid = await call(mcp, "/whoami", "a.b." + "c".repeat(40));
  assert.equal(invalid.status, 401);
  assert.match(invalid.headers.get("WWW-Authenticate"), /error="invalid_token"/);
  const meta = await (await auth.fetch(ORIGIN + "/.well-known/oauth-authorization-server/mcp-oauth")).json();
  assert.equal(meta.issuer, ORIGIN + "/mcp-oauth");
  assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(meta.token_endpoint_auth_methods_supported, ["none"]);
  assert.equal(meta.registration_endpoint, ORIGIN + "/mcp-oauth/register");
  assert.equal(meta.authorization_response_iss_parameter_supported, true);
  // Better Auth's own metadata for /api/auth is untouched.
  const betterAuth = await (await auth.fetch(ORIGIN + "/.well-known/oauth-authorization-server/api/auth")).json();
  assert.equal(betterAuth.issuer, ORIGIN + "/api/auth");
});

test("an MCP SDK client discovers, registers, gets narrowed consent and calls a tool", async () => {
  const provider = {
    redirectUrl: REDIRECT,
    clientMetadata: { client_name: "SDK agent", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" },
    clientInformation() { return this.client; }, saveClientInformation(c) { this.client = c; },
    tokens() { return this.saved; }, saveTokens(t) { this.saved = t; },
    redirectToAuthorization(url) { this.authorizationUrl = url; },
    saveCodeVerifier(v) { this.verifier = v; }, codeVerifier() { return this.verifier; }
  };
  const route = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const worker = url.host === MCP_HOST ? mcp : url.host === HOST ? auth : null;
    if (!worker) throw Error("unexpected fetch " + url.href);
    if (input instanceof Request) return worker.fetch(url.href, { method: input.method, headers: input.headers, body: input.method === "GET" ? undefined : await input.text() });
    return worker.fetch(url.href, { ...init, body: init.body === undefined ? undefined : String(init.body) });
  };
  const transport = () => new StreamableHTTPClientTransport(new URL(RESOURCE), { authProvider: provider, fetch: route });

  const first = transport();
  await assert.rejects(new Client({ name: "nathan-test", version: "1.0.0" }).connect(first), UnauthorizedError);
  assert.match(provider.client.client_id, /^nmcp_/, "registered dynamically");
  const authorization = new URL(provider.authorizationUrl);
  assert.equal(authorization.origin + authorization.pathname, ORIGIN + "/mcp-oauth/authorize");
  assert.equal(authorization.searchParams.get("resource"), RESOURCE);
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.deepEqual(authorization.searchParams.get("scope").split(" ").sort(), SCOPES, "the client asks for the challenge's scopes");

  // Alice narrows the request to reading notes only.
  const { html, ticket, page } = await consentPage(alice, authorization.href);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("Content-Security-Policy"), /script-src 'none'/);
  assert.match(page.headers.get("Content-Security-Policy"), /form-action 'self' http:\/\/127\.0\.0\.1:33418;/);
  // no-referrer would make browsers send Origin: null with the form post, which Nathan refuses.
  assert.equal(page.headers.get("Referrer-Policy"), "same-origin");
  assert.doesNotMatch(html, /<script/);
  for (const s of SCOPES) assert.match(html, new RegExp('value="' + s + '" checked'), s + " preselected from the request");
  const approved = await answer(alice, ticket, ["notes:read"]);
  assert.equal(approved.status, 303);
  const callback = new URL(approved.headers.get("Location"));
  assert.equal(callback.origin + callback.pathname, REDIRECT);
  assert.equal(callback.searchParams.get("iss"), ORIGIN + "/mcp-oauth");
  assert.equal(callback.searchParams.get("state"), authorization.searchParams.get("state"));

  await first.finishAuth(callback.searchParams.get("code"));
  assert.equal(provider.saved.scope, "notes:read", "the token response reports what was granted");
  assert.equal(provider.saved.token_type.toLowerCase(), "bearer");
  assert.ok(provider.saved.expires_in <= 900 && provider.saved.refresh_token);

  const client = new Client({ name: "nathan-test", version: "1.0.0" });
  await client.connect(transport());
  const tools = (await client.listTools()).tools.map(t => t.name).sort();
  assert.deepEqual(tools, ["notes_list", "whoami"], "only tools the granted scopes allow");
  const result = await client.callTool({ name: "notes_list", arguments: {} });
  assert.deepEqual(JSON.parse(result.content[0].text).map(n => n.id), ["n1", "n2"]);
  await client.close();

  // The access token is a NATH-15 token: Gatekeeper's own resolver accepts it as an agent acting for Alice.
  const principal = await gatekeeper(mf, { ...PROVIDER, audience: RESOURCE })(provider.saved.access_token);
  assert.equal(principal.kind, "agent");
  assert.equal(principal.subject, "u-alice");
  assert.equal(principal.id, "principal:" + encodeURIComponent(PROVIDER.issuer) + ":sub:u-alice", "the same principal as Alice's own tokens");
  assert.equal(principal.authentication.clientId, provider.client.client_id);
  assert.deepEqual(principal.authentication.scopes, ["notes:read"]);
  assert.equal(principal.mfa, false);
  const [header, claims] = provider.saved.access_token.split(".").slice(0, 2).map(p => JSON.parse(Buffer.from(p, "base64url")));
  assert.equal(header.typ, "at+jwt");
  assert.equal(claims.iss, PROVIDER.issuer);
  assert.equal(claims.principal_kind, "agent");
  assert.ok(claims.exp - claims.iat <= 900);
  assert.deepEqual(claims.roles, ["editor"]);
  await assert.rejects(gatekeeper(mf, PROVIDER)(provider.saved.access_token), invalidCredentials, "not valid for another audience");
  await assert.rejects(gatekeeper(mf, { ...PROVIDER, audience: RESOURCE }, { now: () => Date.now() + 301_000 })(provider.saved.access_token), invalidCredentials, "expired after 300 s");
});

test("resource is mandatory and must name the registered MCP server on authorize, token and refresh", async () => {
  const client = (await registerClient()).body;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  for (const resource of [null, "https://other.example.com/mcp", ORIGIN + "/mcp"]) {
    const response = await auth.fetch(authorizeUrl(client.client_id, { resource, verifier }), { redirect: "manual", headers: { Cookie: alice.cookie } });
    assert.equal(response.status, 302, String(resource));
    assert.equal(new URL(response.headers.get("Location")).searchParams.get("error"), "invalid_target", String(resource));
  }
  const { client: c2, tokens, code, verifier: v2 } = await connect(alice, ["notes:read"]);
  for (const resource of [undefined, "https://other.example.com/mcp"]) {
    const refreshed = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: c2.client_id, ...(resource ? { resource } : {}) });
    assert.equal(refreshed.status, 400);
    assert.equal(refreshed.body.error, "invalid_target");
  }
  const noResource = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: v2, client_id: c2.client_id });
  assert.equal(noResource.body.error, "invalid_target");
  assert.equal((await grantStatus(tokens.access_token, "https://other.example.com/mcp")).active, false);
  assert.equal((await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: c2.client_id, resource: RESOURCE })).status, 200,
    "rejected attempts did not consume the refresh token");
});

test("scopes outside the catalog, reserved scopes and non-public clients are refused", async () => {
  const client = (await registerClient()).body;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  for (const scope of ["notes:delete", "notes:read openid", "nathan:admin", "nathan:read"]) {
    const response = await auth.fetch(authorizeUrl(client.client_id, { scope, verifier }), { redirect: "manual", headers: { Cookie: alice.cookie } });
    assert.equal(new URL(response.headers.get("Location")).searchParams.get("error"), "invalid_scope", scope);
  }
  for (const [extra, error] of [
    [{ scope: "openid notes:read" }, "invalid_client_metadata"], [{ scope: "nathan:admin" }, "invalid_client_metadata"],
    [{ token_endpoint_auth_method: "client_secret_basic" }, "invalid_client_metadata"],
    [{ redirect_uris: ["http://agent.example.com/cb"] }, "invalid_redirect_uri"],
    [{ grant_types: ["client_credentials"] }, "invalid_client_metadata"]
  ]) {
    const registered = await registerClient(extra);
    assert.equal(registered.status, 400, JSON.stringify(extra));
    assert.equal(registered.body.error, error);
  }
  assert.equal((await registerClient({ scope: "notes:basic offline_access" })).status, 201);
  const unregistered = await auth.fetch(authorizeUrl(client.client_id, { verifier }).replace(encodeURIComponent(REDIRECT), encodeURIComponent("http://127.0.0.1:1/other")), { headers: { Cookie: alice.cookie }, redirect: "manual" });
  assert.equal(unregistered.status, 400, "an unregistered redirect URI is never redirected to");
  // Registration is rate-limited per address.
  let limited = 0;
  for (let i = 0; i < 22; i++) {
    const response = await auth.fetch(ORIGIN + "/mcp-oauth/register", { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.7" },
      body: JSON.stringify({ redirect_uris: [REDIRECT] }) });
    if (response.status === 429) limited++;
  }
  assert.ok(limited >= 2, "more than 20 registrations a minute are refused");
});

test("sensitive scopes are never granted through an alias or Full access, and need their own tick", async () => {
  const client = (await registerClient()).body;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const { html, ticket } = await consentPage(alice, authorizeUrl(client.client_id, { scope: "notes:full notes:basic", verifier }));
  assert.match(html, /value="notes:full" checked/);
  assert.match(html, /value="notes:export">/, "offered, but not preselected");
  const callback = new URL((await answer(alice, ticket, ["notes:full"])).headers.get("Location"));
  const exchanged = await token({ grant_type: "authorization_code", code: callback.searchParams.get("code"), redirect_uri: REDIRECT, code_verifier: verifier, client_id: client.client_id, resource: RESOURCE });
  assert.equal(exchanged.body.scope, "notes:read notes:share notes:write");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_mcp_grants WHERE scope='notes:full'"), 1, "stored as the marker");
  const explicit = await connect(alice, ["notes:full", "notes:export"], { scope: "notes:export" });
  assert.equal(explicit.tokens.scope, "notes:export notes:read notes:share notes:write");
  // Bob holds no permission on the app: nothing to offer, and the client learns access_denied.
  const denied = await auth.fetch(authorizeUrl(client.client_id, { verifier }), { redirect: "manual", headers: { Cookie: bob.cookie } });
  assert.equal(new URL(denied.headers.get("Location")).searchParams.get("error"), "access_denied");
});

test("consent CSRF and ticket replay are rejected; an empty selection keeps the ticket", async () => {
  const client = (await registerClient()).body;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const { ticket } = await consentPage(alice, authorizeUrl(client.client_id, { verifier }));
  assert.equal((await answer(alice, ticket, ["notes:read"], "allow", { Origin: "https://evil.example" })).status, 403);
  assert.equal((await answer(alice, ticket, ["notes:read"], "allow", { "Sec-Fetch-Site": "cross-site" })).status, 403);
  assert.equal((await answer(alice, ticket, ["notes:read"], "allow", { Origin: "null" })).status, 403, "an opaque origin is never accepted");
  assert.equal((await answer(alice, ticket, ["notes:read"], "allow", { Origin: undefined })).status, 403, "nor a missing one");
  assert.equal((await answer(bob, ticket, ["notes:read"])).status, 400, "the ticket is bound to Alice's session");
  const otherSession = await session("u-alice");
  assert.equal((await answer(otherSession, ticket, ["notes:read"])).status, 400, "and to this browser session");
  const empty = await answer(alice, ticket, []);
  assert.equal(empty.status, 400);
  assert.match(await empty.text(), /Select at least one permission/);
  const invalid = await answer(alice, ticket, ["notes:read", "nathan:admin"]);
  assert.equal(invalid.status, 400);
  assert.match(await invalid.text(), /value="[^"]+"/, "re-rendered with the same ticket");
  const ok = await answer(alice, ticket, ["notes:write"]);
  assert.equal(ok.status, 303, "the ticket survived the rejected and empty submissions");
  const replay = await answer(alice, ticket, ["notes:write"]);
  assert.equal(replay.status, 400);
  assert.match(await replay.text(), /expired, was already answered/);
  const code = new URL(ok.headers.get("Location")).searchParams.get("code");
  const exchanged = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: client.client_id, resource: RESOURCE });
  assert.equal(exchanged.body.scope, "notes:read notes:write", "notes:write brought notes:read");
  // Deny still answers the client.
  const second = await consentPage(alice, authorizeUrl(client.client_id, { verifier }));
  const denied = new URL((await answer(alice, second.ticket, [], "deny")).headers.get("Location"));
  assert.equal(denied.searchParams.get("error"), "access_denied");
});

test("codes are single-use with S256 PKCE; a replayed code revokes its grant", async () => {
  const client = (await registerClient()).body;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const { ticket } = await consentPage(alice, authorizeUrl(client.client_id, { verifier }));
  const code = new URL((await answer(alice, ticket, ["notes:read"])).headers.get("Location")).searchParams.get("code");
  const base = { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: client.client_id, resource: RESOURCE };
  assert.equal((await token({ ...base, code_verifier: base64url(crypto.getRandomValues(new Uint8Array(32))) })).body.error, "invalid_grant");
  const first = await token({ ...base, code_verifier: verifier });
  assert.equal(first.status, 200, "a wrong verifier does not burn the code");
  assert.equal((await grantStatus(first.body.access_token)).active, true);
  assert.equal((await token({ ...base, code_verifier: verifier })).body.error, "invalid_grant");
  assert.equal((await grantStatus(first.body.access_token)).active, false, "the replay revoked the grant");
});

test("refresh narrows to what the grant holds; reuse of a rotated refresh token revokes the grant", async () => {
  const { client, tokens } = await connect(alice, ["notes:write"]);
  const refresh = (refresh_token, scope) => token({ grant_type: "refresh_token", refresh_token, client_id: client.client_id, resource: RESOURCE, ...(scope ? { scope } : {}) });
  const narrowed = await refresh(tokens.refresh_token, "notes:read");
  assert.equal(narrowed.status, 200);
  assert.equal(narrowed.body.scope, "notes:read");
  const mixed = await refresh(narrowed.body.refresh_token, "notes:read notes:share");
  assert.equal(mixed.body.scope, "notes:read", "scopes the grant does not hold are dropped");
  const nothing = await refresh(mixed.body.refresh_token, "notes:share");
  assert.equal(nothing.body.error, "invalid_scope", "invalid_scope only when nothing remains");
  assert.equal((await refresh(mixed.body.refresh_token, "notes:nope")).body.error, "invalid_scope");
  const whole = await refresh(mixed.body.refresh_token);
  assert.equal(whole.body.scope, "notes:read notes:write", "without scope: the whole grant");
  // Reuse detection: the consumed token comes back.
  const reused = await refresh(tokens.refresh_token);
  assert.equal(reused.body.error, "invalid_grant");
  assert.equal((await refresh(whole.body.refresh_token)).body.error, "invalid_grant", "the whole grant is gone");
  assert.equal((await grantStatus(whole.body.access_token)).active, false);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='mcp_grant_revoke' AND target LIKE '%reason=refresh_reuse'"), 1);
});

test("grant edits and disconnect reach the MCP server within 60 seconds", async () => {
  const { tokens } = await connect(alice, ["notes:write"]);
  for (const worker of [mcpOtherApp, mcpUnpinned])
    assert.equal((await call(worker, "/whoami", tokens.access_token)).status, 401, "the binding is app-scoped like every NathanVerifier call");
  for (const worker of [mcp, mcpHttps]) {
    const before = await (await call(worker, "/whoami", tokens.access_token)).json();
    assert.deepEqual(before.scopes, ["notes:read", "notes:write"]);
    assert.equal(before.canWrite, true);
  }
  const loaded = await auth.fetch(ORIGIN + "/connections", { headers: { Cookie: alice.cookie } });
  assert.equal(loaded.headers.get("Referrer-Policy"), "same-origin", "so browsers send Nathan's Origin with Save and Disconnect");
  const page = await loaded.text();
  const grantId = (await grantStatus(tokens.access_token)).grantId;
  assert.match(page, new RegExp('name="grant" value="' + grantId + '"'));
  const csrf = /name="csrf" value="([^"]+)"/.exec(page)[1];
  const edit = (who, params, headers = {}) => form("/connections", new URLSearchParams(params), { Cookie: who.cookie, ...browserFormHeaders(loaded), ...headers });
  assert.equal((await edit(alice, { csrf: "x".repeat(43), grant: grantId, action: "save", scope: "notes:read" })).status, 403, "CSRF token");
  assert.equal((await edit(alice, { csrf, grant: grantId, action: "save", scope: "notes:read" }, { Origin: "https://evil.example" })).status, 403);
  assert.equal((await edit(alice, { csrf, grant: grantId, action: "save", scope: "notes:read" }, { Origin: "null" })).status, 403, "an opaque origin is never accepted");
  // Bob has a connection of his own, so his page carries his CSRF token.
  await sql("INSERT INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g-bob','notes','editor','user','u-bob','test')");
  await connect(bob, ["notes:read"]);
  await sql("DELETE FROM nathan_rbac_grants WHERE id='g-bob'");
  const bobPage = await (await auth.fetch(ORIGIN + "/connections", { headers: { Cookie: bob.cookie } })).text();
  const bobCsrf = /name="csrf" value="([^"]+)"/.exec(bobPage)[1];
  assert.match(bobPage, /Usable now: nothing/, "Bob lost his permissions, so his connection can do nothing");
  assert.doesNotMatch(bobPage, new RegExp(grantId));
  assert.equal((await edit(bob, { csrf: bobCsrf, grant: grantId, action: "disconnect" })).status, 404, "another user's connection is not found");
  const saved = await edit(alice, { csrf, grant: grantId, action: "save", scope: "notes:read" });
  assert.equal(saved.status, 303);
  assert.equal((await grantStatus(tokens.access_token)).scope, "notes:read", "Nathan answers with the edit at once");
  await sleep(1200); // the sample server caches checks for 1 s (the SDK never caches longer than 30 s)
  for (const worker of [mcp, mcpHttps]) {
    assert.deepEqual((await (await call(worker, "/whoami", tokens.access_token)).json()).scopes, ["notes:read"]);
    const write = await call(worker, "/notes/write", tokens.access_token);
    assert.equal(write.status, 403);
    assert.match(write.headers.get("WWW-Authenticate"), /error="insufficient_scope", scope="notes:write"/);
  }
  assert.equal((await edit(alice, { csrf, grant: grantId, action: "disconnect" })).status, 303);
  await sleep(1200);
  for (const worker of [mcp, mcpHttps]) assert.equal((await call(worker, "/whoami", tokens.access_token)).status, 401);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE actor='u-alice' AND action IN ('mcp_grant_update','mcp_grant_revoke')"), 2);
});

test("removing the user's permission removes the scope from tokens and requests", async () => {
  const { client, tokens } = await connect(alice, ["notes:write"]);
  await sql("DELETE FROM nathan_rbac_role_permissions WHERE app_id='notes' AND role_key='editor' AND permission_key='notes:write'");
  try {
    assert.equal((await grantStatus(tokens.access_token)).scope, "notes:read");
    await sleep(1200);
    assert.equal((await (await call(mcp, "/whoami", tokens.access_token)).json()).canWrite, false);
    const refreshed = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id, resource: RESOURCE });
    assert.equal(refreshed.body.scope, "notes:read");
    await sql("DELETE FROM nathan_rbac_grants WHERE id='g1'");
    assert.equal((await grantStatus(refreshed.body.access_token)).active, false, "no access to the app, no scopes");
    const none = await token({ grant_type: "refresh_token", refresh_token: refreshed.body.refresh_token, client_id: client.client_id, resource: RESOURCE });
    assert.equal(none.status, 400);
    assert.equal(none.body.error, "invalid_scope", "nothing usable now is a scope problem, not a dead grant");
  } finally {
    await sql("INSERT OR IGNORE INTO nathan_rbac_role_permissions(app_id,role_key,permission_key) VALUES ('notes','editor','notes:write')");
    await sql("INSERT OR IGNORE INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g1','notes','editor','user','u-alice','test')");
  }
});

test("a refresh with nothing usable now does not consume the refresh token", async () => {
  const { client, tokens } = await connect(dave, ["notes:read"]);
  const grantId = (await grantStatus(tokens.access_token)).grantId;
  const refresh = () => token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id, resource: RESOURCE });
  await sql("DELETE FROM nathan_rbac_grants WHERE id='g4'");
  try {
    const refused = await refresh();
    assert.equal(refused.status, 400);
    assert.equal(refused.body.error, "invalid_scope");
  } finally {
    await sql("INSERT OR IGNORE INTO nathan_rbac_grants(id,app_id,role_key,principal_type,principal_id,created_by) VALUES ('g4','notes','editor','user','u-dave','test')");
  }
  const again = await refresh();
  assert.equal(again.status, 200, "the same refresh token works once access is back: " + JSON.stringify(again.body));
  assert.equal((await grantStatus(again.body.access_token)).active, true, "and the grant was not revoked as a reuse");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='mcp_grant_revoke' AND instr(target, ?) = 1", grantId + " "), 0);
});

test("banning the user stops their MCP connections at the next check; the refresh token survives a temporary ban", async () => {
  const { client, tokens } = await connect(carol, ["notes:read"]);
  const grantId = (await grantStatus(tokens.access_token)).grantId;
  const refresh = () => token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: client.client_id, resource: RESOURCE });
  await sql('UPDATE "user" SET "banned"=1 WHERE "id"=\'u-carol\'');
  try {
    assert.equal((await grantStatus(tokens.access_token)).active, false);
    const refused = await refresh();
    assert.equal(refused.status, 503, "a ban is temporary: retry later, keep the refresh token");
    assert.equal(refused.body.error, "temporarily_unavailable");
  } finally {
    await sql('UPDATE "user" SET "banned"=0 WHERE "id"=\'u-carol\'');
  }
  assert.equal((await grantStatus(tokens.access_token)).active, true, "the grant itself survives a temporary ban");
  const lifted = await refresh();
  assert.equal(lifted.status, 200, "the refresh token refused during the ban still works: " + JSON.stringify(lifted.body));
  assert.equal((await grantStatus(lifted.body.access_token)).active, true, "no refresh_reuse revocation");
  assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='mcp_grant_revoke' AND instr(target, ?) = 1", grantId + " "), 0);
});

test("concurrent use of one code or one refresh token: exactly one succeeds and the grant is revoked", async () => {
  for (let round = 0; round < 3; round++) {
    const client = (await registerClient()).body;
    const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const { ticket } = await consentPage(dave, authorizeUrl(client.client_id, { verifier }));
    const code = new URL((await answer(dave, ticket, ["notes:read"])).headers.get("Location")).searchParams.get("code");
    const exchange = { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: client.client_id, resource: RESOURCE };
    const exchanged = await Promise.all([tokenAlongside(exchange), tokenAlongside(exchange), token(exchange)]);
    const won = exchanged.filter(r => r.status === 200);
    assert.equal(won.length, 1, "exactly one exchange succeeds: " + JSON.stringify(exchanged.map(r => r.body.error ?? "ok")));
    for (const lost of exchanged.filter(r => r.status !== 200)) assert.equal(lost.body.error, "invalid_grant");
    assert.equal((await grantStatus(won[0].body.access_token)).active, false, "the losing exchange revoked the grant");
    assert.equal((await token({ grant_type: "refresh_token", refresh_token: won[0].body.refresh_token, client_id: client.client_id, resource: RESOURCE })).body.error, "invalid_grant");
    assert.equal(await count("SELECT count(*) AS n FROM nathan_mcp_grants WHERE client_id=?", client.client_id), 0);

    const { client: other, tokens } = await connect(dave, ["notes:read"]);
    const refresh = { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: other.client_id, resource: RESOURCE };
    const refreshed = await Promise.all([tokenAlongside(refresh), tokenAlongside(refresh), token(refresh)]);
    const fresh = refreshed.filter(r => r.status === 200);
    assert.equal(fresh.length, 1, "exactly one refresh succeeds: " + JSON.stringify(refreshed.map(r => r.body.error ?? "ok")));
    for (const lost of refreshed.filter(r => r.status !== 200)) assert.equal(lost.body.error, "invalid_grant");
    assert.equal((await grantStatus(fresh[0].body.access_token)).active, false, "the losing refresh revoked the grant");
    assert.equal((await token({ ...refresh, refresh_token: fresh[0].body.refresh_token })).body.error, "invalid_grant");
    assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='mcp_grant_revoke' AND instr(target, ?) > 0 AND target LIKE '%reason=refresh_reuse'", " client=" + other.client_id + " "), 1);
  }
});

test("clients revoke grants (RFC 7009), administrators revoke and disable servers", async () => {
  const { client, tokens } = await connect(carol, ["notes:read"]);
  const revoked = await form("/mcp-oauth/revoke", new URLSearchParams({ client_id: client.client_id, token: tokens.access_token }));
  assert.equal(revoked.status, 200);
  assert.equal((await grantStatus(tokens.access_token)).active, false);
  assert.equal((await form("/mcp-oauth/revoke", new URLSearchParams({ client_id: client.client_id, token: "unknown" }))).status, 200);
  const second = await connect(carol, ["notes:read"]);
  const grantId = (await grantStatus(second.tokens.access_token)).grantId;
  assert.equal((await studio({ op: "grant.revoke", grantId }, admin)).status, 409, "explicit confirmation");
  assert.equal((await studio({ op: "grant.revoke", grantId, confirm: "CONFIRM REVOKE " + grantId }, admin)).status, 200);
  assert.equal((await grantStatus(second.tokens.access_token)).active, false);
  const third = await connect(carol, ["notes:read"]);
  assert.equal((await studio({ op: "resource.status", identifier: RESOURCE, enabled: false, confirm: "CONFIRM DISABLE MCP " + RESOURCE }, admin)).status, 200);
  assert.equal((await grantStatus(third.tokens.access_token)).active, false, "a disabled server accepts no tokens");
  assert.equal((await token({ grant_type: "refresh_token", refresh_token: third.tokens.refresh_token, client_id: third.client.client_id, resource: RESOURCE })).body.error, "invalid_target");
  assert.equal((await studio({ op: "resource.status", identifier: RESOURCE, enabled: true, confirm: "CONFIRM ENABLE MCP " + RESOURCE }, admin)).status, 200);
  assert.equal((await grantStatus(third.tokens.access_token)).active, true);
});

test("signing in during authorization returns to the consent page", async () => {
  const client = (await registerClient()).body;
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const url = authorizeUrl(client.client_id, { verifier });
  const signedOut = await auth.fetch(url, { redirect: "manual" });
  assert.equal(signedOut.status, 302);
  assert.equal(signedOut.headers.get("Location"), ORIGIN + "/sign-in");
  const cookie = signedOut.headers.getSetCookie().find(c => c.startsWith("__Host-nathan-mcp-return="));
  assert.match(cookie, /Secure; HttpOnly; SameSite=Lax/);
  const back = await auth.fetch(ORIGIN + "/", { redirect: "manual", headers: { Cookie: alice.cookie + "; " + cookie.split(";")[0] } });
  assert.equal(back.status, 302);
  assert.equal(back.headers.get("Location"), url);
  const forged = "__Host-nathan-mcp-return=" + Buffer.from("https://evil.example/").toString("base64url");
  const safe = await auth.fetch(ORIGIN + "/", { redirect: "manual", headers: { Cookie: alice.cookie + "; " + forged } });
  assert.equal(safe.headers.get("Location"), ORIGIN + "/sign-in", "never an open redirect");
});

test("registration: only successful registrations count globally, unused clients are capped and pruned after a day", async () => {
  const register = (body, address) => auth.fetch(ORIGIN + "/mcp-oauth/register", {
    method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": address }, body: JSON.stringify(body)
  }).then(async r => ({ status: r.status, headers: r.headers, body: await r.json() }));
  const globalCount = async () => (await db.prepare("SELECT coalesce(max(request_count),0) AS n FROM nathan_mcp_limits WHERE id LIKE 'mcp-oauth:register-all:%' AND expires_at>unixepoch()").first()).n;
  // Stay inside one fixed one-minute window.
  if (Date.now() % 60000 > 50000) await sleep(60000 - (Date.now() % 60000) + 50);

  // Unknown fields are dropped; the stored row holds only bounded, known metadata.
  const extra = await register({ client_name: "Bounded", redirect_uris: [REDIRECT], jwks_uri: "https://agent.example/jwks", software_statement: "x".repeat(3000) }, "192.0.2.1");
  assert.equal(extra.status, 201, JSON.stringify(extra.body));
  assert.equal(extra.body.jwks_uri, undefined);
  const row = await db.prepare("SELECT * FROM nathan_mcp_clients WHERE client_id=?").bind(extra.body.client_id).first();
  assert.deepEqual(Object.keys(row).sort(), ["client_id", "client_name", "created_at", "expires_at", "first_grant_at", "redirect_uris", "scope"]);
  assert.equal(row.first_grant_at, null);
  assert.ok(JSON.stringify(row).length < 1024);

  // Invalid attempts use up only their own address's budget, never the global one.
  const before = await globalCount();
  assert.ok(before >= 1);
  const statuses = [];
  for (let i = 0; i < 25; i++) statuses.push((await register({ redirect_uris: ["http://not-loopback.example/cb"] }, "192.0.2.10")).status);
  assert.deepEqual([...new Set(statuses)], [400, 429], "invalid until the address's 20 a minute run out");
  assert.equal(await globalCount(), before, "invalid registrations do not count toward the global limit");
  // The per-address limit still applies to every attempt, valid or not.
  assert.equal((await register({ redirect_uris: [REDIRECT] }, "192.0.2.10")).status, 429);

  // One address may store at most MCP_DAILY_REGISTRATIONS_PER_ADDRESS (50) registrations a day, so a
  // single address cannot keep the unused-client pool full by itself.
  assert.equal((await register({ redirect_uris: [REDIRECT] }, "192.0.2.50")).status, 201);
  await sql("UPDATE nathan_mcp_limits SET request_count=50 WHERE id LIKE 'mcp-oauth:register-day:%' AND expires_at>unixepoch()");
  const daily = await register({ redirect_uris: [REDIRECT] }, "192.0.2.50");
  assert.equal(daily.status, 429, "the address's daily registrations are used up: " + JSON.stringify(daily.body));
  assert.equal((await register({ redirect_uris: [REDIRECT] }, "192.0.2.51")).status, 201, "other addresses are unaffected");
  await sql("UPDATE nathan_mcp_limits SET request_count=0 WHERE id LIKE 'mcp-oauth:register-day:%'");

  // The global limit on successful registrations (300 a minute).
  await sql("UPDATE nathan_mcp_limits SET request_count=300 WHERE id LIKE 'mcp-oauth:register-all:%' AND expires_at>unixepoch()");
  const overall = await register({ redirect_uris: [REDIRECT] }, "192.0.2.20");
  assert.equal(overall.status, 429, JSON.stringify(overall.body));
  await sql("UPDATE nathan_mcp_limits SET request_count=0 WHERE id LIKE 'mcp-oauth:register-all:%'");

  // A client that has obtained a grant is no longer unused.
  const { client: used } = await connect(dave, ["notes:read"]);
  assert.ok((await db.prepare("SELECT first_grant_at FROM nathan_mcp_clients WHERE client_id=?").bind(used.client_id).first()).first_grant_at);

  // Clients that never obtained a grant are pruned a day after registration, at the next registration.
  const day = 24 * 3600;
  await sql("INSERT INTO nathan_mcp_clients(client_id,client_name,redirect_uris,created_at,expires_at) VALUES ('nmcp_stale_unused_aaaaaaaaaaaaaaaaaaaa','Stale','[]',unixepoch()-?,unixepoch()+?)", day + 60, 100 * day);
  await sql("INSERT INTO nathan_mcp_clients(client_id,client_name,redirect_uris,created_at,expires_at,first_grant_at) VALUES ('nmcp_stale_used_aaaaaaaaaaaaaaaaaaaaaa','Used','[]',unixepoch()-?,unixepoch()+?,unixepoch()-?)", day + 60, 100 * day, day);
  await sql("INSERT INTO nathan_mcp_clients(client_id,client_name,redirect_uris,created_at,expires_at) VALUES ('nmcp_fresh_unused_aaaaaaaaaaaaaaaaaaaa','Fresh','[]',unixepoch()-?,unixepoch()+?)", day - 600, 100 * day);
  assert.equal((await register({ redirect_uris: [REDIRECT] }, "192.0.2.30")).status, 201);
  const left = (await db.prepare("SELECT client_id FROM nathan_mcp_clients WHERE client_id LIKE 'nmcp_stale%' OR client_id LIKE 'nmcp_fresh%' ORDER BY client_id").all()).results.map(r => r.client_id);
  assert.deepEqual(left, ["nmcp_fresh_unused_aaaaaaaaaaaaaaaaaaaa", "nmcp_stale_used_aaaaaaaaaaaaaaaaaaaaaa"]);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_mcp_clients WHERE client_id=?", used.client_id), 1);

  // The scheduled handler prunes them too.
  await sql("UPDATE nathan_mcp_clients SET created_at=unixepoch()-? WHERE client_id='nmcp_fresh_unused_aaaaaaaaaaaaaaaaaaaa'", day + 60);
  await authDirect.scheduled({ cron: "0 * * * *" });
  assert.equal(await count("SELECT count(*) AS n FROM nathan_mcp_clients WHERE client_id='nmcp_fresh_unused_aaaaaaaaaaaaaaaaaaaa'"), 0);
  assert.equal(await count("SELECT count(*) AS n FROM nathan_mcp_clients WHERE client_id='nmcp_stale_used_aaaaaaaaaaaaaaaaaaaaaa'"), 1);

  // At most MCP_UNUSED_CLIENT_LIMIT (1000) unused clients exist at once: then registration answers 503, audited once per window.
  const unused = await count("SELECT count(*) AS n FROM nathan_mcp_clients WHERE first_grant_at IS NULL");
  for (let i = unused; i < 1000; i += 100) {
    const values = [];
    for (let j = i; j < Math.min(i + 100, 1000); j++) values.push("('nmcp_fill_" + String(j).padStart(24, "0") + "','Fill','[]',unixepoch(),unixepoch()+86400)");
    await db.prepare("INSERT INTO nathan_mcp_clients(client_id,client_name,redirect_uris,created_at,expires_at) VALUES " + values.join(",")).run();
  }
  try {
    for (const address of ["192.0.2.40", "192.0.2.41"]) {
      const full = await register({ redirect_uris: [REDIRECT] }, address);
      assert.equal(full.status, 503, JSON.stringify(full.body));
      assert.equal(full.body.error, "temporarily_unavailable");
      assert.ok(Number(full.headers.get("Retry-After")) > 0);
    }
    assert.equal(await count("SELECT count(*) AS n FROM nathan_security_audit WHERE action='mcp_client_register' AND outcome='refused'"), 1, "audited once per window");
    assert.equal(await count("SELECT count(*) AS n FROM nathan_mcp_clients WHERE first_grant_at IS NULL"), 1000);
    // Registered clients keep working: the cap only stops new registrations.
    const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    assert.ok((await consentPage(dave, authorizeUrl(used.client_id, { verifier }))).ticket, "an existing client still gets a consent page");
  } finally {
    await sql("DELETE FROM nathan_mcp_clients WHERE client_id LIKE 'nmcp_fill_%'");
  }
  assert.equal((await register({ redirect_uris: [REDIRECT] }, "192.0.2.42")).status, 201, "registration resumes below the cap");
});
