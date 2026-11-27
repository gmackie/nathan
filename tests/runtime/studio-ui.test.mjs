/**
 * NATH-39: Identity Studio as a Kumo SPA in the built identity Worker. The shell is server-rendered
 * with renderPage (one island, SRI, nonce'd scripts, no style=), only verified administrators who
 * pass mayAdminister get it, and the SPA's API (/studio/api/v1) and the raw admin boundary behave
 * as before.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { authWorker, randomKey, enrollAdmin, insertSession, studioShell, studioPost } from "./helpers.mjs";

const HOST = "login.example.test";
const ORIGIN = "https://" + HOST;
const SECRET = randomKey() + randomKey();
let mf, db, admin, member, unstepped;
after(() => mf?.dispose());

const fetcher = { fetch: (url, init) => mf.dispatchFetch(url, init) };
const get = (path, cookie) => mf.dispatchFetch(ORIGIN + path, { headers: cookie ? { Cookie: cookie } : {}, redirect: "manual" });

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET });
  db = await mf.getD1Database("DB");
  admin = await enrollAdmin(db, SECRET);
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (\'u-alice\',\'Alice\',\'alice@example.test\',1,?,?,\'user\')').bind(now, now).run();
  member = await insertSession(db, SECRET, "u-alice");
  unstepped = await insertSession(db, SECRET, "admin-1");
});

test("the Studio shell renders under renderPage with one SRI-pinned island and no style= attributes", async () => {
  const response = await get("/studio", admin.cookie);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "private, no-store, no-transform");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("content-security-policy"), /^default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-[^']+'; script-src 'self' 'nonce-[^']+'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'$/);
  const { html, code } = await studioShell(fetcher, ORIGIN, response);
  assert.match(html, /<title>Identity Studio · Nathan<\/title>/);
  const props = JSON.parse(/data-nathan-island="studio"[^>]*data-props="([^"]+)"/.exec(html)[1].replaceAll("&quot;", '"'));
  assert.deepEqual(props, { email: "admin@example.test", issuerOrigin: ORIGIN });
  // Every panel of today's Studio is in the bundle.
  for (const title of ["Administrators and recovery", "Register OIDC client", "Roles and access", "Protected applications", "Domain-wide SSO",
    "Access tokens", "Remote MCP servers", "Account admission and invitations", "Social login providers", "Enterprise SSO (OIDC)",
    "Enterprise SAML", "SAML applications", "SCIM directory connections", "Directory lifecycle", "Security audit", "Authentication and MFA policy"])
    assert.ok(code.includes(title), title);
  assert.doesNotMatch(code, /\/studio\/api\/(?!v1)[a-z]/, "the SPA uses only the v1 API");
});

test("Studio stays admin-only: anonymous and non-admins get 403, an unstepped admin is sent to setup", async () => {
  assert.equal((await get("/studio")).status, 403);
  assert.equal((await get("/studio", member.cookie)).status, 403);
  const unsteppedPage = await get("/studio", unstepped.cookie);
  assert.equal(unsteppedPage.status, 302);
  assert.equal(unsteppedPage.headers.get("location"), ORIGIN + "/security?setup=admin");
});

test("the SPA's reads work for the administrator, and the raw Better Auth admin API stays 404", async () => {
  const bootstrap = await get("/studio/api/v1/bootstrap", admin.cookie);
  assert.equal(bootstrap.status, 200);
  const body = await bootstrap.json();
  assert.equal(body.ok, true);
  assert.equal(body.data.isInitialAdmin, true);
  assert.equal(body.data.ready, true);
  assert.equal((await get("/studio/api/v1/bootstrap", member.cookie)).status, 403);
  assert.equal((await get("/studio/api/v1/bootstrap", unstepped.cookie)).status, 403);
  for (const path of ["/api/auth/admin/list-users", "/api/auth/admin/create-user"])
    assert.equal((await mf.dispatchFetch(ORIGIN + path, { method: "POST", headers: { Cookie: admin.cookie, Origin: ORIGIN, "Content-Type": "application/json" }, body: "{}" })).status, 404, path);
});

test("Studio writes still need a same-origin JSON request", async () => {
  const cross = await mf.dispatchFetch(ORIGIN + "/studio/api/v1/admins/grant", { method: "POST", body: JSON.stringify({ email: "x@example.test", confirm: "x" }),
    headers: { Cookie: admin.cookie, Origin: "https://evil.example", "Content-Type": "application/json" } });
  assert.equal(cross.status, 403);
  assert.equal((await cross.json()).error.code, "cross_origin");
  const form = await mf.dispatchFetch(ORIGIN + "/studio/api/v1/admins/grant", { method: "POST", body: "email=x",
    headers: { Cookie: admin.cookie, Origin: ORIGIN, "Content-Type": "application/x-www-form-urlencoded" } });
  assert.equal(form.status, 415);
  // A same-origin JSON write reaches the service, which demands the exact confirmation.
  const refused = await studioPost(fetcher, ORIGIN, "/studio/api/v1/admins/grant", { email: "alice@example.test", confirm: "yes" }, admin.cookie);
  assert.equal(refused.status, 409);
});
