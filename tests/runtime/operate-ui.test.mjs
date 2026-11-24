/**
 * NATH-40 in workerd: the built installer and gateway Workers render their Kumo pages with
 * renderPage. The installer page (CSP intact, the wizard island SRI-pinned and served by the
 * installer Worker itself, never by the sealed-release ASSETS binding). The gateway's error pages
 * for browser navigations (no style=, script-src 'none', only /__nathan/ui/ subresources that the
 * gateway serves without touching the upstream, exact returnTo handling in "Try again"), while
 * every non-browser client keeps the plain-text body.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { COMPAT, bundle, cookiesOf, migrateGateway, randomKey, start } from "./helpers.mjs";

const manifest = JSON.parse(readFileSync("src/ui/generated/ui-manifest.json", "utf8"));
const sri = bytes => "sha384-" + createHash("sha384").update(bytes).digest("base64");
const nonceOf = response => /'nonce-([^']+)'/.exec(response.headers.get("content-security-policy"))[1];
const HTML = { Accept: "text/html,application/xhtml+xml" };
/** src/href of every <link> and <script src>. */
const subresources = html => [...html.matchAll(/<(?:link|script)\b[^>]*?\s(?:href|src)="([^"]+)"/g)].map(m => m[1]);
const instances = [];
after(() => Promise.all(instances.map(mf => mf.dispose())));

test("installer: GET / is the renderPage Kumo page; its island is served by the Worker with SRI, not by ASSETS", async () => {
  const assetRequests = [];
  const mf = await start({
    scriptPath: bundle("installer"),
    d1Databases: { INSTALLER_DB: "installer-ui-db" },
    serviceBindings: { ASSETS: request => { assetRequests.push(new URL(request.url).pathname); return new Response("asset"); } },
    bindings: {
      PUBLIC_ORIGIN: "https://install.example.test", CF_OAUTH_CLIENT_ID: "cf-client", CF_OAUTH_CLIENT_SECRET: "cf-secret",
      CF_OAUTH_SCOPES: "user-details.read", INSTALLER_ENCRYPTION_KEY: randomKey()
    }
  });
  instances.push(mf);
  const page = await mf.dispatchFetch("https://install.example.test/");
  const html = await page.text();
  assert.equal(page.status, 200);
  const nonce = nonceOf(page);
  assert.equal(page.headers.get("content-security-policy"),
    "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; " +
    "script-src 'self' 'nonce-" + nonce + "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  for (const [name, value] of [["cache-control", "no-store"], ["referrer-policy", "same-origin"], ["x-frame-options", "DENY"],
    ["x-content-type-options", "nosniff"], ["strict-transport-security", "max-age=31536000"], ["cross-origin-opener-policy", "same-origin"]])
    assert.equal(page.headers.get(name), value, name);
  assert.doesNotMatch(html, /\sstyle=/);
  const island = manifest.islands["installer-wizard"];
  assert.ok(html.includes("<script type=\"module\" src=\"" + island.src + "\" integrity=\"" + island.integrity + "\" nonce=\"" + nonce + "\"></script>"));
  assert.equal([...html.matchAll(/<script\b(?![^>]*\ssrc=)(?![^>]*type="importmap")[^>]*>/g)].length, 0, "no inline script");

  for (const src of subresources(html)) {
    assert.match(src, /^\/__nathan\/ui\//, src);
    const asset = await mf.dispatchFetch("https://install.example.test" + src);
    assert.equal(asset.status, 200, src);
    const expected = [manifest.css, island, ...island.imports].find(a => a.src === src);
    assert.ok(expected, src + " is in the manifest");
    assert.equal(sri(Buffer.from(await asset.arrayBuffer())), expected.integrity, src + " bytes match SRI");
  }
  assert.deepEqual(assetRequests, [], "UI assets never come from the sealed-release ASSETS binding");
  const login = await mf.dispatchFetch("https://install.example.test/api/login", { redirect: "manual" });
  assert.notEqual(login.status, 404, "the Cloudflare OAuth start route is still the Worker's");
});

const ISSUER = "https://login.example.test/api/auth";
const ORIGIN = "https://app.example.test";
async function gateway() {
  const upstreamRequests = [];
  const mf = await start({
    workers: [{
      name: "gateway", modules: true, ...COMPAT, scriptPath: bundle("gateway"),
      d1Databases: { SESSIONS: "gateway-ui-sessions" },
      serviceBindings: {
        UPSTREAM: request => { upstreamRequests.push(request.url); return new Response("upstream ok"); },
        NATHAN: { name: "nathan-stub", entrypoint: "NathanVerifier" }
      },
      outboundService: request => request.url === ISSUER + "/.well-known/openid-configuration"
        ? Response.json({ issuer: ISSUER, authorization_endpoint: ISSUER + "/oauth2/authorize", token_endpoint: ISSUER + "/oauth2/token", jwks_uri: ISSUER + "/jwks" })
        : new Response("unexpected outbound " + request.url, { status: 599 }),
      bindings: {
        NATHAN_ISSUER: ISSUER, PUBLIC_ORIGIN: ORIGIN, APPLICATION_ID: "dashboard", OIDC_CLIENT_ID: "gateway-client",
        OIDC_CLIENT_SECRET: "s".repeat(40), SESSION_ENCRYPTION_KEY: randomKey(), SESSION_TTL_SECONDS: "3600",
        REQUIRE_AAL2: "false", NATHAN_PRINCIPAL_KEY: randomKey()
      }
    }, {
      name: "nathan-stub", modules: true, ...COMPAT,
      script: 'import { WorkerEntrypoint } from "cloudflare:workers";\n' +
        'export class NathanVerifier extends WorkerEntrypoint { async resolveAccess() { return { allowed: true, roles: [], permissions: [] }; } }\n' +
        'export default { fetch() { return new Response(null, { status: 404 }); } };'
    }]
  });
  instances.push(mf);
  await migrateGateway(await mf.getD1Database("SESSIONS", "gateway"));
  return { mf, upstreamRequests };
}

/** Checks a gateway error page and returns its HTML. */
async function assertGatewayPage(mf, response, status, message) {
  const html = await response.text();
  assert.equal(response.status, status);
  assert.match(response.headers.get("content-type"), /^text\/html/);
  const nonce = nonceOf(response);
  assert.equal(response.headers.get("content-security-policy"),
    "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; " +
    "script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "same-origin");
  assert.doesNotMatch(html, /<script|\sstyle=/);
  assert.ok(html.includes(message), message);
  assert.deepEqual(subresources(html), [manifest.css.src], "the page loads only the gateway's own stylesheet");
  const css = await mf.dispatchFetch(ORIGIN + manifest.css.src);
  assert.equal(css.status, 200);
  assert.equal(sri(Buffer.from(await css.arrayBuffer())), manifest.css.integrity);
  return html;
}

test("gateway: browser navigations get Kumo error pages built only from /__nathan/ui/; other clients keep plain text", async () => {
  const { mf, upstreamRequests } = await gateway();
  await assertGatewayPage(mf, await mf.dispatchFetch(ORIGIN + "/__nathan/nope", { headers: HTML }), 404, "Not found");

  const badState = await mf.dispatchFetch(ORIGIN + "/__nathan/callback?code=c&state=forged", { headers: HTML, redirect: "manual" });
  assert.match(cookiesOf(badState)["__Host-nathan-flow"].raw, /Max-Age=0/, "the flow cookie is still cleared");
  const badHtml = await assertGatewayPage(mf, badState, 400, "Login state invalid or expired. Please try again.");
  assert.match(badHtml, /<a [^>]*href="\/__nathan\/login\?returnTo=%2F"/);

  // IdP refusal: "Try again" restarts login with the flow's validated returnTo, and a hostile one stays "/".
  for (const [returnTo, expected] of [["/reports?tab=a", "%2Freports%3Ftab%3Da"], ["//evil.example/x", "%2F"], ["https://evil.example/", "%2F"]]) {
    const begin = await mf.dispatchFetch(ORIGIN + "/__nathan/login?returnTo=" + encodeURIComponent(returnTo), { redirect: "manual" });
    assert.equal(begin.status, 302);
    const state = new URL(begin.headers.get("Location")).searchParams.get("state");
    const refused = await mf.dispatchFetch(ORIGIN + "/__nathan/callback?error=access_denied&state=" + state, {
      redirect: "manual", headers: { ...HTML, Cookie: "__Host-nathan-flow=" + cookiesOf(begin)["__Host-nathan-flow"].value }
    });
    const html = await assertGatewayPage(mf, refused, 401, "Identity provider rejected login");
    const links = [...html.matchAll(/<a [^>]*href="([^"]+)"/g)].map(m => m[1]);
    assert.deepEqual(links, ["/__nathan/login?returnTo=" + expected], returnTo);
  }

  // Not a navigation: exactly today's plain-text body.
  const api = await mf.dispatchFetch(ORIGIN + "/__nathan/nope", { headers: { Accept: "application/json" } });
  assert.equal(api.status, 404);
  assert.equal(api.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(await api.text(), "Not found");
  const post = await mf.dispatchFetch(ORIGIN + "/__nathan/logout", { method: "POST", headers: { ...HTML, Origin: "https://evil.example" } });
  assert.equal(post.status, 403);
  assert.equal(await post.text(), "Cross-origin logout denied");

  // Unauthenticated navigation to an app path still redirects to login with the exact returnTo.
  const app = await mf.dispatchFetch(ORIGIN + "/reports?x=1", { headers: HTML, redirect: "manual" });
  assert.equal(app.status, 302);
  assert.equal(app.headers.get("Location"), ORIGIN + "/__nathan/login?returnTo=" + encodeURIComponent("/reports?x=1"));
  assert.deepEqual(upstreamRequests, [], "no gateway page or asset ever reached the upstream");
});
