/**
 * NATH-37 in workerd: renderPage() pages from a test-only Worker (react-dom/server's workerd
 * build), and the hashed UI assets served by the built identity Worker itself (src/ui/assets.ts,
 * NATH-32), with immutable caching, nosniff and SRI-matching bytes. Assets never shadow a route.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { authWorker, bundle, start } from "./helpers.mjs";

const HOST = "auth.example.test";
const manifest = JSON.parse(readFileSync("src/ui/generated/ui-manifest.json", "utf8"));
const sri = bytes => "sha384-" + createHash("sha384").update(bytes).digest("base64");

function fixture() {
  const path = ".nathan/build-ui-fixture/ui-worker.js";
  if (!existsSync(path)) throw Error("Missing " + path + ": run `npm run test:runtime`, which builds it first");
  return start({ name: "nathan-test-ui", scriptPath: path });
}

test("workerd renders K0 pages CSP-safe, with today's headers, and islands with SRI", async () => {
  const mf = await fixture();
  try {
    const form = await mf.dispatchFetch("https://" + HOST + "/form");
    const html = await form.text();
    assert.equal(form.status, 200);
    const nonce = /'nonce-([^']+)'/.exec(form.headers.get("content-security-policy"))[1];
    assert.equal(form.headers.get("content-security-policy"),
      "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; script-src 'none'; " +
      "form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    for (const [name, value] of [["cache-control", "no-store"], ["referrer-policy", "same-origin"], ["x-content-type-options", "nosniff"],
      ["x-frame-options", "DENY"], ["cross-origin-opener-policy", "same-origin"], ["strict-transport-security", "max-age=31536000"]])
      assert.equal(form.headers.get(name), value, name);
    assert.doesNotMatch(html, /\sstyle=/);
    assert.doesNotMatch(html, /<script/);
    assert.match(html, new RegExp("<style nonce=\"" + nonce.replace(/[+/=]/g, "\\$&") + "\" data-nathan-inline>\\.nathan-inline-0\\{"));
    assert.match(html, /--kumo-button-emphasis-bg:/, "Kumo's Button styles survive as classes");

    const island = await mf.dispatchFetch("https://" + HOST + "/island");
    const islandHtml = await island.text();
    const entry = manifest.islands["passkey-button"];
    const islandNonce = /'nonce-([^']+)'/.exec(island.headers.get("content-security-policy"))[1];
    assert.match(island.headers.get("content-security-policy"), /script-src 'self' 'nonce-/);
    assert.ok(islandHtml.includes("<script type=\"module\" src=\"" + entry.src + "\" integrity=\"" + entry.integrity + "\" nonce=\"" + islandNonce + "\">"));
    assert.doesNotMatch(islandHtml, /\sstyle=/);

    const refusal = await (await mf.dispatchFetch("https://" + HOST + "/refusal")).text();
    assert.ok(refusal.includes("Start again from the application. (saml_cross_site_request)</p>"));

    const post = await mf.dispatchFetch("https://" + HOST + "/auto-post");
    assert.match(post.headers.get("content-security-policy"), /form-action https:\/\/sp\.example\.com;/);
    const formTag = /<form [^>]*>/.exec(await post.text())[0];
    for (const attr of ["method=\"post\"", "action=\"https://sp.example.com/acs\"", "id=\"saml-post\"", "data-nathan-autopost=\"\""])
      assert.ok(formTag.includes(attr), formTag + " has " + attr);
  } finally { await mf.dispose(); }
});

test("the identity Worker serves its bundled UI assets from /__nathan/ui/ immutably, and assets never shadow its routes", async () => {
  assert.doesNotMatch(readFileSync("wrangler.auth.jsonc", "utf8"), /"assets":/, "no static-assets binding");
  const mf = await authWorker(HOST, {}, { name: "nathan-auth" });
  try {
    const files = [manifest.css, ...Object.values(manifest.islands).flatMap(i => [i, ...i.imports])];
    for (const asset of files) {
      const response = await mf.dispatchFetch("https://" + HOST + asset.src);
      assert.equal(response.status, 200, asset.src);
      assert.equal(sri(Buffer.from(await response.arrayBuffer())), asset.integrity, asset.src + " bytes match SRI");
      assert.equal(response.headers.get("cache-control"), "public, max-age=31536000, immutable", asset.src);
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
      assert.match(response.headers.get("content-type"), asset.src.endsWith(".css") ? /^text\/css/ : /^text\/javascript/);
    }
    const head = await mf.dispatchFetch("https://" + HOST + manifest.css.src, { method: "HEAD" });
    assert.equal(head.status, 200);
    const post = await mf.dispatchFetch("https://" + HOST + manifest.css.src, { method: "POST" });
    assert.equal(post.status, 405);
    // Unknown files under the prefix are an uncached 404; every other path still reaches the routes.
    for (const path of ["/__nathan/ui/nope.js", "/__nathan/ui/../healthz", "/__nathan/ui/"]) {
      const missing = await mf.dispatchFetch("https://" + HOST + path);
      if (new URL("https://" + HOST + path).pathname.startsWith("/__nathan/ui/")) {
        assert.equal(missing.status, 404, path);
        assert.equal(missing.headers.get("cache-control"), "no-store", path);
      }
    }
    const discovery = await mf.dispatchFetch("https://" + HOST + "/api/auth/.well-known/openid-configuration");
    assert.equal(discovery.status, 200, "OIDC discovery is still the Worker's");
    const signIn = await mf.dispatchFetch("https://" + HOST + "/sign-in");
    assert.equal(signIn.status, 200);
    assert.equal(signIn.headers.get("cache-control"), "private, no-store, no-transform", "preserve the identity document at the edge");
  } finally { await mf.dispose(); }
});

test("no Worker bundle ships echarts or shiki", () => {
  for (const path of [bundle("auth"), ".nathan/build-ui-fixture/ui-worker.js"]) {
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(source, /zrender|echarts\.init|createHighlighter/, path);
  }
});
