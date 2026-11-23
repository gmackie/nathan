/**
 * NATH-40: the installer and gateway pages under renderPage. CSP-safe markup, islands with SRI,
 * escaping, the gateway's same-origin-only subresources, and island markup that hydrates with the
 * same React ids the browser-side root computes.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { rewriteTags } from "../src/ui/csp-styles.ts";

await mkdir(".nathan/test-ui", { recursive: true });
const outfile = ".nathan/test-ui/operate-pages.mjs";
await build({
  entryPoints: ["tests/fixtures/operate-pages.tsx"], outfile, bundle: true, platform: "node", format: "esm",
  jsx: "automatic", packages: "external", logLevel: "error", logOverride: { "module-level-directive": "silent" }
});
const ui = await import(pathToFileURL(outfile).href + "?" + Date.now());
const manifest = JSON.parse(readFileSync("src/ui/generated/ui-manifest.json", "utf8"));

const csp = response => response.headers.get("content-security-policy");
const tags = html => {
  const out = [];
  rewriteTags(html, tag => { out.push({ name: tag.name, attrs: Object.fromEntries(tag.attributes.map(a => [a.name, a.value])) }); });
  return out;
};
/** Every URL the page makes the browser load (stylesheets, module preloads, scripts). */
const subresources = html => tags(html).flatMap(t =>
  t.name === "link" ? [t.attrs.href] : t.name === "script" && t.attrs.src ? [t.attrs.src] : []);

test("installer: renderPage CSP, the SRI-pinned wizard island and no style or inline code", async () => {
  const response = ui.installerPage();
  const html = await response.text();
  const policy = csp(response);
  const nonce = /'nonce-([^']+)'/.exec(policy)[1];
  assert.equal(policy, "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; " +
    "script-src 'self' 'nonce-" + nonce + "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  for (const [name, value] of [["cache-control", "no-store"], ["referrer-policy", "same-origin"], ["x-frame-options", "DENY"],
    ["x-content-type-options", "nosniff"], ["strict-transport-security", "max-age=31536000"]])
    assert.equal(response.headers.get(name), value, name);
  assert.doesNotMatch(html, /\sstyle=/);
  const island = manifest.islands["installer-wizard"];
  const scripts = tags(html).filter(t => t.name === "script");
  assert.deepEqual(scripts.map(s => s.attrs.type), ["importmap", "module"]);
  assert.deepEqual(scripts[1].attrs, { type: "module", src: island.src, integrity: island.integrity, nonce });
  const integrity = JSON.parse(/<script type="importmap"[^>]*>([^<]*)<\/script>/.exec(html)[1]).integrity;
  for (const asset of [island, ...island.imports]) assert.equal(integrity[asset.src], asset.integrity, asset.src);
  for (const src of subresources(html)) assert.match(src, /^\/__nathan\/ui\/[A-Za-z0-9_-]+\.(css|js)$/, src);
  for (const link of tags(html).filter(t => t.name === "link")) assert.match(link.attrs.integrity, /^sha384-/);
  // Every wizard step and the Kumo controls are server-rendered.
  for (const text of ["1. Connect Cloudflare", "2. Choose installation details", "3. Configure first sign-in",
    "4. Enterprise, MFA and directory provisioning", "5. Review and deploy", "What gets created?"])
    assert.ok(html.includes(text), text);
  assert.match(html, /<a [^>]*href="\/api\/login"/, "Connect Cloudflare is a plain link to the OAuth start");
  // Off-site links open without opener or referrer.
  for (const a of tags(html).filter(t => t.name === "a" && /^https:/.test(t.attrs.href)))
    assert.equal(a.attrs.rel, "noopener noreferrer", a.attrs.href);
});

test("installer: the island markup uses the same React ids as the browser-side root", async () => {
  const html = await ui.installerPage().text();
  const ids = s => [...s.matchAll(/\s(id|for|aria-labelledby|aria-describedby|aria-controls)="([^"]+)"/g)].map(m => m[0]);
  const container = html.slice(html.indexOf("data-nathan-island=\"installer-wizard\""));
  const standalone = ui.standaloneWizard();
  assert.ok(ids(standalone).some(id => id.includes("base-ui-")), "the wizard has Base UI generated ids");
  assert.deepEqual(ids(container).slice(0, ids(standalone).length), ids(standalone));
});

test("gateway error page: escaped message, script-src 'none', form-action 'none', only /__nathan/ui/ assets", async () => {
  const response = ui.renderGatewayError({ status: 403, message: "Access denied <img src=x onerror=alert(1)> & \"quoted\"" });
  const html = await response.text();
  assert.equal(response.status, 403);
  const nonce = /'nonce-([^']+)'/.exec(csp(response))[1];
  assert.equal(csp(response), "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; " +
    "script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'");
  assert.doesNotMatch(html, /<script|\sstyle=|<img/);
  assert.ok(html.includes("Access denied &lt;img src=x onerror=alert(1)&gt; &amp; &quot;quoted&quot;"));
  assert.deepEqual(subresources(html), [manifest.css.src]);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "same-origin");
});

test("gateway error page: Try again only ever links to a same-origin path", async () => {
  const href = async retry => tags(await ui.renderGatewayError({ status: 401, message: "x", retry }).text())
    .filter(t => t.name === "a").map(t => t.attrs.href);
  assert.deepEqual(await href("/__nathan/login?returnTo=%2Freports"), ["/__nathan/login?returnTo=%2Freports"]);
  for (const hostile of ["//evil.example/x", "https://evil.example/", "/\\evil.example", "javascript:alert(1)"])
    assert.deepEqual(await href(hostile), ["/"], hostile);
  assert.deepEqual(await href(undefined), [], "no link without a retry target");
});
