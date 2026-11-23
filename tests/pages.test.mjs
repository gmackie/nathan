import test from "node:test";
import assert from "node:assert/strict";
import { Script } from "node:vm";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { signInPage, consentPage, studioPage } from "../src/auth/ui.ts";
import { installerPage } from "../src/installer/ui.ts";

// NATH-38: /security is a TSX page now (node can't import TSX), so bundle it like ui-render.test.mjs.
await mkdir(".nathan/test-ui", { recursive: true });
const securityBundle = ".nathan/test-ui/security-page.mjs";
await build({
  entryPoints: ["src/auth/security-ui.ts"], outfile: securityBundle, bundle: true, platform: "node", format: "esm",
  jsx: "automatic", packages: "external", logLevel: "error", logOverride: { "module-level-directive": "silent" }
});
const { securityPage } = await import(pathToFileURL(securityBundle).href + "?" + Date.now());

/** Every inline script must at least parse, or no button on the page works. */
function assertScriptsParse(name, html) {
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  for (const [i, source] of scripts.entries()) {
    assert.doesNotThrow(() => new Script(source, { filename: name + "#script" + i }), name + " script " + i + " must parse");
  }
  return scripts.length;
}

test("Identity Studio, sign-in, consent and installer scripts parse", async () => {
  const pages = {
    studio: await studioPage("admin@example.com").text(),
    signIn: await signInPage(["google", "github"], true, true).text(),
    consent: await consentPage(true, "Example app", "openid profile email").text(),
    installer: installerPage("bm9uY2U=")
  };
  let total = 0;
  for (const [name, html] of Object.entries(pages)) total += assertScriptsParse(name, html);
  assert.ok(total >= 3, "expected inline scripts on the interactive pages");
});

test("security page scripts parse: only its import map and the SRI-pinned security island, no inline code", async () => {
  const html = await securityPage("admin@example.com").text();
  const manifest = JSON.parse(readFileSync("src/ui/generated/ui-manifest.json", "utf8"));
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].map(m => ({ attrs: m[1], body: m[2] }));
  const map = scripts.filter(s => / type="importmap"/.test(s.attrs));
  assert.equal(map.length, 1);
  assert.doesNotThrow(() => JSON.parse(map[0].body), "the import map is valid JSON");
  const modules = scripts.filter(s => !/ type="importmap"/.test(s.attrs));
  assert.deepEqual(modules.map(s => / src="([^"]+)"/.exec(s.attrs)?.[1]), [manifest.islands.security.src]);
  for (const m of modules) {
    assert.equal(m.body, "", "no inline code");
    assert.match(m.attrs, / type="module"/);
    assert.ok(m.attrs.includes(' integrity="' + manifest.islands.security.integrity + '"'), "the island carries SRI");
  }
  // The island and every chunk it imports must parse as ES modules, or no button on the page works.
  for (const asset of [manifest.islands.security, ...manifest.islands.security.imports])
    assert.doesNotThrow(() => execFileSync(process.execPath, ["--check", ".nathan/ui-assets" + asset.src], { stdio: "pipe" }), asset.src);
});

/**
 * Under `Referrer-Policy: no-referrer` browsers send `Origin: null` on a same-origin HTML form POST
 * (verified in Chromium against staging: the form got "Cross-origin request denied", while a
 * fetch() POST from the same page carried the real origin). Nathan's write paths and the gateway's
 * unsafe-request check require an exact Origin, so pages must keep the origin on same-origin
 * requests while still sending no referrer cross-site: `same-origin`.
 */
test("interactive pages keep the same-origin Origin header (no no-referrer)", async () => {
  const pages = {
    studio: studioPage("admin@example.com"),
    signIn: signInPage(["google"], true, true),
    consent: consentPage(true, "Example app", "openid"),
    security: securityPage("admin@example.com")
  };
  for (const [name, response] of Object.entries(pages))
    assert.equal(response.headers.get("Referrer-Policy"), "same-origin", name);
});
