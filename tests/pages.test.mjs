import test from "node:test";
import assert from "node:assert/strict";
import { Script } from "node:vm";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { signInPage, consentPage } from "../src/auth/ui.ts";

// NATH-38 /security and NATH-40 installer are TSX pages now (node can't import TSX), so bundle them
// like ui-render.test.mjs does.
await mkdir(".nathan/test-ui", { recursive: true });
const BUNDLE = { platform: "node", format: "esm", bundle: true, jsx: "automatic", packages: "external", logLevel: "error",
  logOverride: { "module-level-directive": "silent" } };
const securityBundle = ".nathan/test-ui/security-page.mjs";
await build({ ...BUNDLE, entryPoints: ["src/auth/security-ui.ts"], outfile: securityBundle });
const { securityPage } = await import(pathToFileURL(securityBundle).href + "?" + Date.now());
await build({ ...BUNDLE, entryPoints: ["src/installer/ui.ts"], outfile: ".nathan/test-ui/installer-ui.mjs" });
const { installerPage } = await import(pathToFileURL(".nathan/test-ui/installer-ui.mjs").href + "?" + Date.now());

/** Every inline script must at least parse, or no button on the page works. Import maps must be JSON. */
function assertScriptsParse(name, html) {
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].map(m => ({ attrs: m[1], source: m[2] }));
  for (const [i, { attrs, source }] of scripts.entries()) {
    if (/\btype="importmap"/.test(attrs)) assert.doesNotThrow(() => JSON.parse(source), name + " import map " + i + " must be JSON");
    else assert.doesNotThrow(() => new Script(source, { filename: name + "#script" + i }), name + " script " + i + " must parse");
  }
  return scripts.length;
}

// The Kumo Studio shell and its security headers are covered by studio-ui.test.mjs.
test("sign-in, consent, security and installer scripts parse", async () => {
  const pages = {
    signIn: await signInPage(["google", "github"], true, true).text(),
    consent: await consentPage(true, "Example app", "openid profile email").text(),
    security: await securityPage("admin@example.com").text(),
    installer: await installerPage().text()
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
    installer: installerPage(),
    signIn: signInPage(["google"], true, true),
    consent: consentPage(true, "Example app", "openid"),
    security: securityPage("admin@example.com")
  };
  for (const [name, response] of Object.entries(pages))
    assert.equal(response.headers.get("Referrer-Policy"), "same-origin", name);
});

/** NATH-40: the installer page has no inline code; its wizard is the SRI-pinned installer-wizard island. */
test("installer page loads its wizard only as the hashed island, with no inline script", async () => {
  const response = installerPage();
  const html = await response.text();
  const manifest = JSON.parse(readFileSync("src/ui/generated/ui-manifest.json", "utf8"));
  const island = manifest.islands["installer-wizard"];
  assert.ok(island, "installer-wizard is a built island");
  const nonce = /'nonce-([^']+)'/.exec(response.headers.get("content-security-policy"))[1];
  assert.ok(html.includes("<script type=\"module\" src=\"" + island.src + "\" integrity=\"" + island.integrity + "\" nonce=\"" + nonce + "\"></script>"));
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (/type="importmap"/.test(m[1])) continue;
    assert.match(m[1], /\ssrc="\/__nathan\/ui\/[^"]+" integrity="sha384-/, "every script is a hashed same-origin module with SRI");
    assert.equal(m[2], "", "no inline code");
  }
  assert.doesNotMatch(html, /\sstyle=|\son[a-z]+=/i, "no style or event-handler attributes");
  assert.doesNotMatch(html, /__NONCE__|providerRegistry=/, "the old inline registry script is gone");
  assert.match(html, /href="\/api\/login"/, "Connect Cloudflare works as a plain link");
});
