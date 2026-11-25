/**
 * NATH-37: the K0 Kumo layer. renderPage's CSP-safe output, headers, islands with SRI, layouts,
 * escaping, icons and theme. TSX can't be imported by node directly, so the fixture is bundled
 * with esbuild first (packages stay external). `npm test` runs scripts/build-ui.mjs beforehand.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import {
  moveInlineStylesToClasses, assertCspSafe, safeDeclarations, decodeAttribute, rewriteTags
} from "../src/ui/csp-styles.ts";
import { contentSecurityPolicy, securityHeaders, formActionSource } from "../src/ui/headers.ts";
import { BRANDABLE_TOKENS, isBrandableToken } from "../src/ui/theme.ts";
import { PROVIDER_IDS } from "../src/shared/providers.mjs";

assert.ok(existsSync("src/ui/generated/ui-manifest.json"), "run `node scripts/build-ui.mjs` first (npm test does)");
await mkdir(".nathan/test-ui", { recursive: true });
const outfile = ".nathan/test-ui/ui-pages.mjs";
await build({
  entryPoints: ["tests/fixtures/ui-pages.tsx"], outfile, bundle: true, platform: "node", format: "esm",
  jsx: "automatic", packages: "external", logLevel: "error", logOverride: { "module-level-directive": "silent" }
});
const ui = await import(pathToFileURL(outfile).href + "?" + Date.now());

const cspOf = response => response.headers.get("content-security-policy");
const nonceOf = response => /'nonce-([^']+)'/.exec(cspOf(response))[1];
/** Every start tag with its attributes, through the renderer's own tokenizer. */
const tags = html => {
  const out = [];
  rewriteTags(html, tag => { out.push({ name: tag.name, attrs: Object.fromEntries(tag.attributes.map(a => [a.name, a.value])) }); });
  return out;
};

// ---- CSP-safe output -------------------------------------------------------------------------

test("a page with Button, Checkbox and Input has no style attributes; their styles are nonce'd classes", async () => {
  const response = ui.formPage();
  const html = await response.text();
  assert.doesNotMatch(html, /\sstyle=/i, "no style= attribute anywhere");
  const styles = tags(html).filter(t => t.name === "style");
  assert.equal(styles.length, 1, "one generated <style> block");
  assert.equal(styles[0].attrs.nonce, nonceOf(response));
  const block = /<style nonce="[^"]+" data-nathan-inline>([^<]*)<\/style>/.exec(html)[1];
  // Kumo's Button emphasis custom properties and the visually-hidden checkbox input.
  assert.match(block, /\.nathan-inline-\d+\{[^}]*--kumo-button-emphasis-bg:color-mix\(in oklch, var\(--color-kumo-brand\), white 30%\)/);
  assert.match(block, /\.nathan-inline-\d+\{clip-path:inset\(50%\);overflow:hidden;[^}]*width:1px;height:1px;/);
  // Two primary buttons share one class (deduplicated).
  const defined = [...block.matchAll(/\.(nathan-inline-\d+)\{/g)].map(m => m[1]);
  assert.equal(new Set(defined).size, defined.length);
  const used = tags(html).flatMap(t => (t.attrs.class ?? "").split(/\s+/)).filter(c => /^nathan-inline-\d+$/.test(c));
  assert.deepEqual([...new Set(used)].sort(), [...defined].sort(), "every generated class is defined and used");
  const primary = tags(html).filter(t => t.name === "button" && /emphasis-bg/.test(t.attrs.class));
  assert.equal(primary.length, 2);
  assert.equal(primary[0].attrs.class.split(" ").at(-1), primary[1].attrs.class.split(" ").at(-1));
});

test("style attributes are parsed with React's escaping (&quot; &amp;) and merged into class", () => {
  const { html, css, classes } = moveInlineStylesToClasses(
    "<div class=\"a b\" style=\"font-family:&quot;A&amp;B&quot;;color:red\"><span style=\"color:red\"></span>" +
    "<i style=\"font-family:&quot;A&amp;B&quot;;color:red\"></i><p style=\"\">t</p></div>");
  assert.equal(css, ".nathan-inline-0{font-family:\"A&B\";color:red}.nathan-inline-1{color:red}");
  assert.equal(classes, 2);
  assert.equal(html, "<div class=\"a b nathan-inline-0\"><span class=\"nathan-inline-1\"></span><i class=\"nathan-inline-0\"></i><p>t</p></div>");
  assert.equal(decodeAttribute("&#x27;&#39;&lt;&gt;"), "''<>");
});

test("style values that could leave their rule are refused (fail closed)", () => {
  for (const bad of ["color:red}body{color:blue", "x:</style><script>", "a:\"open", "b:'x", "c:\\7d", "d:/* x */", "e:{"]) {
    assert.throws(() => safeDeclarations(bad), /Unsafe inline style/, bad);
  }
  assert.equal(safeDeclarations(" color: red; "), "color: red");
  assert.equal(safeDeclarations("font-family:\"a;b\""), "font-family:\"a;b\"");
  assert.throws(() => ui.hostileStylePage("x}body{background:red"), /Unsafe inline style/);
  assert.throws(() => ui.hostileStylePage("\"x"), /Unsafe inline style/);
});

test("the final scan refuses style attributes, event handlers and scripts without the nonce", () => {
  const n = "AAAAAAAAAAAAAAAAAAAAAA==";
  assert.throws(() => assertCspSafe("<p style=\"x:y\">", n, { allowScripts: false }), /Inline style attribute/);
  assert.throws(() => assertCspSafe("<p onclick=\"x()\">", n, { allowScripts: false }), /event handler/);
  assert.throws(() => assertCspSafe("<script nonce=\"" + n + "\"></script>", n, { allowScripts: false }), /without islands/);
  assert.throws(() => assertCspSafe("<script></script>", n, { allowScripts: true }), /nonce/);
  assert.throws(() => assertCspSafe("<style></style>", n, { allowScripts: false }), /nonce/);
  assert.doesNotThrow(() => assertCspSafe("<script nonce=\"" + n + "\">a<b</script><p data-style=\"x\">", n, { allowScripts: true }));
});

// ---- Headers ---------------------------------------------------------------------------------

test("pages send today's security headers; without islands there is no script at all", async () => {
  const response = ui.formPage();
  const html = await response.text();
  const nonce = nonceOf(response);
  assert.equal(response.status, 200);
  assert.equal(cspOf(response),
    "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; script-src 'none'; " +
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  assert.equal(response.headers.get("content-type"), "text/html; charset=utf-8");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "same-origin");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(response.headers.get("strict-transport-security"), "max-age=31536000");
  assert.doesNotMatch(html, /<script/i);
  assert.match(html, /^<!doctype html><html lang="en" data-theme="nathan" data-mode="system"><head>/);
  assert.match(html, /<title>Sign in · Nathan<\/title>/);
  const css = tags(html).find(t => t.name === "link" && t.attrs.rel === "stylesheet");
  assert.deepEqual([css.attrs.href, css.attrs.integrity], [ui.UI_MANIFEST.css.src, ui.UI_MANIFEST.css.integrity]);
});

test("renderPage options: status, lang, theme, body class, extra headers; security headers can't be overridden", async () => {
  const response = ui.formPage("X", { status: 403, lang: "de-CH", theme: "dark", bodyClass: "a\"b",
    headers: { "Set-Cookie": "a=1; Path=/; Secure", "Vary": "Cookie" } });
  const html = await response.text();
  assert.equal(response.status, 403);
  assert.match(html, /<html lang="de-CH" data-theme="nathan" data-mode="dark">/);
  assert.match(html, /<body class="nathan-body a&quot;b">/);
  assert.deepEqual(response.headers.getSetCookie(), ["a=1; Path=/; Secure"]);
  assert.equal(response.headers.get("vary"), "Cookie");
  assert.throws(() => ui.formPage("X", { headers: { "Content-Security-Policy": "default-src *" } }), /owns the content-security-policy/);
  assert.throws(() => ui.formPage("X", { headers: { "cache-control": "public" } }), /owns the cache-control/);
  assert.throws(() => ui.formPage("X", { lang: "en\"><script>" }), /Invalid lang/);
  assert.throws(() => ui.formPage("X", { theme: "neon" }), /Invalid theme/);
  assert.throws(() => ui.formPage("X", { islands: ["nope"] }), /Unknown island/);
  assert.throws(() => ui.formPage("X", { formAction: ["http://sp.example.com"] }), /form-action/);
  assert.throws(() => ui.formPage("X", { formAction: ["https://sp.example.com/acs"] }), /form-action/);
});

test("CSP helpers validate nonce and form-action sources", () => {
  assert.throws(() => contentSecurityPolicy({ nonce: "x'; script-src *", scripts: true }), /nonce/);
  assert.equal(formActionSource("https://sp.example.com"), "https://sp.example.com");
  assert.throws(() => formActionSource("*"), /form-action/);
  assert.match(contentSecurityPolicy({ nonce: "AAAAAAAAAAAAAAAAAAAAAA==", scripts: false, formAction: [] }), /form-action 'none'/);
  assert.throws(() => securityHeaders({ nonce: "AAAAAAAAAAAAAAAAAAAAAA==", scripts: false }, { "X-Frame-Options": "ALLOW" }), /owns/);
});

// ---- Islands ---------------------------------------------------------------------------------

test("islands load as SRI'd, nonce'd module scripts; their chunks are pinned too", async () => {
  const response = ui.islandPage();
  const html = await response.text();
  const nonce = nonceOf(response);
  assert.match(cspOf(response), new RegExp("script-src 'self' 'nonce-" + nonce.replace(/[+/=]/g, "\\$&") + "'"));
  const island = ui.UI_MANIFEST.islands["passkey-button"];
  const all = tags(html);
  const scripts = all.filter(t => t.name === "script");
  for (const s of scripts) assert.equal(s.attrs.nonce, nonce, "every script carries the CSP nonce");
  const modules = scripts.filter(s => s.attrs.type === "module");
  assert.deepEqual(modules.map(s => [s.attrs.src, s.attrs.integrity]), [[island.src, island.integrity]]);
  assert.ok(island.imports.length >= 1, "React islands import the shared vendor chunk");
  const preloads = all.filter(t => t.name === "link" && t.attrs.rel === "modulepreload");
  assert.deepEqual(preloads.map(l => [l.attrs.href, l.attrs.integrity]), island.imports.map(i => [i.src, i.integrity]));
  const importMap = JSON.parse(/<script type="importmap" nonce="[^"]+">([^<]*)<\/script>/.exec(html)[1]);
  assert.equal(importMap.integrity[island.src], island.integrity);
  for (const chunk of island.imports) assert.equal(importMap.integrity[chunk.src], chunk.integrity);
  // Server markup: island container with JSON props, button disabled until hydrated.
  assert.match(html, /<div data-nathan-island="passkey-button" data-props="\{&quot;label&quot;:&quot;Sign in with passkey&quot;\}">/);
  assert.match(html, /<button data-kumo-component="Button"[^>]*disabled=""[^>]*data-hydrated="false"/);
  assert.doesNotMatch(html, /\sstyle=/);
});

test("an island in the markup must be listed in renderPage's islands", () => {
  assert.throws(() => ui.unlistedIslandPage(), /Island passkey-button is rendered but not in/);
});

test("built assets match their SRI hashes and stay under /__nathan/ui/", () => {
  const m = ui.UI_MANIFEST;
  const files = [m.css, ...Object.values(m.islands).flatMap(i => [i, ...i.imports])];
  for (const asset of files) {
    assert.match(asset.src, /^\/__nathan\/ui\/[A-Za-z0-9_-]+\.(css|js)$/);
    const bytes = readFileSync(".nathan/ui-assets" + asset.src);
    assert.equal("sha384-" + createHash("sha384").update(bytes).digest("base64"), asset.integrity, asset.src);
  }
  // The Worker serves the bundled copies (src/ui/assets.ts): same bytes, so SRI still holds.
  const bundled = JSON.parse(readFileSync("src/ui/generated/ui-assets.json", "utf8"));
  for (const asset of files)
    assert.equal("sha384-" + createHash("sha384").update(Buffer.from(bundled[asset.src].body, "utf8")).digest("base64"), asset.integrity, "bundled " + asset.src);
  assert.deepEqual(m.islands["auto-post"].imports, [], "auto-post is plain script, no React");
  for (const asset of files) {
    const text = readFileSync(".nathan/ui-assets" + asset.src, "utf8");
    assert.doesNotMatch(text, /zrender|echarts\.init|createHighlighter/, asset.src + " must not bundle echarts or shiki");
  }
});

// ---- Layouts ---------------------------------------------------------------------------------

test("RefusalPage shows the message with its reason code as one '(code)' text, no script", async () => {
  const response = ui.refusalPage("Request refused", "Confirm the sign-in on Nathan's own page.", "saml_cross_site_request", true, 403);
  const html = await response.text();
  assert.equal(response.status, 403);
  assert.ok(html.includes("Confirm the sign-in on Nathan&#x27;s own page. (saml_cross_site_request)</p>"), html);
  assert.match(html, /<p class="nathan-text" role="alert">/);
  assert.match(html, /<a [^>]*href="\/sign-in"[^>]*>/);
  assert.doesNotMatch(html, /<script/);
  assert.doesNotMatch(html, /\sstyle=/);
  assert.match(cspOf(response), /script-src 'none'/);
});

test("hostile titles, messages and codes are HTML-escaped", async () => {
  const evil = "<script>alert(1)</script>\"'&";
  const html = await ui.refusalPage(evil, evil, evil).text();
  assert.doesNotMatch(html, /<script>alert/);
  assert.ok(html.includes("<title>&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp; · Nathan</title>"));
  assert.ok(html.includes(">&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp;</h1>"));
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp; (&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp;)</p>"));
  assert.equal(tags(html).filter(t => t.name === "script").length, 0);
});

test("AutoPostPage posts to the exact ACS URL, allows only its origin, and auto-submits via the SRI'd island", async () => {
  const response = ui.autoPostPage("https://sp.example.com/saml/acs?x=1&y=\"2\"", "PHNhbWw+\"&<", "relay\"<", "Grafana <dev>");
  const html = await response.text();
  const nonce = nonceOf(response);
  assert.match(cspOf(response), /form-action https:\/\/sp\.example\.com; /);
  const form = tags(html).find(t => t.name === "form");
  assert.deepEqual(form.attrs, { method: "post", action: "https://sp.example.com/saml/acs?x=1&y=\"2\"", id: "saml-post", "data-nathan-autopost": "" });
  const inputs = tags(html).filter(t => t.name === "input").map(t => [t.attrs.name, t.attrs.value, t.attrs.type]);
  assert.deepEqual(inputs, [["SAMLResponse", "PHNhbWw+\"&<", "hidden"], ["RelayState", "relay\"<", "hidden"]]);
  assert.ok(html.includes("<noscript><p class=\"nathan-text\">JavaScript is off. Continue to send your sign-in to Grafana &lt;dev&gt;.</p></noscript>"));
  assert.match(html, /<button[^>]*type="submit"[^>]*>/);
  const island = ui.UI_MANIFEST.islands["auto-post"];
  assert.ok(html.includes("<script type=\"module\" src=\"" + island.src + "\" integrity=\"" + island.integrity + "\" nonce=\"" + nonce + "\"></script>"));
  const noRelay = await ui.autoPostPage("https://sp.example.com/acs", "x", null, "SP").text();
  assert.doesNotMatch(noRelay, /RelayState/);
  assert.throws(() => ui.autoPostPage("http://sp.example.com/acs", "x", null, "SP"), /https/);
  assert.throws(() => ui.autoPostPage("javascript:alert(1)", "x", null, "SP"), /https/);
});

// ---- Icons and theme -------------------------------------------------------------------------

test("every registered provider has its own icon; unknown providers get the generic one", () => {
  for (const id of PROVIDER_IDS) {
    assert.ok(Object.hasOwn(ui.PROVIDER_ICONS, id), "icon for " + id);
    assert.notEqual(ui.providerIcon(id), ui.GENERIC_PROVIDER_ICON, id);
  }
  assert.equal(ui.providerIcon("okta"), ui.GENERIC_PROVIDER_ICON);
  assert.equal(ui.providerIcon("__proto__"), ui.GENERIC_PROVIDER_ICON);
  for (const name of ["passkey", "key", "shield-check", "warning", "error", "info", "success", "user", "users", "app",
    "token", "mcp", "sso", "scim", "settings", "sign-out"]) assert.ok(ui.ICONS[name], name);
  const markup = ui.iconMarkup();
  assert.match(markup.google, /^<svg [^>]*width="20"[^>]*>/);
  assert.match(markup.google, /^<svg [^>]*aria-hidden="true"[^>]*>/);
  assert.match(markup.unknown, /role="img"[^>]*aria-label="Okta"/);
  assert.match(markup.passkey, /^<svg /);
});

/** WCAG relative luminance and contrast for #rrggbb. */
function contrast(a, b) {
  const lum = hex => {
    const [r, g, bl] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
      .map(c => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
  };
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

test("theme: Nathan's default is stock Kumo; appearance may set only real Kumo tokens or Nathan's plate tokens", () => {
  const kumo = readFileSync("node_modules/@cloudflare/kumo/dist/styles/theme-kumo.css", "utf8");
  const theme = readFileSync("src/ui/theme.css", "utf8");
  assert.doesNotMatch(theme.replace(/\/\*[\s\S]*?\*\//g, ""), /--(color|text-color)-kumo-[a-z-]+\s*:/, "theme.css overrides no Kumo colour token");
  for (const token of BRANDABLE_TOKENS)
    assert.ok(token.startsWith("--nathan-") || new RegExp(token + ":").test(kumo), token + " is a Kumo token or a Nathan plate token");
  assert.ok(isBrandableToken("--color-kumo-brand"));
  assert.ok(!isBrandableToken("--text-color-kumo-default") && !isBrandableToken("--color-kumo-focus"));
  assert.ok(contrast("#ffffff", "#056DFF") >= 4.5, "Kumo's own primary keeps its white text");
});

test("CLI-generated identity Worker configs build the UI assets from the repository root", async () => {
  const { createGeneratedConfig } = await import("../scripts/lib/wrangler.mjs");
  const path = await createGeneratedConfig({ name: "nath37", accountId: "a".repeat(32), hostname: "login.example.com",
    securityProfile: "business", database: { name: "nath37-auth" } }, "00000000-0000-0000-0000-000000000000");
  const generated = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(generated.assets, undefined, "no static-assets binding: the Worker serves its own UI assets");
  assert.deepEqual(generated.build, { command: "node scripts/build-ui.mjs", cwd: process.cwd() });
});

test("every Worker config builds the UI assets first, from the repository root", () => {
  // Wrangler resolves build.cwd against the directory it is invoked in, not the config file's, and
  // ForgeGraph deploys from the repository root: a cwd of "../.." broke the staging deploy.
  for (const path of ["wrangler.auth.jsonc", "wrangler.gateway.jsonc", "wrangler.installer.jsonc",
    "deploy/staging/wrangler.auth.jsonc", "deploy/production/wrangler.auth.jsonc",
    "deploy/insure-staging/wrangler.auth.jsonc", "deploy/insure-production/wrangler.auth.jsonc"]) {
    const text = readFileSync(path, "utf8");
    assert.ok(text.includes('"build": { "command": "node scripts/build-ui.mjs" }'), path);
    // The installer keeps its own static-assets binding, but only for sealed release files.
    if (path === "wrangler.installer.jsonc") assert.match(text, /"directory": "\.\/installer\/public"|"directory": "installer\/public"|installer\/public/, path);
    else assert.doesNotMatch(text, /"assets":/, path + " has no static-assets binding");
  }
});

// ---- NATH-37 security review hardening ---------------------------------------------------------

test("form-action refuses wildcard and non-DNS hosts", () => {
  for (const bad of ["https://*", "https://*.example", "https://a_b.example", "https://-x.example"])
    assert.throws(() => formActionSource(bad), /form-action/, bad);
  assert.equal(formActionSource("https://sp.example.com"), "https://sp.example.com");
  assert.equal(formActionSource("https://sp.example.com:8443"), "https://sp.example.com:8443");
});

test("the tag scanner fails closed on comment forms and elements browsers parse differently", () => {
  for (const html of ["<!--><img src=x>", "<!-- --!><img src=x>", "<!-- hi --><p>", "<noscript><a title=\"</noscript><img src=x>\">x</a></noscript>", "<noscript><noscript></noscript>",
    "<iframe></iframe>", "<xmp>x</xmp>", "<plaintext>"])
    assert.throws(() => rewriteTags(html, () => undefined), /Unexpected HTML comment|Refused element|Unterminated|Nested|Malformed/, html);
  for (const html of ["<!-- --><p>a</p>", "<!--$--><p>a</p><!--/$-->", "<title>a <b> c</title><p>x</p>", "<textarea><p></textarea>", "<noscript><button>Continue</button></noscript>"])
    assert.doesNotThrow(() => rewriteTags(html, () => undefined), html);
});

test("inline style declarations must balance brackets outside strings", () => {
  for (const bad of ["width:calc(1px", "background:url(a b", "width:calc(1px))", "grid-area:[a"])
    assert.throws(() => safeDeclarations(bad), /Unsafe inline style/, bad);
  assert.equal(safeDeclarations("width:calc(100% - (2px * 3));content:\")(\""), "width:calc(100% - (2px * 3));content:\")(\"");
});

test("page-supplied extra headers are an allowlist", () => {
  const csp = { nonce: "A".repeat(22) + "==", scripts: false };
  for (const name of ["Refresh", "Link", "Permissions-Policy", "Content-Disposition"])
    assert.throws(() => securityHeaders(csp, { [name]: "x" }), /does not allow/, name);
  assert.equal(securityHeaders(csp, { Vary: "Cookie" }).get("vary"), "Cookie");
});
