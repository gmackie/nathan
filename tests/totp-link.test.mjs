import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
import { authenticatorLink } from "../src/auth/totp-link.mjs";

// NATH-38: /security is a TSX page (node can't import TSX), so bundle it like ui-render.test.mjs.
await mkdir(".nathan/test-ui", { recursive: true });
const bundle = ".nathan/test-ui/security-page-totp.mjs";
await build({
  entryPoints: ["src/auth/security-ui.ts"], outfile: bundle, bundle: true, platform: "node", format: "esm",
  jsx: "automatic", packages: "external", logLevel: "error", logOverride: { "module-level-directive": "silent" }
});
const { securityPage } = await import(pathToFileURL(bundle).href + "?" + Date.now());

const uri = "otpauth://totp/gmacko:owner%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=gmacko&digits=6&period=30";

test("authenticatorLink passes a TOTP otpauth URI through unchanged", () => {
  assert.equal(authenticatorLink(uri), uri);
});

test("authenticatorLink refuses other schemes, HOTP, markup and oversized input", () => {
  for (const bad of [
    "javascript:alert(1)",
    "data:text/html,hi",
    "https://id.gmac.io/",
    "otpauth://hotp/gmacko:x?secret=AAAA&counter=0",
    'otpauth://totp/x?secret=A"onmouseover=1',
    "otpauth://totp/x?secret=A <b>",
    "otpauth://totp/" + "a".repeat(480),
    "",
    undefined,
    null,
    42
  ]) assert.equal(authenticatorLink(bad), null, String(bad));
});

test("the security page offers an app link and a copy button for same-device enrolment", async () => {
  const html = await securityPage("owner@example.com").text();
  const open = /<a [^>]*id="totp-open"[^>]*>([\s\S]*?)<\/a>/.exec(html);
  assert.ok(open, "the built-in authenticator link is rendered");
  assert.match(open[0], /\shidden=""/, "hidden until enrolment starts");
  assert.match(open[1], /Add to built-in authenticator/);
  const copy = /<button [^>]*id="totp-copy"[^>]*>([\s\S]*?)<\/button>/.exec(html);
  assert.ok(copy, "the Copy key button is rendered");
  assert.match(copy[0], /\stype="button"/);
  assert.match(copy[1], /Copy key/);
  // iOS routes otpauth: links to Apple Passwords, so the page must say so and offer Copy key first.
  assert.match(html, /On iPhone this always opens Apple Passwords/);
  assert.ok(html.indexOf('id="totp-copy"') < html.indexOf('id="totp-open"'), "Copy key comes before the built-in link");
  // The link starts without an href; only the guard's result is ever assigned to it.
  assert.doesNotMatch(open[0], /\shref=/);
});

test("the security island takes the link's href only from authenticatorLink()", () => {
  const panel = readFileSync("src/ui/pages/security/SecurityPanel.tsx", "utf8");
  assert.match(panel, /import \{ authenticatorLink \} from "\.\.\/\.\.\/\.\.\/auth\/totp-link\.mjs";/, "the guard is imported");
  assert.match(panel, /const openHref = totpUri \? authenticatorLink\(totpUri\) : null;/, "the guard computes the href");
  const link = /<LinkButton id="totp-open"[^>]*>/.exec(panel);
  assert.ok(link, "the link is a Kumo LinkButton");
  assert.match(link[0], /href=\{openHref \?\? undefined\}/, "its href is the guard's result, nothing else");
  assert.equal((panel.match(/href=/g) || []).length, 2, "only the guarded link and the static /studio link set an href");
  assert.match(panel, /<Link href="\/studio">/);
  // The guard itself reaches the island bundle unchanged.
  const manifest = JSON.parse(readFileSync("src/ui/generated/ui-manifest.json", "utf8"));
  const island = readFileSync(".nathan/ui-assets" + manifest.islands.security.src, "utf8");
  // The regular expression literal from src/auth/totp-link.mjs, byte for byte.
  const guard = /\/\^otpauth:\S*?\$\//.exec(authenticatorLink.toString());
  assert.ok(guard, "authenticatorLink has its otpauth://totp regular expression");
  assert.ok(island.includes(guard[0] + ".test("), "authenticatorLink's otpauth://totp guard is in the island bundle");
});
