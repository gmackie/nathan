import test from "node:test";
import assert from "node:assert/strict";
import { Script } from "node:vm";
import { signInPage, consentPage, studioPage } from "../src/auth/ui.ts";
import { securityPage } from "../src/auth/security-ui.ts";
import { installerPage } from "../src/installer/ui.ts";

/** Every inline script must at least parse, or no button on the page works. */
function assertScriptsParse(name, html) {
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  for (const [i, source] of scripts.entries()) {
    assert.doesNotThrow(() => new Script(source, { filename: name + "#script" + i }), name + " script " + i + " must parse");
  }
  return scripts.length;
}

test("Identity Studio, sign-in, consent, security and installer scripts parse", async () => {
  const pages = {
    studio: await studioPage("admin@example.com").text(),
    signIn: await signInPage(["google", "github"], true, true).text(),
    consent: await consentPage(true, "Example app", "openid profile email").text(),
    security: await securityPage("admin@example.com").text(),
    installer: installerPage("bm9uY2U=")
  };
  let total = 0;
  for (const [name, html] of Object.entries(pages)) total += assertScriptsParse(name, html);
  assert.ok(total >= 3, "expected inline scripts on the interactive pages");
});
