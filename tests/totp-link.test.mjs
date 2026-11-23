import test from "node:test";
import assert from "node:assert/strict";
import { authenticatorLink } from "../src/auth/totp-link.mjs";
import { securityPage } from "../src/auth/security-ui.ts";

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
  assert.match(html, /<a id="totp-open" hidden>Add to built-in authenticator<\/a>/);
  assert.match(html, /<button id="totp-copy" type="button">Copy key<\/button>/);
  assert.ok(html.includes(authenticatorLink.toString()), "the guard is inlined into the page");
  // iOS routes otpauth: links to Apple Passwords, so the page must say so and offer Copy key first.
  assert.match(html, /On iPhone this always opens Apple Passwords/);
  assert.ok(html.indexOf('id="totp-copy"') < html.indexOf('id="totp-open"'), "Copy key comes before the built-in link");
  // The link starts without an href; only the guard's result is ever assigned to it.
  assert.doesNotMatch(html, /id="totp-open"[^>]*href=/);
});
