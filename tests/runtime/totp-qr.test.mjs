/**
 * TOTP enrollment QR code (staging feedback 2026-11-22: "TOTP should show a QR code"). The security
 * page draws the code as inline SVG from a module matrix that this same-origin endpoint returns, so
 * the page CSP (img-src 'none', nonce-only scripts) stays unchanged and no third party sees the secret.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { authWorker, randomKey, insertSession } from "./helpers.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST, SECRET = randomKey() + randomKey();
const URI = "otpauth://totp/Nathan:user%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Nathan";
let mf, db, member;

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET });
  db = await mf.getD1Database("DB");
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u-1\',\'u\',\'user@example.test\',1,?,?)').bind(now, now).run();
  member = await insertSession(db, SECRET, "u-1");
});
after(() => mf?.dispose());

const qr = (body, { cookie = member.cookie, origin = ORIGIN, site = "same-origin" } = {}) =>
  mf.dispatchFetch(ORIGIN + "/security/api/totp-qr", { method: "POST", body: JSON.stringify(body),
    headers: { Cookie: cookie, Origin: origin, "Sec-Fetch-Site": site, "Content-Type": "application/json" } });

test("a signed-in user gets a square QR module matrix for an otpauth://totp URI, never cached", async () => {
  const response = await qr({ uri: URI });
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  const { size, rows } = await response.json();
  assert.ok(Number.isInteger(size) && size >= 21 && size <= 177, "QR version size");
  assert.equal(rows.length, size);
  assert.ok(rows.every(r => r.length === size && /^[01]+$/.test(r)));
  // Finder pattern: the top-left 7x7 corner starts with a full dark row.
  assert.equal(rows[0].slice(0, 7), "1111111");
});

test("the endpoint refuses anonymous, cross-origin and non-TOTP requests", async () => {
  assert.equal((await qr({ uri: URI }, { cookie: "" })).status, 401);
  assert.equal((await qr({ uri: URI }, { origin: "https://evil.example" })).status, 403);
  assert.equal((await qr({ uri: URI }, { site: "cross-site" })).status, 403);
  for (const uri of ["https://example.test/", "otpauth://hotp/x?secret=A", "otpauth://totp/" + "a".repeat(600), 42])
    assert.equal((await qr({ uri })).status, 400, String(uri).slice(0, 40));
});

test("the security page offers a QR area, the secret for manual entry and a security-key enrollment", async () => {
  const html = await (await mf.dispatchFetch(ORIGIN + "/security", { headers: { Cookie: member.cookie } })).text();
  assert.match(html, /id="totp-qr"/);
  assert.match(html, /id="totp-secret"/);
  assert.match(html, /id="security-key-add"/);
  // NATH-38: the passkey code lives in the hashed `security` island the Worker serves.
  const src = /<script type="module" src="(\/__nathan\/ui\/security-[A-Za-z0-9_-]+\.js)"/.exec(html)?.[1];
  assert.ok(src, "the page loads the security island");
  const island = await (await mf.dispatchFetch(ORIGIN + src)).text();
  assert.match(island, /authenticatorAttachment=/);
  assert.match(island, /"cross-platform"/, "the YubiKey button asks for a cross-platform authenticator");
  assert.match(island, /\/security\/api\/totp-qr/);
});

test("GET /security is a renderPage page: nonce'd SRI island script, no inline style or script, same-origin referrer", async () => {
  const response = await mf.dispatchFetch(ORIGIN + "/security", { headers: { Cookie: member.cookie } });
  assert.equal(response.status, 200);
  const html = await response.text();
  const csp = response.headers.get("content-security-policy");
  const nonce = /'nonce-([^']+)'/.exec(csp)[1];
  assert.equal(csp,
    "default-src 'none'; connect-src 'self'; img-src 'none'; style-src 'self' 'nonce-" + nonce + "'; script-src 'self' 'nonce-" + nonce + "'; " +
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  for (const [name, value] of [["cache-control", "no-store"], ["referrer-policy", "same-origin"], ["x-content-type-options", "nosniff"],
    ["x-frame-options", "DENY"], ["cross-origin-opener-policy", "same-origin"], ["strict-transport-security", "max-age=31536000"]])
    assert.equal(response.headers.get(name), value, name);
  assert.doesNotMatch(html, /\sstyle=/, "no style attributes");
  assert.doesNotMatch(html, /<img\b/i, "no img; the QR is inline SVG");
  assert.match(html, /data-nathan-island="security"/);
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.ok(scripts.length >= 2);
  for (const [, attrs, body] of scripts) {
    assert.ok(attrs.includes(' nonce="' + nonce + '"'), "every script carries the nonce: " + attrs);
    if (/type="importmap"/.test(attrs)) continue;
    assert.equal(body, "", "no inline script code");
    const src = / src="([^"]+)"/.exec(attrs)[1], integrity = / integrity="(sha384-[^"]+)"/.exec(attrs)?.[1];
    assert.ok(integrity, "the island script carries SRI");
    const bytes = Buffer.from(await (await mf.dispatchFetch(ORIGIN + src)).arrayBuffer());
    assert.equal("sha384-" + createHash("sha384").update(bytes).digest("base64"), integrity, src + " matches its SRI");
  }
  const codeInput = /<input [^>]*id="totp-code"[^>]*>/.exec(html)?.[0] ?? "";
  assert.match(codeInput, /\sinputmode="numeric"/i);
  assert.match(codeInput, /\sautocomplete="one-time-code"/i);
  // The signed-in email is escaped page text.
  assert.match(html, /Signed in as <strong>user@example\.test<\/strong>/);
  // Without a session, /security still redirects to sign-in.
  const anonymous = await mf.dispatchFetch(ORIGIN + "/security", { redirect: "manual" });
  assert.equal(anonymous.status, 302);
  assert.equal(anonymous.headers.get("location"), ORIGIN + "/sign-in");
});
