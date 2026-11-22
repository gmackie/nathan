/**
 * TOTP enrollment QR code (staging feedback 2026-11-22: "TOTP should show a QR code"). The security
 * page draws the code as inline SVG from a module matrix that this same-origin endpoint returns, so
 * the page CSP (img-src 'none', nonce-only scripts) stays unchanged and no third party sees the secret.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
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
  assert.match(html, /authenticatorAttachment=/);
  assert.match(html, /addPasskey\('cross-platform'/);
});
