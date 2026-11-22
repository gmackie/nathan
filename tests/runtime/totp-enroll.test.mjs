/**
 * TOTP enrollment end to end through the built Worker, exactly as /security does it: enable (no
 * password; Nathan's social and passkey users have none), read the otpauth URI, compute the current
 * code from its secret like an authenticator app, verify. Staging 2026-11-22: the owner's verify left
 * twoFactorEnabled = 0, and no test covered this path.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { authWorker, randomKey, insertSession } from "./helpers.mjs";

const HOST = "login.example.test", ORIGIN = "https://" + HOST, SECRET = randomKey() + randomKey();
let mf, db, member;

function base32(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "", out = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) bits += A.indexOf(c).toString(2).padStart(5, "0");
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, { period = 30, digits = 6, at = Date.now() } = {}) {
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / period)));
  const h = createHmac("sha1", base32(secret)).update(counter).digest(), o = h[h.length - 1] & 15;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 10 ** digits)).padStart(digits, "0");
}

before(async () => {
  mf = await authWorker(HOST, { BETTER_AUTH_SECRET: SECRET, NATHAN_INSTANCE_NAME: "gmacko" });
  db = await mf.getD1Database("DB");
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (\'u-1\',\'u\',\'user@example.test\',1,?,?)').bind(now, now).run();
  member = await insertSession(db, SECRET, "u-1");
});
after(() => mf?.dispose());

const api = (path, body) => mf.dispatchFetch(ORIGIN + "/api/auth" + path, { method: "POST", body: JSON.stringify(body),
  headers: { Cookie: member.cookie, Origin: ORIGIN, "Content-Type": "application/json" } });

test("a passwordless signed-in user enrolls TOTP from /security's requests and verifies the current code", async () => {
  const enabled = await api("/two-factor/enable", { method: "totp" });
  const body = await enabled.json();
  assert.equal(enabled.status, 200, JSON.stringify(body));
  const uri = new URL(body.totpURI);
  assert.equal(uri.protocol, "otpauth:");
  // Authenticator apps show the issuer: the instance name, never Better Auth's default.
  assert.equal(uri.searchParams.get("issuer"), "gmacko");
  assert.match(decodeURIComponent(body.totpURI), /^otpauth:\/\/totp\/gmacko:/);
  const params = uri.searchParams;
  const code = totp(params.get("secret"), { period: Number(params.get("period") || 30), digits: Number(params.get("digits") || 6) });
  const verified = await api("/two-factor/verify-totp", { code, trustDevice: false });
  assert.equal(verified.status, 200, await verified.clone().text());
  const row = await db.prepare('SELECT "twoFactorEnabled" FROM "user" WHERE "id"=\'u-1\'').first();
  assert.equal(row.twoFactorEnabled, 1);
});
