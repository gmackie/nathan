/**
 * NATH-52 in workerd: email sign-in over the pinned NathanVerifier binding.
 * AUTH_MODE must be single-app, the binding must be pinned, and the answer is
 * the person only: no session cookie, token, or admin role.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { bundle, migrate, randomKey, start, COMPAT } from "./helpers.mjs";

const HOST = "login.example.test";
const SECRET = randomKey() + randomKey();
const RESEND = { RESEND_API_KEY: "re_test_key", EMAIL_FROM: "Nathan <login@example.test>" };

const PROBE = 'export default { async fetch(request, env) {\n' +
  '  const { method, args } = await request.json();\n' +
  '  try { return Response.json({ ok: true, result: await env.NATHAN[method](...args) }); }\n' +
  '  catch (error) { return Response.json({ ok: false, error: String(error && error.message || error) }); }\n' +
  '} };';

const mails = [];
async function outbound(request) {
  if (request.url === "https://api.resend.com/emails") {
    mails.push(JSON.parse(await request.text()));
    return Response.json({ id: "mail-" + mails.length });
  }
  return new Response("unexpected outbound " + request.url, { status: 599 });
}

function auth(name, extra) {
  return {
    name, modules: true, ...COMPAT, scriptPath: bundle("auth"),
    d1Databases: { DB: name + "-db" },
    durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
    outboundService: outbound,
    bindings: {
      NATHAN_ISSUER: "https://" + HOST, NATHAN_ADMIN_EMAILS: "admin@example.test",
      NATHAN_SECURITY_PROFILE: "business", NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_INSTALL_ACTIVE: "true",
      NATHAN_MCP_WRITE_ENABLED: "false", NATHAN_REALM_APEX: "", ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false",
      NATHAN_ADMIN_STEPUP_REQUIRED: "true", ENABLE_EMAIL_OTP: "true", BETTER_AUTH_SECRET: SECRET,
      NATHAN_CONFIG_KEY: randomKey(), NATHAN_INSTANCE_NAME: "Example", ...RESEND, ...extra
    }
  };
}
const probe = (name, service, props) => ({
  name, modules: true, ...COMPAT, script: PROBE,
  serviceBindings: { NATHAN: { name: service, entrypoint: "NathanVerifier", ...(props ? { props } : {}) } }
});

let on, off;
before(async () => {
  on = await start({
    workers: [
      probe("app", "auth-on", { applicationId: "insure" }),
      probe("unpinned", "auth-on"),
      auth("auth-on", { AUTH_MODE: "single-app" })
    ]
  });
  off = await start({
    workers: [
      probe("app-off", "auth-off", { applicationId: "insure" }),
      auth("auth-off", {})
    ]
  });
  for (const [mf, worker] of [[on, "auth-on"], [off, "auth-off"]]) {
    const db = await mf.getD1Database("DB", worker);
    for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort())
      await migrate(db, "migrations/" + file);
  }
  const db = await on.getD1Database("DB", "auth-on");
  const now = new Date().toISOString();
  await db.prepare('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,1,?,?)')
    .bind("u-member", "Member", "member@example.test", now, now).run();
});
after(async () => { await on?.dispose(); await off?.dispose(); });

async function call(mf, worker, method, ...args) {
  const response = await (await mf.getWorker(worker)).fetch("https://probe.internal/", {
    method: "POST", body: JSON.stringify({ method, args })
  });
  return response.json();
}
const settle = () => new Promise(resolve => setTimeout(resolve, 50));
async function codeFor(email) {
  for (let i = 0; i < 40 && !mails.some(mail => mail.to[0] === email); i++) await settle();
  const mail = mails.filter(mail => mail.to[0] === email).at(-1);
  assert.ok(mail, "a code was mailed to " + email);
  return /\b(\d{6})\b/.exec(mail.text)[1];
}

test("without AUTH_MODE=single-app the pinned binding does not sign anyone in", async () => {
  const before = mails.length;
  const answer = await call(off, "app-off", "beginEmailSignIn", { email: "member@example.test", ip: "203.0.113.10" });
  assert.equal(answer.ok, true, answer.error);
  assert.deepEqual(answer.result, { ok: false, error: "unavailable" });
  await settle();
  assert.equal(mails.length, before);
});

test("an unpinned binding is refused even when the instance is single-app", async () => {
  const answer = await call(on, "unpinned", "beginEmailSignIn", { email: "member@example.test", ip: "203.0.113.11" });
  assert.equal(answer.ok, true, answer.error);
  assert.deepEqual(answer.result, { ok: false, error: "unavailable" });
});

test("a pinned app gets a subject and email, and nothing that could administer", async () => {
  const begun = await call(on, "app", "beginEmailSignIn", { email: "member@example.test", ip: "203.0.113.12" });
  assert.equal(begun.ok, true, begun.error);
  assert.deepEqual(begun.result, { ok: true });
  const code = await codeFor("member@example.test");
  const finished = await call(on, "app", "finishEmailSignIn", { email: "member@example.test", code, ip: "203.0.113.12" });
  assert.equal(finished.ok, true, finished.error);
  assert.equal(finished.result.ok, true);
  assert.equal(finished.result.sub, "u-member");
  assert.equal(finished.result.email, "member@example.test");
  assert.equal(finished.result.name, "Member");
  assert.deepEqual(Object.keys(finished.result).sort(), ["email", "name", "ok", "sub"]);
  const wrong = await call(on, "app", "finishEmailSignIn", { email: "member@example.test", code: "000000", ip: "203.0.113.13" });
  assert.equal(wrong.result.ok, false);
  assert.equal(wrong.result.sub, undefined);
});
