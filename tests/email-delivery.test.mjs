import assert from "node:assert/strict";
import test from "node:test";
import * as mail from "../src/auth/email.ts";

const sender = "sign-in@mail.staging.educateos.io";
const teacher = "teacher@example.test";
const link = "https://staging.educateos.io/sign-in/email#fixture.123456";
const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aB9sAAAAASUVORK5CYII=";

test("the Cloudflare binding delivers the sign-in code and matching inline image", async t => {
  const send = t.mock.fn(async () => ({ messageId: "email-id" }));
  const fetch = t.mock.method(globalThis, "fetch", () => assert.fail("Unexpected HTTP delivery"));
  const env = {
    SEND_EMAIL: { send },
    EMAIL_FROM: sender,
    NATHAN_INSTANCE_NAME: "EducateOS",
    NATHAN_EMAIL_LOGOS: JSON.stringify({ school: png }),
  };
  assert.equal(mail.emailDeliveryConfigured(env), true);
  await mail.sendSignInEmail(env, teacher, "123456", link, {
    name: "EducateOS",
    metadata: JSON.stringify({ appearance: { logo: "school" } }),
  });
  assert.equal(fetch.mock.callCount(), 0);
  assert.equal(send.mock.callCount(), 1);
  const [message] = send.mock.calls[0].arguments;
  assert.deepEqual(message.from, { name: "EducateOS", email: sender });
  assert.equal(message.to, teacher);
  assert.equal(message.subject, "Sign in to EducateOS");
  assert.ok(message.text.includes(link));
  assert.match(message.text, /123456/);
  assert.match(message.html, /src="cid:school"/);
  assert.deepEqual(message.attachments, [{
    disposition: "inline", contentId: "school", filename: "school.png", type: "image/png", content: png,
  }]);
});

test("a Cloudflare delivery failure is propagated without sending a second message", async t => {
  const fetch = t.mock.method(globalThis, "fetch", () => assert.fail("Unexpected HTTP delivery"));
  const send = async () => { throw Error("Provider refused delivery to " + teacher); };
  const env = { EMAIL_FROM: sender, RESEND_API_KEY: "fixture-unused", SEND_EMAIL: { send } };
  await assert.rejects(mail.sendAuthEmail(env, teacher, "Verify your email", link), {
    message: "Authentication email delivery failed",
  });
  assert.equal(fetch.mock.callCount(), 0);
});

test("Resend remains available with its existing formatted From address", async t => {
  const fetch = t.mock.method(globalThis, "fetch", async () => new Response(null, { status: 200 }));
  const env = { EMAIL_FROM: "Nathan <test@example.test>", RESEND_API_KEY: "fixture-key" };
  assert.equal(mail.emailDeliveryConfigured(env), true);
  assert.equal(mail.emailDeliveryConfigured({ EMAIL_FROM: env.EMAIL_FROM }), false);
  assert.equal(mail.emailDeliveryConfigured({ SEND_EMAIL: { send() {} } }), false);
  await mail.sendAuthEmail(env, teacher, "Verify your email", link);
  assert.equal(fetch.mock.callCount(), 1);
  const [url, request] = fetch.mock.calls[0].arguments;
  assert.equal(url, "https://api.resend.com/emails");
  assert.equal(request.redirect, "manual");
  assert.deepEqual(JSON.parse(request.body), {
    from: env.EMAIL_FROM, to: [teacher], subject: "Verify your email",
    text: `Use this one-time link to continue: ${link}\n\nIf you did not request this, ignore it.`,
  });
});
