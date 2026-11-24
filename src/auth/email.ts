import type { AuthEnv } from "./env";
import { signInCodeMail } from "./email-otp-policy.mjs";
import { instanceName } from "./passkey-config.mjs";

/** The one way Nathan sends mail (Resend). Fails closed: without configuration nothing is dropped silently. */
async function deliver(env: AuthEnv, to: string, subject: string, text: string): Promise<void> {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) {
    throw new Error("Email delivery is not configured; refusing to silently drop an authentication email.");
  }
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], subject, text })
  });
  // The status only: the request carried the code or link, and the response may echo it.
  if (!response.ok) throw new Error("Authentication email delivery failed: " + response.status);
}

export async function sendAuthEmail(env: AuthEnv, to: string, subject: string, url: string): Promise<void> {
  await deliver(env, to, subject, "Use this one-time link to continue: " + url + "\n\nIf you did not request this, ignore it.");
}

/** NATH-49: a sign-in code, with the host that asked for it. */
export async function sendSignInCode(env: AuthEnv, to: string, code: string): Promise<void> {
  const { subject, text } = signInCodeMail({ code, host: new URL(env.NATHAN_ISSUER).host, appName: instanceName(env) });
  await deliver(env, to, subject, text);
}
