import type { AuthEnv } from "./env";

export async function sendAuthEmail(env: AuthEnv, to: string, subject: string, url: string): Promise<void> {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) {
    throw new Error("Email delivery is not configured; refusing to silently drop an authentication email.");
  }
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: env.EMAIL_FROM,
      to: [to],
      subject,
      text: "Use this one-time link to continue: " + url + "\n\nIf you did not request this, ignore it."
    })
  });
  if (!response.ok) throw new Error("Authentication email delivery failed: " + response.status);
}
