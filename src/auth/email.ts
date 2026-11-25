import { resolveAppearance } from "../ui/appearance";
import { escapeHtml } from "../ui/csp-styles";
import type { AuthEnv } from "./env";
import { instanceName } from "./passkey-config.mjs";

async function deliver(env: AuthEnv, to: string, message: { subject: string; text: string; html?: string; attachments?: object[] }) {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) throw new Error("Email delivery is not configured");
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST", redirect: "manual",
    headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], ...message })
  });
  if (!response.ok) throw new Error("Authentication email delivery failed: " + response.status);
}

export function sendAuthEmail(env: AuthEnv, to: string, subject: string, url: string): Promise<void> {
  return deliver(env, to, { subject, text: "Use this one-time link to continue: " + url + "\n\nIf you did not request this, ignore it." });
}

export type EmailClient = { name: string | null; metadata: string | null };

/** Older registrations can have arbitrary OAuth metadata. Only validated appearance and
 * operator-installed PNGs reach the message. An unusable optional asset falls back to text. */
function emailBrand(env: AuthEnv, client: EmailClient | null) {
  const registered = client?.name?.trim();
  let name = registered && /^[^\p{C}<>]{1,100}$/u.test(registered) ? registered : instanceName(env);
  let logo: string | null = null;
  try {
    const app = client?.metadata ? JSON.parse(client.metadata)?.appearance : undefined;
    const appearance = resolveAppearance(env.NATHAN_APPEARANCE ? JSON.parse(env.NATHAN_APPEARANCE) : undefined, app);
    if (appearance.wordmark && (app?.wordmark || !registered)) name = appearance.wordmark;
    logo = appearance.logo;
    const logos = logo && env.NATHAN_EMAIL_LOGOS ? JSON.parse(env.NATHAN_EMAIL_LOGOS) : null;
    const png = logo && logos && Object.hasOwn(logos, logo) ? logos[logo] : null;
    if (typeof png === "string" && png.length <= 128 * 1024 && /^iVBORw0KGgo[A-Za-z0-9+/]+=*$/.test(png))
      return { name, logo, png };
  } catch { /* Invalid stored branding must not suppress authentication mail. */ }
  return { name, logo: null, png: null };
}

export async function sendSignInEmail(env: AuthEnv, to: string, code: string, url: string, client: EmailClient | null) {
  const { name, logo, png } = emailBrand(env, client);
  const instructions = "Open the link in the browser where you requested it, or enter the code there. Both expire in 5 minutes and work once.";
  return deliver(env, to, {
    subject: "Sign in to " + name,
    text: "Sign in to " + name + "\n\n" + code + "\n\n" + url + "\n\n" + instructions + "\n\nIf you did not request this, ignore it.",
    html: (png ? '<img alt="" width="64" src="cid:' + logo + '">' : "") +
      "<h1>Sign in to " + escapeHtml(name) + "</h1><p>Your code is <strong>" + code + '</strong>.</p><p><a href="' +
      escapeHtml(url) + '">Sign in to ' + escapeHtml(name) + "</a></p><p>" + instructions + "</p><p>If you did not request this, ignore it.</p>",
    ...(png ? { attachments: [{ filename: logo + ".png", content: png, content_type: "image/png", content_id: logo }] } : {})
  });
}
