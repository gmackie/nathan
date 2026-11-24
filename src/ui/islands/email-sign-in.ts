import { signedOAuthQuery } from "../../auth/oauth-query.mjs";

const requestForm = document.querySelector<HTMLFormElement>("#request-email")!;
const verifyForm = document.querySelector<HTMLFormElement>("#verify-email")!;
const email = document.querySelector<HTMLInputElement>("#email-address")!;
const code = document.querySelector<HTMLInputElement>("#email-code")!;
const message = document.querySelector<HTMLElement>("#email-status")!;
let secondFactor = false;
let flowId: string | undefined;

async function submit(form: HTMLFormElement, action: string, body: object) {
  const button = form.querySelector("button")!;
  button.disabled = true;
  try {
    const r = await fetch("/sign-in/email/" + action, { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const result = await r.json() as { flowId?: string; message?: string; error?: string; twoFactorRedirect?: boolean; url?: string };
    if (!r.ok) throw Error(result.error || "Unable to sign in. Try again.");
    if (result.url) { location.assign(result.url); return; }
    if (result.flowId) flowId = result.flowId;
    secondFactor = Boolean(result.twoFactorRedirect);
    requestForm.hidden = secondFactor;
    verifyForm.hidden = false;
    code.value = "";
    document.querySelector("#code-label")!.textContent = secondFactor ? "Authenticator code" : "Email code";
    message.textContent = result.message || "Enter the code from your authenticator.";
    code.focus();
  } catch (e) {
    message.textContent = e instanceof Error ? e.message : "Unable to sign in. Try again.";
  } finally { button.disabled = false; }
}
requestForm.addEventListener("submit", event => {
  event.preventDefault();
  void submit(requestForm, "request", { email: email.value, oauth_query: signedOAuthQuery(location.search) });
});
verifyForm.addEventListener("submit", event => {
  event.preventDefault();
  void submit(verifyForm, "verify", secondFactor ? { flowId, totp: code.value } : { flowId, code: code.value });
});

// A mail scanner's GET has no credential. A browser must have initiated this particular request.
if (location.hash) {
  const match = /^#([A-Za-z0-9_-]{43})\.(\d{6})$/.exec(location.hash);
  history.replaceState(null, "", location.pathname + location.search);
  if (match) {
    flowId = match[1];
    void submit(verifyForm, "verify", { flowId, code: match[2] });
  }
}
