/**
 * NATH-38: the sign-in page's behaviour, moved verbatim from the inline script signInPage() used to
 * carry (src/auth/ui.ts before K1) into a hashed, SRI-pinned module. Plain script, no React, so it
 * does not load the vendor chunk.
 *
 * - Every sign-in request carries the signed `oauth_query` (src/auth/oauth-query.mjs) derived from
 *   this page's URL, so Better Auth resumes an app's authorization instead of landing on "/".
 * - After a sign-in, `land(d)` follows the resumed authorization (`d.url`) when Better Auth returns one.
 * - Only same-origin fetches with credentials: 'same-origin'; messages are written with textContent.
 * - The server renders every button disabled; this script enables them, so nothing looks usable
 *   without it and no form can be submitted natively.
 */
import { signedOAuthQuery } from "../../auth/oauth-query.mjs";

type Json = Record<string, any>;

const root = document.querySelector<HTMLElement>("[data-nathan-sign-in]");
if (root) init(root);

function init(root: HTMLElement) {
  const errorBox = root.querySelector<HTMLElement>("[data-sign-in-error]");
  const noticeBox = root.querySelector<HTMLElement>("[data-sign-in-notice]");
  const say = (box: HTMLElement | null, other: HTMLElement | null, message: string) => {
    if (other) other.hidden = true;
    if (!box) return;
    const text = box.querySelector<HTMLElement>("[data-text]") ?? box;
    text.textContent = message;
    box.hidden = false;
  };
  const fail = (e: unknown) => say(errorBox, noticeBox, e instanceof Error ? e.message : "Authentication failed");
  const notice = (message: string) => say(noticeBox, errorBox, message);

  // An app's /oauth2/authorize sent the browser here with a signed query; every sign-in request
  // carries it so Better Auth resumes that authorization (back to the app) instead of landing on "/".
  const oauthQuery = signedOAuthQuery(location.search);
  const withOAuth = (b: Json): Json => (oauthQuery ? { ...b, oauth_query: oauthQuery } : b);
  // After a sign-in, follow the resumed authorization when Better Auth returns one.
  const landingPage = root.hasAttribute("data-passkey-setup") ? "/security?setup=admin#passkeys-section" : "/";
  const land = (d: Json | null | undefined) => location.assign(d && typeof d.url === "string" && d.url ? d.url : landingPage);
  const unwrap = (x: Json) => (x && x.data) || x;

  async function request(path: string, payload: Json): Promise<Json> {
    const res = await fetch("/api/auth" + path, {
      method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify(payload)
    });
    const body = await res.json().catch(() => ({})) as Json;
    if (!res.ok) throw Error(body.message || body.error || "Authentication failed");
    return unwrap(body);
  }

  const field = (form: HTMLFormElement, name: string) => {
    const el = form.elements.namedItem(name);
    return el instanceof HTMLInputElement ? el.value : "";
  };
  const onSubmit = (selector: string, handler: (form: HTMLFormElement) => Promise<void>) => {
    const form = root.querySelector<HTMLFormElement>(selector);
    if (!form) return;
    form.addEventListener("submit", event => {
      event.preventDefault();
      handler(form).catch(fail);
    });
  };

  for (const button of Array.from(root.querySelectorAll<HTMLButtonElement>("button[data-provider]"))) {
    button.addEventListener("click", () => {
      (async () => {
        const d = await request("/sign-in/social", withOAuth({ provider: button.dataset.provider, callbackURL: landingPage, errorCallbackURL: "/sign-in" }));
        if (!d.url) throw Error("No OAuth redirect URL");
        location.assign(d.url);
      })().catch(fail);
    });
  }

  onSubmit("form[data-password]", async form => {
    const d = await request("/sign-in/email", withOAuth({ email: field(form, "email"), password: field(form, "password") }));
    if (d.twoFactorRedirect) {
      const twoFactor = root.querySelector<HTMLElement>("form[data-two-factor]");
      if (twoFactor) {
        twoFactor.hidden = false;
        twoFactor.querySelector<HTMLInputElement>("input[name=code]")?.focus();
      }
      notice("Enter the code from your authenticator to finish signing in.");
    } else land(d);
  });

  onSubmit("form[data-two-factor]", async form => {
    land(await request("/two-factor/verify-totp", withOAuth({ code: field(form, "code"), trustDevice: false })));
  });

  onSubmit("form[data-sso]", async form => {
    // Nathan routes the email domain to its enabled SAML or verified OIDC connection.
    const res = await fetch("/sign-in/sso/start", {
      method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
      body: JSON.stringify(withOAuth({ email: field(form, "email") }))
    });
    const d = unwrap(await res.json().catch(() => ({})) as Json);
    if (!res.ok) throw Error(d.error || d.message || "SSO provider unavailable");
    if (!d.url) throw Error("SSO provider unavailable");
    location.assign(d.url);
  });

  const decode = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  const encode = (b: ArrayBuffer) => {
    let s = "";
    for (const x of new Uint8Array(b)) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  root.querySelector<HTMLButtonElement>("button[data-passkey]")?.addEventListener("click", () => {
    (async () => {
      if (!window.PublicKeyCredential) throw Error("Passkeys are unavailable in this browser");
      const optRes = await fetch("/api/auth/passkey/generate-authenticate-options", { credentials: "same-origin" });
      const options: Json = await optRes.json();
      if (!optRes.ok) throw Error("Passkey challenge unavailable");
      const publicKey = unwrap(options).publicKey || unwrap(options);
      publicKey.challenge = decode(publicKey.challenge);
      if (publicKey.allowCredentials) publicKey.allowCredentials = publicKey.allowCredentials.map((c: Json) => ({ ...c, id: decode(c.id) }));
      const cred = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
      if (!cred) throw Error("Passkey authentication cancelled");
      const r = cred.response as AuthenticatorAssertionResponse;
      const response = {
        id: cred.id, rawId: encode(cred.rawId), type: "public-key",
        response: {
          clientDataJSON: encode(r.clientDataJSON), authenticatorData: encode(r.authenticatorData), signature: encode(r.signature),
          userHandle: r.userHandle ? encode(r.userHandle) : undefined
        },
        clientExtensionResults: cred.getClientExtensionResults()
      };
      land(await request("/passkey/verify-authentication", withOAuth({ response })));
    })().catch(fail);
  });

  for (const button of Array.from(root.querySelectorAll<HTMLButtonElement>("button[data-needs-script]"))) enable(button);
}

/** Kumo renders a disabled Button with static disabled-look classes; drop them with the attribute. */
function enable(button: HTMLButtonElement) {
  button.disabled = false;
  button.classList.remove("cursor-not-allowed", "opacity-50");
}
