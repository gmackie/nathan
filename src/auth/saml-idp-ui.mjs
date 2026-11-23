/**
 * NATH-12 pages for Nathan as a SAML IdP: the auto-POST page that delivers a signed Response to an
 * SP's ACS URL, the IdP-initiated confirmation page, error pages, and the Identity Studio section.
 * Every value is HTML-escaped; the Studio script writes with textContent only.
 * Keep the Studio strings free of backticks and "${" because ui.ts embeds them in a template.
 */
const html = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const nonce = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
const STYLE = "body{font:16px system-ui;background:#10121a;color:#f2f3fa;margin:0;min-height:100vh;display:grid;place-items:center}" +
  "main{width:min(480px,94vw);padding:32px;background:#1b1e2a;border:1px solid #35394b;border-radius:16px}p{color:#b6bfce;line-height:1.5}" +
  "button,a.button{background:#ef9028;color:#171717;border:0;border-radius:8px;padding:13px 16px;cursor:pointer;font:inherit;text-decoration:none;display:inline-block}" +
  "button.secondary{background:transparent;color:#f2f3fa;border:1px solid #35394b;margin-left:8px}";

function page(title, body, { formAction = "'none'", script = "", status = 200, n = nonce() } = {}) {
  return new Response("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<meta name=\"referrer\" content=\"same-origin\"><title>" + html(title) + " · Nathan</title><style nonce=\"" + n + "\">" + STYLE + "</style></head><body><main>" +
    body + "</main>" + (script ? "<script nonce=\"" + n + "\">" + script + "</script>" : "") + "</body></html>", {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Pragma": "no-cache",
      "Content-Security-Policy": "default-src 'none'; style-src 'nonce-" + n + "'; script-src 'nonce-" + n + "'; form-action " + formAction +
        "; base-uri 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "same-origin",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Strict-Transport-Security": "max-age=31536000"
    }
  });
}

/**
 * Delivers a signed SAML Response with the HTTP-POST binding. The form posts only to the exact,
 * registered ACS URL; CSP form-action allows only that URL's origin, and the Referrer-Policy keeps
 * Nathan's URLs from the SP.
 * @param {{ acsUrl: string, samlResponse: string, relayState: string|null, spName: string }} input
 */
export function autoPostPage({ acsUrl, samlResponse, relayState, spName }) {
  const origin = new URL(acsUrl).origin;
  return page("Signing in", "<h1>Signing you in to " + html(spName) + "</h1>" +
    "<form method=\"post\" action=\"" + html(acsUrl) + "\" id=\"saml-post\">" +
    "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + html(samlResponse) + "\">" +
    (relayState !== null ? "<input type=\"hidden\" name=\"RelayState\" value=\"" + html(relayState) + "\">" : "") +
    "<noscript><p>JavaScript is off. Continue to send your sign-in to " + html(spName) + ".</p></noscript>" +
    "<button type=\"submit\">Continue</button></form>",
  { formAction: origin, script: "document.getElementById('saml-post').submit();" });
}

/** A refusal shown by Nathan. Nothing is sent to the service provider. */
export function idpErrorPage(title, message, { status = 403, signIn = false } = {}) {
  return page(title, "<h1>" + html(title) + "</h1><p>" + html(message) + "</p>" +
    (signIn ? "<p><a class=\"button\" href=\"/sign-in\">Sign in to Nathan</a></p>" : ""), { status });
}

/** IdP-initiated sign-in needs an explicit same-origin POST, so a cross-site link cannot log anyone in. */
export function idpInitiatedPage({ spId, spName, email }) {
  return page("Continue to " + spName, "<h1>Continue to " + html(spName) + "</h1><p>Signed in to Nathan as " + html(email) + ".</p>" +
    "<form method=\"post\" action=\"/saml/idp/start/" + html(spId) + "\"><button type=\"submit\">Sign in to " + html(spName) + "</button></form>",
  { formAction: "'self'" });
}

/**
 * Asked before answering an unsigned AuthnRequest with a session that already existed: anyone can
 * send the browser such a request, so the user confirms on Nathan's own page. Continue and Cancel
 * are a same-origin POST carrying the single-use token; no script, no framing.
 * @param {{ spName: string, email: string, acsHost: string, token: string }} input
 */
export function ssoConfirmPage({ spName, email, acsHost, token }) {
  return page("Continue to " + spName, "<h1>Continue to " + html(spName) + " as " + html(email) + "?</h1>" +
    "<p>" + html(spName) + " asked Nathan to sign you in. Nathan will send your sign-in to " + html(acsHost) + ".</p>" +
    "<p>If you did not just start signing in to " + html(spName) + ", choose Cancel.</p>" +
    "<form method=\"post\" action=\"/saml/idp/continue\"><input type=\"hidden\" name=\"confirm\" value=\"" + html(token) + "\">" +
    "<button type=\"submit\" name=\"action\" value=\"continue\">Continue</button>" +
    "<button type=\"submit\" name=\"action\" value=\"cancel\" class=\"secondary\">Cancel</button></form>",
  { formAction: "'self'" });
}
