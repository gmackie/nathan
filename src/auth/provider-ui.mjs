/** @param {string} s */
const escape = (s) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

/** Result of a Studio test sign-in. Static HTML, no script. */
/**
 * @param {boolean} ok
 * @param {string | null} provider
 * @param {string} email
 * @param {boolean} [adminVerified] the account that signed in is a current Nathan administrator
 * @returns {Response}
 */
export function providerTestResultPage(ok, provider, email, adminVerified = false) {
  const title = ok ? "Test sign-in succeeded" : "Test sign-in not recorded";
  const body = ok
    ? "<p>Nathan received a successful <strong>" + escape(provider ?? "") + "</strong> sign-in and recorded the test against the provider's current credentials.</p>" +
      (adminVerified
        ? "<p>You signed in as a Nathan administrator, so this provider can now remain as the only login method administrators use.</p>"
        : "<p>The account you used is not a Nathan administrator. The test shows the provider works, but it does not count toward " +
          "keeping administrator access: you can't disable your other login methods until an administrator completes a test sign-in.</p>")
    : "<p>Nathan could not confirm a fresh sign-in through the provider with the credentials the test was started for. The test link may " +
      "have expired or been used, the credentials may have changed since the test started, or the sign-in did not complete. " +
      "Start a new test from Identity Studio.</p>";
  const who = email ? "<p><small>You are currently signed in as " + escape(email) + ". Sign in again as an administrator to continue in Identity Studio.</small></p>" : "";
  const html = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" + title + " · Nathan</title></head><body><main><h1>" + title + "</h1>" + body + who +
    "<p><a href=\"/sign-in\">Sign in</a> · <a href=\"/studio\">Identity Studio</a></p></main></body></html>";
  return new Response(html, {
    status: ok ? 200 : 400,
    headers: {
      "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"
    }
  });
}
