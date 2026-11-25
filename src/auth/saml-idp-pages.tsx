/**
 * NATH-12 end-user pages for Nathan as a SAML IdP, in stock Kumo (NATH-38). Moved here from
 * saml-idp-ui.mjs, which keeps only the Identity Studio section.
 *
 * - autoPostPage: layouts/AutoPostPage. The form posts only to the exact registered ACS URL; CSP
 *   form-action allows only that URL's origin. The only script is the hashed, SRI-pinned auto-post
 *   island (no inline code); without JavaScript the person presses Continue.
 * - samlRefusalPage: layouts/RefusalPage, "<message> (<reason code>)", no script
 *   (script-src 'none'), no form (form-action 'none'). Nothing is sent to the SP.
 * - idpInitiatedPage, ssoConfirmPage: same-origin POST forms (form-action 'self'), no script, so
 *   a cross-site link or an unsigned AuthnRequest cannot sign anyone in without a click on Nathan.
 *
 * Every value is React-escaped. All pages send Referrer-Policy same-origin (renderPage), so
 * Nathan's URLs never reach the SP, and Pragma no-cache next to Cache-Control no-store.
 */
import { Button } from "@cloudflare/kumo/components/button";
import { renderPage } from "../ui/render.tsx";
import { AuthLayout } from "../ui/layouts/AuthLayout.tsx";
import { AutoPostPage, autoPostPageOptions } from "../ui/layouts/AutoPostPage.tsx";
import { RefusalPage } from "../ui/layouts/RefusalPage.tsx";

const NO_CACHE = { Pragma: "no-cache" };

export function autoPostPage({ acsUrl, samlResponse, relayState, spName, issuer }:
  { acsUrl: string; samlResponse: string; relayState: string | null; spName: string; issuer?: string }): Response {
  return renderPage(
    <AutoPostPage acsUrl={acsUrl} samlResponse={samlResponse} relayState={relayState} spName={spName} issuer={issuer} />,
    { title: "Signing in", ...autoPostPageOptions(acsUrl), headers: NO_CACHE }
  );
}

/** A refusal shown by Nathan with its reason code (the same one the audit log records). */
export function samlRefusalPage(title: string, message: string, code: string, { status = 403, signIn = false } = {}): Response {
  return renderPage(<RefusalPage title={title} message={message} code={code} signIn={signIn} />,
    { title, status, formAction: ["'none'"], headers: NO_CACHE });
}

/** IdP-initiated sign-in needs an explicit same-origin POST, so a cross-site link cannot log anyone in. */
export function idpInitiatedPage({ spId, spName, email, issuer }: { spId: string; spName: string; email: string; issuer?: string }): Response {
  return renderPage(
    <AuthLayout title={"Continue to " + spName} issuer={issuer} route={issuer ? spName : undefined}>
      <p className="nathan-text">{"Signed in to Nathan as " + email + "."}</p>
      <form method="post" action={"/saml/idp/start/" + spId}>
        <div className="nathan-actions">
          <Button type="submit" variant="primary" size="lg">{"Sign in to " + spName}</Button>
        </div>
      </form>
    </AuthLayout>,
    { title: "Continue to " + spName, headers: NO_CACHE }
  );
}

/**
 * Asked before answering an unsigned AuthnRequest with a session that already existed: anyone can
 * send the browser such a request, so the user confirms on Nathan's own page. Continue and Cancel
 * are a same-origin POST carrying the single-use token; no script, no framing.
 */
export function ssoConfirmPage({ spName, email, acsHost, token, issuer }:
  { spName: string; email: string; acsHost: string; token: string; issuer?: string }): Response {
  return renderPage(
    <AuthLayout title={"Continue to " + spName + " as " + email + "?"} issuer={issuer} route={issuer ? spName : undefined}>
      <p className="nathan-text">{spName + " asked Nathan to sign you in. Nathan will send your sign-in to " + acsHost + "."}</p>
      <p className="nathan-text" role="note">{"If you did not just start signing in to " + spName + ", choose Cancel."}</p>
      <form method="post" action="/saml/idp/continue"><input type="hidden" name="confirm" value={token} />
        <div className="nathan-actions">
          <Button type="submit" name="action" value="continue" variant="primary" size="lg">Continue</Button>
          <Button type="submit" name="action" value="cancel" variant="secondary" size="lg">Cancel</Button>
        </div>
      </form>
    </AuthLayout>,
    { title: "Continue to " + spName, headers: NO_CACHE }
  );
}
