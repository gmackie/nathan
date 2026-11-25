/**
 * NATH-37: delivers a signed SAML Response with the HTTP-POST binding, like autoPostPage() in
 * src/auth/saml-idp-ui.mjs. The form posts only to the exact ACS URL; CSP form-action allows only
 * that URL's origin (autoPostPageOptions). The auto-post island (a hashed, SRI-pinned script, no
 * inline code) submits it; without JavaScript the person presses Continue.
 */
import { Button } from "@cloudflare/kumo/components/button";
import type { IslandId } from "../island-ids.ts";
import { AuthLayout } from "./AuthLayout.tsx";

export interface AutoPostPageProps {
  acsUrl: string;
  samlResponse: string;
  relayState: string | null;
  spName: string;
  /** NATH-38: issuer host for the fixed footer and route line. */
  issuer?: string;
}

function acsOrigin(acsUrl: string): string {
  const url = new URL(acsUrl);
  if (url.protocol !== "https:") throw Error("ACS URL must use https");
  return url.origin;
}

export function AutoPostPage({ acsUrl, samlResponse, relayState, spName, issuer }: AutoPostPageProps) {
  acsOrigin(acsUrl);
  return (
    <AuthLayout title={"Signing you in to " + spName} issuer={issuer} route={issuer ? spName : undefined}>
      <form method="post" action={acsUrl} id="saml-post" data-nathan-autopost="">
        <input type="hidden" name="SAMLResponse" value={samlResponse} />
        {relayState !== null ? <input type="hidden" name="RelayState" value={relayState} /> : null}
        <noscript>
          <p className="nathan-text">{"JavaScript is off. Continue to send your sign-in to " + spName + "."}</p>
        </noscript>
        <div className="nathan-actions">
          <Button type="submit" variant="primary">Continue</Button>
        </div>
      </form>
    </AuthLayout>
  );
}

/** renderPage options AutoPostPage needs: its island and form-action limited to the ACS origin. */
export function autoPostPageOptions(acsUrl: string): { islands: IslandId[]; formAction: string[] } {
  return { islands: ["auto-post"], formAction: [acsOrigin(acsUrl)] };
}
