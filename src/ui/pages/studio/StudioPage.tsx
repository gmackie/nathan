/**
 * NATH-39: the Identity Studio document. Server-rendered with renderPage() (nonce'd classes for
 * Kumo's inline styles, CSP with script-src limited to the page nonce and same-origin hashed
 * modules, SRI on every module, frame-ancestors 'none', Referrer-Policy same-origin), hosting the
 * Studio SPA as its single island.
 *
 * Authorization happens before this is called: worker.ts serves /studio only to a verified,
 * granted administrator who passes mayAdminister (otherwise 403 or the admin setup redirect), and
 * every API call the SPA makes is authorized again by /studio/api/v1. The page itself carries no
 * account data beyond the administrator's email.
 */
import { renderPage } from "../../render.tsx";
import { Island } from "../../island.tsx";
import { StudioApp } from "./StudioApp.tsx";

export function studioPage(userEmail: string, classCheck = false): Response {
  return renderPage(
    <>
      <Island id="studio" component={StudioApp} props={{ email: userEmail, classCheck: classCheck || undefined }} />
      <noscript><p className="nathan-text nathan-studio-noscript">Turn on JavaScript to use Identity Studio.</p></noscript>
    </>,
    { title: "Identity Studio", islands: ["studio"], bodyClass: "nathan-studio-body" }
  );
}
