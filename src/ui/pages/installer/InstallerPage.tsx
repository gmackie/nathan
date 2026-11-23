/**
 * NATH-40: the hosted installer's page (GET / on the installer Worker), rendered with renderPage.
 *
 * An Operate surface: stock Kumo, never themed. The wizard is one island (installer-wizard); the
 * header, the "what gets created" panel and the footer are server-only markup. CSP comes from
 * renderPage: default-src 'none', script-src 'self' plus the page nonce (the SRI-pinned island),
 * connect-src 'self' (the wizard's /api/* calls), form-action 'self', frame-ancestors 'none'.
 * The sealed release served from the ASSETS binding is untouched; UI assets come from
 * /__nathan/ui/ in the Worker itself.
 */
import { Badge } from "@cloudflare/kumo/components/badge";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Island } from "../../island.tsx";
import { NathanMark } from "../../layouts/AuthLayout.tsx";
import { renderPage } from "../../render.tsx";
import { InstallerWizard } from "./InstallerWizard.tsx";

export function InstallerPage() {
  return (
    <div className="nathan-operate">
      <header className="nathan-operate-header">
        <div className="nathan-stack-tight">
          <NathanMark />
          <span className="nathan-muted">Cloudflare-native identity and access</span>
        </div>
        <Badge variant="secondary">Customer-owned installation</Badge>
      </header>
      <div className="nathan-operate-main">
        <main className="nathan-panel nathan-stack">
          <h1 className="nathan-title">Deploy your identity provider</h1>
          <p className="nathan-text">Nathan sets up an OAuth/OIDC issuer, D1 database, secure hostname, social login, and a personal admin console in your own Cloudflare account.</p>
          <noscript>
            <Banner variant="alert" text="The installer needs JavaScript to talk to the Cloudflare API on your behalf. Turn it on and reload this page." />
          </noscript>
          <Island id="installer-wizard" component={InstallerWizard} props={{}} />
        </main>
        <aside className="nathan-panel nathan-stack">
          <h2 className="nathan-heading">What gets created?</h2>
          <ol className="nathan-list">
            <li>One Better Auth Worker</li>
            <li>One Cloudflare D1 identity database</li>
            <li>Private upload and locked-down preview endpoints</li>
            <li>Login provider credentials encrypted in your own D1 database</li>
            <li>Custom domain and HTTPS</li>
            <li>OIDC issuer, JWKS, and client registration</li>
            <li>Identity Studio and OAuth-protected MCP admin tools</li>
          </ol>
          <h2 className="nathan-heading">What happens next?</h2>
          <p className="nathan-text">Log in with your upstream provider, verify your account, and complete the initial admin bootstrap. Then onboard Workers and external OIDC clients from Identity Studio.</p>
          <p className="nathan-text">
            <a className="nathan-link" href="https://github.com/gmackie/nathan" target="_blank" rel="noopener noreferrer">Source and deployment docs</a>
          </p>
          <p className="nathan-muted">Experimental build: this wizard uses Cloudflare's real APIs, but needs live integration testing before production use.</p>
        </aside>
      </div>
      <footer className="nathan-footer">Nathan uses a pinned, integrity-checked release bundle. No Cloudflare OAuth tokens are exposed to the browser.</footer>
    </div>
  );
}

export function renderInstallerPage(): Response {
  return renderPage(<InstallerPage />, { title: "Deploy to Cloudflare", islands: ["installer-wizard"] });
}
