/**
 * NATH-38: /security (account security) on Kumo. A single-column page that reads well at 375px:
 * a header with the signed-in email, then the `security` island (SecurityPanel) with the
 * administrator onboarding, TOTP and passkey cards. renderPage() supplies the CSP (script-src
 * 'self' 'nonce-…' for the island, img-src 'none'), Referrer-Policy same-origin and the other
 * security headers; the email is rendered as React text.
 */
import { Link } from "@cloudflare/kumo/components/link";
import { Island } from "../../island.tsx";
import { NathanMark } from "../../layouts/AuthLayout.tsx";
import { renderPage } from "../../render.tsx";
import { SecurityPanel } from "./SecurityPanel.tsx";

export function SecurityPage({ email }: { email: string }) {
  return (
    <main style={{ maxWidth: 600, margin: "0 auto", padding: "24px 16px 48px", boxSizing: "border-box", display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 16 }}>
      <header style={{ display: "grid", gap: 8 }}>
        <nav aria-label="Account" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 16, justifyContent: "space-between" }}>
          <NathanMark />
          <span style={{ display: "flex", gap: 16, fontSize: 14 }}>
            <Link href="/studio">Identity Studio</Link>
            <Link href="/sign-in">Sign in</Link>
          </span>
        </nav>
        <h1 className="nathan-title">Account security</h1>
        <p className="nathan-text">Signed in as <strong>{email}</strong>.</p>
      </header>
      <Island id="security" component={SecurityPanel} props={{}} />
    </main>
  );
}

export function securityPage(userEmail: string): Response {
  return renderPage(<SecurityPage email={userEmail} />, { title: "Account security", islands: ["security"] });
}
