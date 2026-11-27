import { Button } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import { Label } from "@cloudflare/kumo/components/label";
import { AuthLayout } from "../ui/layouts/AuthLayout";
import { renderPage } from "../ui/render";

export function emailSignInPage(loginHint: string | null) {
  return renderPage(<AuthLayout title="Sign in by email">
    <form id="request-email" method="post">
      <div className="nathan-stack">
        <Label htmlFor="email-address"><span id="email-label">Email address</span></Label>
        <Input id="email-address" aria-labelledby="email-label" type="email" autoComplete="email" defaultValue={loginHint ?? ""} required />
        <Button type="submit" variant="primary">Email me a code and link</Button>
      </div>
    </form>
    <form id="verify-email" hidden method="post">
      <div className="nathan-stack">
        <Label htmlFor="email-code"><span id="code-label">Email code</span></Label>
        <Input id="email-code" aria-labelledby="code-label" type="text" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required />
        <Button type="submit" variant="primary">Continue</Button>
      </div>
    </form>
    <p id="email-status" role="status" aria-live="polite"></p>
    <noscript>Turn on JavaScript to sign in by email.</noscript>
  </AuthLayout>, { title: "Sign in by email", islands: ["email-sign-in"] });
}
