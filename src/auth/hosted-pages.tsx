/**
 * NATH-38: Nathan's hosted sign-in and OIDC consent pages in stock Kumo, server-rendered with
 * renderPage() (src/ui/render.tsx). Their behaviour lives in hashed, SRI-pinned islands
 * (src/ui/islands/sign-in.ts, oauth-consent.ts); there is no inline script.
 *
 * Security properties kept from the String.raw pages they replace (src/auth/ui.ts before K1):
 * - CSP frame-ancestors 'none', form-action 'self', base-uri 'none', img-src 'none'; scripts only
 *   the page's islands (nonce + SRI). Referrer-Policy same-origin (so same-origin requests keep
 *   their Origin), Cache-Control no-store, X-Frame-Options DENY.
 * - Every sign-in request carries the signed oauth_query; after sign-in the browser follows the
 *   resumed authorization's URL (see the sign-in island).
 * - All text is React-escaped; nothing uses dangerouslySetInnerHTML.
 *
 * Appearance (DESIGN.md): both pages take an optional resolved appearance. Empty (the default)
 * renders stock Kumo. The issuer footer, route line, scope text, reason codes and warnings are
 * fixed and cannot be changed by it.
 */
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import type { ReactNode } from "react";
import { renderPage } from "../ui/render.tsx";
import { AuthLayout } from "../ui/layouts/AuthLayout.tsx";
import { RefusalPage } from "../ui/layouts/RefusalPage.tsx";
import { NathanIcon, ProviderIcon } from "../ui/icons.tsx";
import type { ResolvedAppearance } from "../ui/appearance.ts";
import { displayName } from "../shared/providers.mjs";

export interface HostedPageOptions {
  /** Issuer host for the fixed footer (for example id.example.com). */
  issuer?: string;
  /** Resolved appearance (resolveAppearance). Omitted: stock Kumo. Storage is NATH-30. */
  appearance?: ResolvedAppearance;
}

export interface SignInOptions extends HostedPageOptions {
  /** The ?error= code a refused sign-in returned with (NATH-16/19). */
  error?: string | null;
  emailHref?: string;
}

/** Fixed explanations for refusal codes a sign-in can return with. The code is always shown too. */
export const SIGN_IN_ERRORS: Readonly<Record<string, string>> = {
  ACCOUNT_NOT_ADMITTED: "This installation creates new accounts by invitation only, and this email address has no open invitation. Ask an administrator to invite it, then sign in again.",
  ACCOUNT_DEPROVISIONED: "Your organization's directory has deactivated this account. Contact your administrator.",
  BANNED_USER: "This account is blocked. Contact your administrator."
};

/** The message for a sign-in ?error= code, or null for none or a malformed one (never echoed). */
export function signInErrorMessage(code: string | null | undefined): string | null {
  if (!code || !/^[A-Za-z_]{1,64}$/.test(code)) return null;
  return Object.hasOwn(SIGN_IN_ERRORS, code) ? SIGN_IN_ERRORS[code] + " (" + code + ")" : "Sign-in failed (" + code + ").";
}

type Method = "passkey" | "email" | `provider:${string}`;

/** The primary method an appearance asks for, if this instance offers it; otherwise passkey. */
function primaryMethod(appearance: ResolvedAppearance | undefined, providers: string[], passwordEnabled: boolean): Method {
  const wanted = appearance?.layout.primaryMethod ?? "passkey";
  if (wanted === "email") return passwordEnabled ? "email" : "passkey";
  if (wanted.startsWith("provider:")) return providers.includes(wanted.slice(9)) ? (wanted as Method) : "passkey";
  return "passkey";
}

/** A message box the island fills; hidden until it has text, or shown with a server-rendered message. */
function StatusBanner({ variant, attr, message }: { variant: "error" | "default"; attr: string; message?: string | null }) {
  return (
    <div {...{ [attr]: "" }} role={variant === "error" ? "alert" : "status"} hidden={!message}>
      <Banner variant={variant} icon={<NathanIcon name={variant === "error" ? "warning" : "info"} />}
        description={<span data-text="">{message ?? ""}</span>} />
    </div>
  );
}

const needsScript = { "data-needs-script": "", disabled: true } as const;

export function signInPage(providers: string[], passwordEnabled: boolean, enterpriseSso = false, opts: SignInOptions = {}): Response {
  const { appearance, issuer } = opts;
  const primary = primaryMethod(appearance, providers, passwordEnabled);
  const iconButtons = appearance?.layout.socialButtonsVariant === "iconButton";
  const error = signInErrorMessage(opts.error);

  const providerButtons = providers.length ? (
    <div className={iconButtons ? "nathan-providers-icons" : "nathan-providers"} key="providers">
      {providers.map(p => {
        const label = "Continue with " + displayName(p);
        const variant = primary === "provider:" + p ? "primary" : "secondary";
        return iconButtons ? (
          <Button key={p} type="button" variant={variant} shape="square" size="lg" aria-label={label} title={label}
            data-provider={p} {...needsScript} icon={<ProviderIcon provider={p} />} />
        ) : (
          <Button key={p} type="button" variant={variant} size="lg" className="nathan-block" data-provider={p} {...needsScript}
            icon={<ProviderIcon provider={p} />}>{label}</Button>
        );
      })}
    </div>
  ) : null;

  const passkey = (
    <section className="nathan-section" key="passkey">
      <Button type="button" variant={primary === "passkey" ? "primary" : "secondary"} size="lg" className="nathan-block"
        data-passkey="" {...needsScript} icon={<NathanIcon name="passkey" />}>Sign in with passkey</Button>
    </section>
  );

  const sso = enterpriseSso ? (
    <section className="nathan-section" key="sso">
      <h2 className="nathan-subtitle">Work or school account</h2>
      <form className="nathan-form" method="post" action="/sign-in" data-sso="" noValidate>
        <Input label="Corporate email address" name="email" type="email" autoComplete="email" placeholder="you@company.com" />
        <Button type="submit" variant="secondary" size="lg" className="nathan-block" {...needsScript}
          icon={<NathanIcon name="sso" />}>Sign in with SSO</Button>
      </form>
    </section>
  ) : null;

  const password = passwordEnabled ? (
    <section className="nathan-section" key="password">
      <h2 className="nathan-subtitle">Email and password</h2>
      <form className="nathan-form" method="post" action="/sign-in" data-password="" noValidate>
        <Input label="Email" name="email" type="email" autoComplete="username" />
        <Input label="Password" name="password" type="password" autoComplete="current-password" />
        <Button type="submit" variant={primary === "email" ? "primary" : "secondary"} size="lg" className="nathan-block"
          {...needsScript}>Sign in</Button>
      </form>
      <form className="nathan-form" method="post" action="/sign-in" data-two-factor="" hidden noValidate>
        <Input label="Authenticator code" name="code" autoComplete="one-time-code" inputMode="numeric" />
        {/* The second step, shown only after the password step; then it is the page's one action. */}
        <Button type="submit" variant="primary" size="lg" className="nathan-block" data-totp="" {...needsScript}
          icon={<NathanIcon name="shield-check" />}>Verify second factor</Button>
      </form>
    </section>
  ) : null;

  // The primary method comes first; the others keep their usual order.
  const blocks: { method: string; node: ReactNode }[] = [
    { method: "provider", node: providerButtons }, { method: "passkey", node: passkey },
    { method: "email-otp", node: opts.emailHref && <p key="email-otp"><a href={opts.emailHref}>Sign in by email</a></p> },
    { method: "sso", node: sso }, { method: "email", node: password }
  ].filter(b => b.node);
  const lead = primary.startsWith("provider:") ? "provider" : primary;
  blocks.sort((a, b) => Number(b.method === lead) - Number(a.method === lead));
  const body: ReactNode[] = [];
  blocks.forEach((b, i) => {
    if (i > 0) body.push(<div className="nathan-divider" key={"or-" + i}>or</div>);
    body.push(b.node);
  });

  return renderPage(
    <AuthLayout title="Sign in" issuer={issuer} appearance={appearance}>
      <div className="nathan-stack" data-nathan-sign-in="">
        <p className="nathan-muted">Use your configured identity provider, passkey, or approved enterprise account.</p>
        <noscript>
          <Banner variant="alert" icon={<NathanIcon name="warning" />} description="Signing in needs JavaScript. Turn it on for this site and reload the page." />
        </noscript>
        <StatusBanner variant="error" attr="data-sign-in-error" message={error} />
        <StatusBanner variant="default" attr="data-sign-in-notice" />
        {body}
      </div>
    </AuthLayout>,
    { title: "Sign in", islands: ["sign-in"], appearance }
  );
}

/** Plain-language text for the standard OIDC scopes; other scopes are shown by name only. */
const OIDC_SCOPES: Readonly<Record<string, string>> = {
  openid: "Confirm who you are with your Nathan account",
  profile: "Your name and profile details",
  email: "Your email address and whether it is verified",
  offline_access: "Keep access while you are away (refresh tokens)"
};

export function consentPage(verified: boolean, clientName: string, scope: string, opts: HostedPageOptions = {}): Response {
  const { issuer, appearance } = opts;
  if (!verified) {
    return renderPage(
      <RefusalPage title="Consent request not valid" message="Invalid or expired consent request. Start again from the application."
        code="oauth_consent_invalid" issuer={issuer} appearance={appearance} />,
      { title: "Consent request not valid", status: 400, formAction: ["'none'"], appearance }
    );
  }
  const scopes = scope.split(/\s+/).filter(Boolean);
  return renderPage(
    <AuthLayout title={clientName + " wants to access your account"} issuer={issuer} route={clientName} appearance={appearance}>
      <div className="nathan-stack" data-nathan-oauth-consent="">
        <p className="nathan-text">{"Client " + clientName + " requests access."}</p>
        <p className="nathan-text">{"Requested scopes: " + scope}</p>
        {scopes.length ? (
          <ul className="nathan-scope-list">
            {scopes.map(s => (
              <li key={s} className="nathan-text">
                <code className="nathan-code">{s}</code>
                {Object.hasOwn(OIDC_SCOPES, s) ? " – " + OIDC_SCOPES[s] : null}
              </li>
            ))}
          </ul>
        ) : null}
        <noscript>
          <Banner variant="alert" icon={<NathanIcon name="warning" />} description="Answering needs JavaScript. Turn it on for this site and reload the page." />
        </noscript>
        <StatusBanner variant="error" attr="data-consent-error" />
        <div className="nathan-actions">
          <Button type="button" variant="primary" size="lg" data-consent="allow" disabled icon={<NathanIcon name="success" />}>Allow</Button>
          <Button type="button" variant="secondary" size="lg" data-consent="deny" disabled>Deny</Button>
        </div>
      </div>
    </AuthLayout>,
    { title: "Authorize application", islands: ["oauth-consent"], appearance }
  );
}
