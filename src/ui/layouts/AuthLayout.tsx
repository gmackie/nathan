/**
 * NATH-37: the centred card every hosted end-user page uses (sign-in, consent, refusals, SAML).
 *
 * NATH-38: hosted pages may pass a resolved appearance (src/ui/appearance.ts). Only its layout
 * reaches this component: a plate (left or top) with the wordmark and the accent disc. Colours,
 * radius and font arrive as CSS from renderPage's `appearance` option. With no appearance, or
 * platePlacement "none", the markup is the stock Kumo card exactly as before.
 *
 * Fixed for every instance and app (DESIGN.md), and never reachable from the appearance object:
 * the route line ("app → issuer host") and the issuer footer.
 */
import type { ReactNode } from "react";
import type { ResolvedAppearance } from "../appearance.ts";
import { NathanIcon } from "../icons.tsx";

/** Placeholder wordmark until the NATH-34 design pass. */
export function NathanMark() {
  return (
    <span className="nathan-mark">
      <NathanIcon name="shield-check" size={18} weight="fill" />
      Nathan
    </span>
  );
}

export interface AuthLayoutProps {
  title: string;
  children?: ReactNode;
  footer?: ReactNode;
  /** Issuer host (for example id.example.com). Shown in the fixed issuer footer. */
  issuer?: string;
  /** Who is asking, for the fixed route line "<route> → <issuer>". Needs `issuer`. */
  route?: string;
  /** Resolved hosted-page appearance; only `layout` and `wordmark` are used here. */
  appearance?: ResolvedAppearance;
}

export function AuthLayout({ title, children, footer, issuer, route, appearance }: AuthLayoutProps) {
  const card = (
    <div className="nathan-auth-card">
      <NathanMark />
      {route && issuer ? <p className="nathan-route">{route + " → " + issuer}</p> : null}
      <h1 className="nathan-title">{title}</h1>
      <div className="nathan-stack">{children}</div>
      {footer || issuer ? (
        <footer className="nathan-footer">
          {footer}
          {issuer ? <p className="nathan-issuer">{"Identity provider: " + issuer + " (Nathan)"}</p> : null}
        </footer>
      ) : null}
    </div>
  );
  const placement = appearance?.layout.platePlacement ?? "none";
  if (placement === "none") return <main className="nathan-auth">{card}</main>;
  const wordmark = appearance?.wordmark && appearance.layout.logoPlacement !== "form" ? appearance.wordmark : null;
  return (
    <div className={"nathan-hosted nathan-hosted-" + placement}>
      <div className="nathan-plate" aria-hidden="true">
        {appearance?.light.plateAccent || appearance?.dark.plateAccent ? <span className="nathan-plate-accent" /> : null}
        {wordmark ? <span className="nathan-wordmark">{wordmark}</span> : null}
      </div>
      <main className="nathan-auth">{card}</main>
    </div>
  );
}
