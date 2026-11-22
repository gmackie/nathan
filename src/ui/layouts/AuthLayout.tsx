/**
 * NATH-37: the centred card every hosted end-user page uses (sign-in, consent, refusals, SAML).
 * Not wired into any page yet; K1 (NATH-38) swaps the pages over.
 */
import type { ReactNode } from "react";
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
}

export function AuthLayout({ title, children, footer }: AuthLayoutProps) {
  return (
    <main className="nathan-auth">
      <div className="nathan-auth-card">
        <NathanMark />
        <h1 className="nathan-title">{title}</h1>
        <div className="nathan-stack">{children}</div>
        {footer ? <footer className="nathan-footer">{footer}</footer> : null}
      </div>
    </main>
  );
}
