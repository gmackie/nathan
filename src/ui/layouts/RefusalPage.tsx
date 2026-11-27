/**
 * NATH-37: a page that refuses something and names Nathan's reason code. Same text format as
 * today's refusal() in src/auth/saml-idp.ts: "<message> (<code>)", in one text node so the HTML
 * contains exactly that string (tests and audit lookups depend on it). No script.
 */
import { LinkButton } from "@cloudflare/kumo/components/button";
import { AuthLayout } from "./AuthLayout.tsx";
import { NathanIcon } from "../icons.tsx";
import type { ResolvedAppearance } from "../appearance.ts";

export interface RefusalPageProps {
  title: string;
  message: string;
  /** Reason code, the same one the audit log records. */
  code: string;
  /** Offer a link to /sign-in. */
  signIn?: boolean;
  /** NATH-38: issuer host for the fixed footer, and the hosted-page appearance. */
  issuer?: string;
  appearance?: ResolvedAppearance;
}

export function RefusalPage({ title, message, code, signIn = false, issuer, appearance }: RefusalPageProps) {
  return (
    <AuthLayout title={title} issuer={issuer} appearance={appearance}>
      <p className="nathan-text" role="alert">{message + " (" + code + ")"}</p>
      {signIn ? (
        <div className="nathan-actions">
          <LinkButton href="/sign-in" variant="primary" icon={<NathanIcon name="user" />}>Sign in to Nathan</LinkButton>
        </div>
      ) : null}
    </AuthLayout>
  );
}
