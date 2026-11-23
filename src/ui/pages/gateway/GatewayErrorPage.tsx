/**
 * NATH-40: the gateway's own HTML pages (login failures, access denied, outages, unknown
 * /__nathan/ paths), shown to browser navigations instead of the plain-text body.
 *
 * The gateway protects private upstream apps, so these pages never reference the upstream: the
 * only subresource is the hashed CSS at /__nathan/ui/, which the gateway Worker serves itself
 * (and /__nathan/* never proxies). No islands, so CSP is script-src 'none'; form-action 'none'
 * because nothing here posts. The message is the exact plain-text message, escaped by React.
 * `retry` must already be a same-origin path; it is re-checked with safeReturnPath here too.
 */
import { Banner } from "@cloudflare/kumo/components/banner";
import { LinkButton } from "@cloudflare/kumo/components/button";
import { safeReturnPath } from "../../../shared/security.mjs";
import { NathanIcon } from "../../icons.tsx";
import { AuthLayout } from "../../layouts/AuthLayout.tsx";
import { renderPage } from "../../render.tsx";

export interface GatewayErrorProps {
  status: number;
  message: string;
  /** Same-origin path for a "Try again" link, for example /__nathan/login?returnTo=%2Freports. */
  retry?: string;
}

const TITLES: Record<number, string> = {
  400: "Sign-in could not finish",
  401: "Sign-in failed",
  403: "Access denied",
  404: "Not found",
  503: "Temporarily unavailable"
};

export const gatewayErrorTitle = (status: number) => TITLES[status] ?? "Request failed";

export function GatewayErrorPage({ status, message, retry }: GatewayErrorProps) {
  const href = retry === undefined ? null : safeReturnPath(retry);
  return (
    <AuthLayout title={gatewayErrorTitle(status)} footer={<span>{"Error " + status + " from the Nathan access gateway."}</span>}>
      <Banner variant={status >= 500 ? "alert" : "error"} icon={<NathanIcon name={status >= 500 ? "warning" : "error"} />}
        role="alert" text={message} />
      {href ? (
        <div className="nathan-actions">
          <LinkButton href={href} variant="primary" icon={<NathanIcon name="user" />}>Try again</LinkButton>
        </div>
      ) : null}
    </AuthLayout>
  );
}

export function renderGatewayError(props: GatewayErrorProps): Response {
  return renderPage(<GatewayErrorPage {...props} />, {
    title: gatewayErrorTitle(props.status), status: props.status, formAction: ["'none'"]
  });
}
