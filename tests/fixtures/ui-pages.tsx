/**
 * NATH-37 test fixture: pages built with the K0 UI layer. tests/ui-render.test.mjs bundles this
 * file with esbuild (node can't import TSX), and tests/runtime/fixtures/ui-worker.tsx serves the
 * same pages from workerd.
 */
import { Button } from "@cloudflare/kumo/components/button";
import { Checkbox } from "@cloudflare/kumo/components/checkbox";
import { Input } from "@cloudflare/kumo/components/input";
import { renderToString } from "react-dom/server";
import { renderPage, type RenderPageOptions } from "../../src/ui/render.tsx";
import { Island } from "../../src/ui/island.tsx";
import { PasskeyButton } from "../../src/ui/components/PasskeyButton.tsx";
import { AuthLayout } from "../../src/ui/layouts/AuthLayout.tsx";
import { RefusalPage } from "../../src/ui/layouts/RefusalPage.tsx";
import { AutoPostPage, autoPostPageOptions } from "../../src/ui/layouts/AutoPostPage.tsx";
import { ProviderIcon, NathanIcon, PROVIDER_ICONS, GENERIC_PROVIDER_ICON, ICONS, providerIcon } from "../../src/ui/icons.tsx";
import { UI_MANIFEST } from "../../src/ui/manifest.ts";

export { renderPage, UI_MANIFEST, PROVIDER_ICONS, GENERIC_PROVIDER_ICON, ICONS, providerIcon };

/** A form with Button, Checkbox and Input: all three emit inline styles or need them. */
export function formPage(title = "Sign in", opts: Partial<RenderPageOptions> = {}) {
  return renderPage(
    <AuthLayout title={title} footer={<span>Footer</span>}>
      <form method="post" action="/sign-in">
        <Input label="Email" name="email" type="email" />
        <Checkbox label="Remember this device" name="remember" />
        <Button type="submit" variant="primary">Continue</Button>
        <Button type="button" variant="primary">Also primary</Button>
        <Button type="button">Secondary</Button>
      </form>
    </AuthLayout>,
    { title, ...opts }
  );
}

export function islandPage(opts: Partial<RenderPageOptions> = {}) {
  return renderPage(
    <AuthLayout title="Passkey">
      <Island id="passkey-button" component={PasskeyButton} props={{ label: "Sign in with passkey" }} />
    </AuthLayout>,
    { title: "Passkey", islands: ["passkey-button"], ...opts }
  );
}

/** An island in the markup that renderPage's `islands` option leaves out. */
export function unlistedIslandPage() {
  return renderPage(
    <Island id="passkey-button" component={PasskeyButton} props={{ label: "x" }} />,
    { title: "Unlisted" }
  );
}

export function refusalPage(title: string, message: string, code: string, signIn = false, status = 403) {
  return renderPage(<RefusalPage title={title} message={message} code={code} signIn={signIn} />, { title, status });
}

export function autoPostPage(acsUrl: string, samlResponse: string, relayState: string | null, spName: string) {
  return renderPage(
    <AutoPostPage acsUrl={acsUrl} samlResponse={samlResponse} relayState={relayState} spName={spName} />,
    { title: "Signing in", ...autoPostPageOptions(acsUrl) }
  );
}

export function iconMarkup() {
  return {
    google: renderToString(<ProviderIcon provider="google" />),
    unknown: renderToString(<ProviderIcon provider="okta" label="Okta" />),
    passkey: renderToString(<NathanIcon name="passkey" />)
  };
}

/** A page whose component writes a hostile inline style; renderPage must refuse it. */
export function hostileStylePage(value: string) {
  return renderPage(<div style={{ fontFamily: value }}>x</div>, { title: "Hostile" });
}
