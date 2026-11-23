/**
 * NATH-40 test fixture: the installer and gateway pages, bundled by tests/operate-pages.test.mjs
 * with esbuild (node can't import TSX).
 */
import { renderToString } from "react-dom/server";
import { installerPage } from "../../src/installer/ui.ts";
import { InstallerWizard, installerProviderIds } from "../../src/ui/pages/installer/InstallerWizard.tsx";
import { renderGatewayError } from "../../src/ui/pages/gateway/GatewayErrorPage.tsx";

export { installerPage, renderGatewayError, installerProviderIds };

/** The wizard exactly as hydrateIslands() hydrates it: its own root, no props. */
export const standaloneWizard = () => renderToString(<InstallerWizard />);

/** The redirect URI the wizard shows for `host` and `provider`, from its own rendered markup. */
export function wizardCallback(host: string, provider: string): string {
  const html = renderToString(<InstallerWizard initialHostname={host} initialProvider={provider} />);
  const match = /<pre [^>]*data-nathan-callback=""[^>]*>([^<]*)<\/pre>/.exec(html);
  if (!match) throw Error("wizard shows no redirect URI");
  return match[1].replaceAll("&amp;", "&");
}
