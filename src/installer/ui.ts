/**
 * Customer-owned Cloudflare account deployment wizard (NATH-40: Kumo, rendered with renderPage).
 * The page and its island live in src/ui/pages/installer/; no inline script, no browser token storage.
 */
import { renderInstallerPage } from "../ui/pages/installer/InstallerPage.tsx";

/** The installer's GET / response, with renderPage's CSP and security headers. */
export function installerPage(): Response {
  return renderInstallerPage();
}
