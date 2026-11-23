/**
 * NATH-37 test-only Worker: renders the K0 fixture pages with react-dom/server's workerd build,
 * exactly as the identity Worker will once K1 swaps its pages over. Never deployed.
 */
import { serveUiAsset } from "../../../src/ui/assets.ts";
import { autoPostPage, formPage, islandPage, refusalPage } from "../../fixtures/ui-pages.tsx";

export default {
  async fetch(request: Request): Promise<Response> {
    const asset = serveUiAsset(request);
    if (asset) return asset;
    const { pathname } = new URL(request.url);
    if (pathname === "/form") return formPage();
    if (pathname === "/island") return islandPage();
    if (pathname === "/refusal") return refusalPage("Request refused", "Start again from the application.", "saml_cross_site_request", true);
    if (pathname === "/auto-post") return autoPostPage("https://sp.example.com/acs", "PHNhbWw+", "relay", "Grafana");
    return new Response("Not found", { status: 404 });
  }
};
