/**
 * NATH-39 test fixture: the Identity Studio page and SPA modules. tests/studio-ui.test.mjs bundles
 * this file with esbuild (node can't import TSX); packages stay external.
 */
export { studioPage } from "../../src/ui/pages/studio/StudioPage.tsx";
export { StudioApp, STUDIO_NAV, panelFromHash } from "../../src/ui/pages/studio/StudioApp.tsx";
export { carriesSecret, when } from "../../src/ui/pages/studio/kit.tsx";
export * as confirmations from "../../src/ui/pages/studio/confirmations.ts";
export { STUDIO_API } from "../../src/ui/pages/studio/api.ts";
export { UI_MANIFEST } from "../../src/ui/manifest.ts";
export { rewriteTags } from "../../src/ui/csp-styles.ts";
