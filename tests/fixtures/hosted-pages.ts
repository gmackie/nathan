/**
 * NATH-38 test fixture: the hosted end-user pages (TSX), re-exported for node tests. Bundled with
 * esbuild by tests/hosted-pages.test.mjs and tests/pages.test.mjs (node can't import TSX).
 */
export { signInPage, consentPage, signInErrorMessage, SIGN_IN_ERRORS } from "../../src/auth/hosted-pages.tsx";
export { consentPage as mcpConsentPage, connectionsPage, mcpErrorPage } from "../../src/auth/mcp-pages.tsx";
export { autoPostPage, samlRefusalPage, idpInitiatedPage, ssoConfirmPage } from "../../src/auth/saml-idp-pages.tsx";
export { resolveAppearance } from "../../src/ui/appearance.ts";
export { UI_MANIFEST } from "../../src/ui/manifest.ts";
