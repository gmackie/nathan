/**
 * NATH-37: every island entry in src/ui/islands/. scripts/build-ui.mjs fails if the directory and
 * this list differ, and renderPage refuses ids that are not in the built manifest.
 *
 * - passkey-button: example React island that hydrates a Kumo Button (no WebAuthn yet).
 * - auto-post: plain script, no React; submits the SAML auto-POST form (AutoPostPage).
 * - sign-in: plain script, no React; the hosted sign-in page (NATH-38, src/auth/hosted-pages.tsx).
 * - oauth-consent: plain script, no React; Allow/Deny on the OIDC consent page (NATH-38).
 */
export const ISLAND_IDS = ["passkey-button", "auto-post", "sign-in", "oauth-consent"] as const;
export type IslandId = (typeof ISLAND_IDS)[number];

export function isIslandId(id: string): id is IslandId {
  return (ISLAND_IDS as readonly string[]).includes(id);
}
