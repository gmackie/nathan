/**
 * NATH-37: every island entry in src/ui/islands/. scripts/build-ui.mjs fails if the directory and
 * this list differ, and renderPage refuses ids that are not in the built manifest.
 *
 * - passkey-button: example React island that hydrates a Kumo Button (no WebAuthn yet).
 * - auto-post: plain script, no React; submits the SAML auto-POST form (AutoPostPage).
 * - security: /security account security panel (admin onboarding, TOTP enrolment, passkeys; NATH-38).
 * - installer-wizard: the hosted installer's wizard (NATH-40, src/ui/pages/installer/).
 * - studio: Identity Studio, the Kumo SPA at /studio (NATH-39, src/ui/pages/studio/).
 */
export const ISLAND_IDS = ["passkey-button", "auto-post", "security", "installer-wizard", "studio"] as const;
export type IslandId = (typeof ISLAND_IDS)[number];

export function isIslandId(id: string): id is IslandId {
  return (ISLAND_IDS as readonly string[]).includes(id);
}
