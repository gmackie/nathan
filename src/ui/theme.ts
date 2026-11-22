/**
 * NATH-37: Nathan's theme on Kumo tokens. The values live in src/ui/theme.css; this module names
 * the theme and the tokens per-app branding may override.
 *
 * Placeholder look until the NATH-34 design pass picks the gmacko theme: Kumo's neutral tokens
 * with today's Nathan orange as the brand colour.
 */

/** The `data-theme` value on <html>. */
export const NATHAN_THEME = "nathan";

/** `data-mode` on <html>. "system" follows prefers-color-scheme (see build-ui.mjs). */
export type ThemeMode = "light" | "dark" | "system";
export const THEME_MODES: readonly ThemeMode[] = ["light", "dark", "system"];

/** Today's Nathan orange, the brand token until NATH-34. */
export const NATHAN_BRAND = "#ef9028";

/**
 * Kumo tokens that per-app branding (NATH-30b) may override, and nothing else. Text colours and
 * every other contrast-critical token are deliberately absent. Primary buttons draw
 * `--nathan-on-brand` text over the brand colour, so NATH-30b must check that pair's contrast
 * (at least 4.5:1) before it accepts an override.
 */
export const BRANDABLE_TOKENS = ["--color-kumo-brand", "--color-kumo-brand-hover"] as const;
export type BrandableToken = (typeof BRANDABLE_TOKENS)[number];

export function isBrandableToken(name: string): name is BrandableToken {
  return (BRANDABLE_TOKENS as readonly string[]).includes(name);
}
