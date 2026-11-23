/**
 * NATH-37/NATH-34: Nathan's theme is stock Kumo. Hosted-page customisation goes through
 * src/ui/appearance.ts (instance and per-app appearance), never through this file.
 */

/** The `data-theme` value on <html>. */
export const NATHAN_THEME = "nathan";

/** `data-mode` on <html>. "system" follows prefers-color-scheme (see build-ui.mjs). */
export type ThemeMode = "light" | "dark" | "system";
export const THEME_MODES: readonly ThemeMode[] = ["light", "dark", "system"];

/** Tokens an appearance may set (see src/ui/appearance.ts); every other Kumo token stays stock. */
export { APPEARANCE_TOKENS as BRANDABLE_TOKENS } from "./appearance.ts";
import { APPEARANCE_TOKENS } from "./appearance.ts";
export type BrandableToken = string;

export function isBrandableToken(name: string): boolean {
  return APPEARANCE_TOKENS.includes(name);
}
