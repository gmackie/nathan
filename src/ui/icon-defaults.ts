/**
 * NATH-37: icon defaults shared by src/ui/icons.tsx and islands. Islands import single icons from
 * @phosphor-icons/react/dist/ssr/<Name> plus these defaults, not the icon map, which would pull
 * every mapped icon into the island bundle.
 *
 * Defaults (the NATH-34 design pass may change them): weight "regular", 20 px, currentColor.
 * Icons are decorative (aria-hidden) unless they have an accessible label.
 */
import type { IconWeight } from "@phosphor-icons/react";

export const ICON_WEIGHT: IconWeight = "regular";
export const ICON_SIZE = 20;

/** ARIA attributes for an icon: labelled image, or hidden decoration. */
export function iconA11y(label?: string): { role: "img"; "aria-label": string } | { "aria-hidden": true } {
  return label ? { role: "img", "aria-label": label } : { "aria-hidden": true };
}
