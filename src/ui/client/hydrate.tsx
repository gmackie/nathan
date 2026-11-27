/**
 * NATH-37: browser side of an island. Runs only in the hashed island bundles, never in a Worker.
 *
 * The server moved Kumo's inline style attributes into generated classes (src/ui/csp-styles.ts).
 * Before hydrating, put those declarations back on each element through CSSOM, which CSP allows,
 * and drop the generated class. The DOM then matches what React rendered, so later re-renders
 * that change className or style behave exactly as in a client-only React app.
 */
import type { ComponentType } from "react";
import { hydrateRoot } from "react-dom/client";
import { CSPProvider } from "@cloudflare/kumo/primitives/csp-provider";
import { INLINE_CLASS_PREFIX, INLINE_STYLE_MARKER } from "../csp-styles.ts";
import type { IslandId } from "../island-ids.ts";

/** Copies generated-class declarations back to the elements under `root` as CSSOM styles. */
export function restoreInlineStyles(root: Element): void {
  const rules = new Map<string, CSSStyleDeclaration>();
  for (const sheet of Array.from(document.styleSheets)) {
    const owner = sheet.ownerNode;
    if (!(owner instanceof HTMLStyleElement) || !owner.hasAttribute(INLINE_STYLE_MARKER)) continue;
    for (const rule of Array.from(sheet.cssRules)) {
      if (rule instanceof CSSStyleRule && rule.selectorText.startsWith("." + INLINE_CLASS_PREFIX))
        rules.set(rule.selectorText.slice(1), rule.style);
    }
  }
  const elements = [root, ...Array.from(root.querySelectorAll("[class]"))];
  for (const element of elements) {
    if (!(element instanceof HTMLElement || element instanceof SVGElement)) continue;
    for (const name of Array.from(element.classList)) {
      const style = rules.get(name);
      if (!style) continue;
      for (const property of Array.from(style))
        element.style.setProperty(property, style.getPropertyValue(property), style.getPropertyPriority(property));
      element.classList.remove(name);
    }
    if (element.getAttribute("class") === "") element.removeAttribute("class");
  }
}

/** Hydrates every server-rendered `<Island id>` on the page with `Component`. */
export function hydrateIslands<P extends object>(id: IslandId, Component: ComponentType<P>): void {
  for (const element of Array.from(document.querySelectorAll("[data-nathan-island=\"" + id + "\"]"))) {
    const props = JSON.parse(element.getAttribute("data-props") || "{}") as P;
    // The island container itself is Nathan markup, not React's; restore only its children.
    for (const child of Array.from(element.children)) restoreInlineStyles(child);
    // Same CSP context as the server (src/ui/render.tsx): base-ui renders no inline <style> elements,
    // which the page CSP would block; their rules are in layout.css.
    hydrateRoot(element, <CSPProvider disableStyleElements><Component {...props} /></CSPProvider>);
  }
}
