/**
 * NATH-37: renderPage(), the CSP-safe server renderer every Kumo page will use (K1 onwards).
 *
 *   React element ─ renderToString ─ style="" → generated classes ─ document shell ─ checks ─ Response
 *
 * - No inline style attributes, no inline event handlers. Kumo's style attributes become classes
 *   in one nonce'd <style> block (src/ui/csp-styles.ts); a final scan throws if any remain.
 * - Scripts only for islands: hashed same-origin modules with SRI and the page nonce. A page
 *   without islands has no <script> at all and sends script-src 'none'.
 * - The same security headers as today's page() in src/auth/ui.ts (src/ui/headers.ts).
 *
 * CSS delivery: Kumo's standalone CSS plus the Nathan theme is a hashed same-origin static asset
 * (/__nathan/ui/nathan-<hash>.css), referenced with <link rel=stylesheet integrity>, not inlined.
 * It is about 150 KB (23 KB gzip). Inlined, it would ride along with every HTML response, and
 * those are Cache-Control: no-store, so every sign-in, consent and refusal page would carry it
 * again. As an immutable asset the browser fetches it once per release. SRI pins the exact bytes,
 * and the page's own markup stays about 2–5 KB.
 */
import type { ReactElement } from "react";
import { renderToString } from "react-dom/server";
import { CSPProvider } from "@cloudflare/kumo/primitives/csp-provider";
import { assertCspSafe, escapeHtml, INLINE_STYLE_MARKER, moveInlineStylesToClasses, rewriteTags } from "./csp-styles.ts";
import { newNonce, securityHeaders } from "./headers.ts";
import { isIslandId, type IslandId } from "./island-ids.ts";
import { UI_MANIFEST, validateManifest, type UiAsset, type UiManifest } from "./manifest.ts";
import { NATHAN_THEME, THEME_MODES, type ThemeMode } from "./theme.ts";

export interface RenderPageOptions {
  /** Document title; " · Nathan" is appended. */
  title: string;
  /** BCP 47 language tag, default "en". */
  lang?: string;
  /** HTTP status, default 200. */
  status?: number;
  /** Colour mode, default "system" (follows prefers-color-scheme). */
  theme?: ThemeMode;
  /** Islands this page hydrates. Every `<Island>` in the markup must be listed. */
  islands?: readonly IslandId[];
  /** Extra classes for <body>. */
  bodyClass?: string;
  /** CSP form-action sources: 'self' (default), 'none' or bare https origins. */
  formAction?: readonly string[];
  /** Page-specific extra headers (for example Set-Cookie). Security headers cannot be overridden. */
  headers?: HeadersInit;
  /** For tests: a manifest other than the built one. */
  manifest?: UiManifest;
}

const LANG = /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/;

function islandsInMarkup(html: string): Set<string> {
  const found = new Set<string>();
  rewriteTags(html, tag => {
    const id = tag.attributes.find(a => a.name === "data-nathan-island")?.value;
    if (id != null) found.add(id);
    return undefined;
  });
  return found;
}

const integrityAttrs = (asset: UiAsset) => " href=\"" + escapeHtml(asset.src) + "\" integrity=\"" + escapeHtml(asset.integrity) + "\"";

export function renderPage(element: ReactElement, opts: RenderPageOptions): Response {
  const { title, lang = "en", status = 200, theme = "system", islands = [], bodyClass, formAction, headers } = opts;
  const manifest = opts.manifest ? validateManifest(opts.manifest) : UI_MANIFEST;
  if (typeof title !== "string" || !title) throw Error("renderPage needs a title");
  if (!LANG.test(lang)) throw Error("Invalid lang");
  if (!THEME_MODES.includes(theme)) throw Error("Invalid theme mode");
  if (!Number.isInteger(status) || status < 200 || status > 599) throw Error("Invalid status");
  if (new Set(islands).size !== islands.length) throw Error("Duplicate island");
  for (const id of islands) if (!isIslandId(id) || !Object.hasOwn(manifest.islands, id)) throw Error("Unknown island: " + id);

  const nonce = newNonce();
  const rendered = renderToString(<CSPProvider nonce={nonce}>{element}</CSPProvider>);
  for (const id of islandsInMarkup(rendered))
    if (!(islands as readonly string[]).includes(id)) throw Error("Island " + id + " is rendered but not in renderPage's islands");
  const { html: body, css } = moveInlineStylesToClasses(rendered);

  let head = "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" + escapeHtml(title) + " · Nathan</title>";
  if (islands.length) {
    // Integrity for every module the islands load. Import maps carry it for chunks imported by
    // an entry; modulepreload carries it for browsers without import map integrity.
    const modules = new Map<string, string>();
    for (const id of islands) {
      const island = manifest.islands[id];
      for (const asset of [island, ...island.imports]) modules.set(asset.src, asset.integrity);
    }
    head += "<script type=\"importmap\" nonce=\"" + nonce + "\">" +
      JSON.stringify({ integrity: Object.fromEntries(modules) }).replaceAll("<", "\\u003c") + "</script>";
  }
  head += "<link rel=\"stylesheet\"" + integrityAttrs(manifest.css) + ">";
  if (css) head += "<style nonce=\"" + nonce + "\" " + INLINE_STYLE_MARKER + ">" + css + "</style>";
  if (islands.length) {
    const preloaded = new Set<string>();
    for (const id of islands) for (const asset of manifest.islands[id].imports) {
      if (preloaded.has(asset.src)) continue;
      preloaded.add(asset.src);
      head += "<link rel=\"modulepreload\"" + integrityAttrs(asset) + ">";
    }
    for (const id of islands) {
      const island = manifest.islands[id];
      head += "<script type=\"module\" src=\"" + escapeHtml(island.src) + "\" integrity=\"" + escapeHtml(island.integrity) +
        "\" nonce=\"" + nonce + "\"></script>";
    }
  }

  const bodyClasses = "nathan-body" + (bodyClass ? " " + bodyClass : "");
  const html = "<!doctype html><html lang=\"" + escapeHtml(lang) + "\" data-theme=\"" + NATHAN_THEME + "\" data-mode=\"" + theme + "\">" +
    "<head>" + head + "</head><body class=\"" + escapeHtml(bodyClasses) + "\">" + body + "</body></html>";
  assertCspSafe(html, nonce, { allowScripts: islands.length > 0 });

  return new Response(html, {
    status,
    headers: securityHeaders({ nonce, scripts: islands.length > 0, formAction }, headers)
  });
}
