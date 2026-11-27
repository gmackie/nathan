/**
 * NATH-37: the UI asset manifest written by scripts/build-ui.mjs (git-ignored, rebuilt by every
 * build:* script) and bundled into the Worker. It names each hashed asset and its SRI hash.
 */
import data from "./generated/ui-manifest.json" with { type: "json" };

export interface UiAsset {
  /** Same-origin path under /__nathan/ui/. */
  src: string;
  /** SRI hash, "sha384-...". */
  integrity: string;
}

export interface UiIsland extends UiAsset {
  /** Every chunk the island imports, directly or not. */
  imports: UiAsset[];
}

export interface UiManifest {
  version: 1;
  base: string;
  css: UiAsset;
  islands: Record<string, UiIsland>;
}

const ASSET = /^\/__nathan\/ui\/[A-Za-z0-9_-]+\.(css|js)$/;
const SRI = /^sha384-[A-Za-z0-9+/]{64}$/;

/** Rejects a manifest that would put anything but same-origin /__nathan/ui/ assets on a page. */
export function validateManifest(value: unknown): UiManifest {
  const m = value as UiManifest;
  const asset = (a: UiAsset) => {
    if (!a || !ASSET.test(a.src) || !SRI.test(a.integrity)) throw Error("Invalid UI asset in manifest");
  };
  if (!m || m.version !== 1 || m.base !== "/__nathan/ui/" || !m.islands || typeof m.islands !== "object")
    throw Error("Invalid UI manifest");
  asset(m.css);
  for (const island of Object.values(m.islands)) {
    asset(island);
    if (!Array.isArray(island.imports)) throw Error("Invalid UI manifest");
    island.imports.forEach(asset);
  }
  return m;
}

export const UI_MANIFEST: UiManifest = validateManifest(data);
