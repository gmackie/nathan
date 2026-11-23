/**
 * NATH-32 (K0 follow-up): the Worker serves its own hashed UI assets.
 *
 * scripts/build-ui.mjs writes every CSS and island file under /__nathan/ui/ into
 * src/ui/generated/ui-assets.json, which is bundled into the Worker module. Serving from the
 * module rather than a Workers static-assets binding means every deploy path gets the assets with
 * no extra upload step: the CLI wizard, ForgeGraph, and the hosted installer (whose sealed
 * releases carry Worker modules only). The bytes are the ones the manifest's SRI hashes pin.
 *
 * Only exact manifest paths are served, GET and HEAD only, with immutable caching (names carry
 * content hashes), nosniff and CORP same-origin. Anything else under /__nathan/ui/ is a 404 that
 * is never cached.
 */
import data from "./generated/ui-assets.json";
import { UI_MANIFEST } from "./manifest.ts";

interface UiAssetFile { type: string; body: string }

const PREFIX = "/__nathan/ui/";
const TYPES: Record<string, string> = { css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8" };

function load(value: unknown): ReadonlyMap<string, UiAssetFile> {
  if (!value || typeof value !== "object") throw Error("Invalid UI assets");
  const files = new Map<string, UiAssetFile>();
  for (const [path, file] of Object.entries(value as Record<string, UiAssetFile>)) {
    const ext = /^\/__nathan\/ui\/[A-Za-z0-9_-]+\.(css|js)$/.exec(path)?.[1];
    if (!ext || !file || typeof file.body !== "string" || file.type !== TYPES[ext]) throw Error("Invalid UI asset " + path);
    files.set(path, file);
  }
  const m = UI_MANIFEST;
  for (const asset of [m.css, ...Object.values(m.islands).flatMap(i => [i, ...i.imports])])
    if (!files.has(asset.src)) throw Error("UI asset missing from the bundle: " + asset.src);
  return files;
}

const FILES = load(data);

/** The response for a /__nathan/ui/ request, or null for any other path. */
export function serveUiAsset(request: Request): Response | null {
  const { pathname } = new URL(request.url);
  if (!pathname.startsWith(PREFIX)) return null;
  const common = { "X-Content-Type-Options": "nosniff", "Cross-Origin-Resource-Policy": "same-origin" };
  if (request.method !== "GET" && request.method !== "HEAD")
    return new Response("Method not allowed", { status: 405, headers: { ...common, Allow: "GET, HEAD", "Cache-Control": "no-store" } });
  const file = FILES.get(pathname);
  if (!file) return new Response("Not found", { status: 404, headers: { ...common, "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" } });
  return new Response(request.method === "HEAD" ? null : file.body, {
    headers: { ...common, "Content-Type": file.type, "Cache-Control": "public, max-age=31536000, immutable" }
  });
}
