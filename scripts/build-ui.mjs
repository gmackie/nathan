#!/usr/bin/env node
/**
 * NATH-37: builds Nathan's UI static assets (served by the Worker itself, see src/ui/assets.ts).
 *
 *   .nathan/ui-assets/__nathan/ui/nathan-<hash>.css   Kumo standalone CSS + system mode + theme + layout
 *   .nathan/ui-assets/__nathan/ui/<island>-<hash>.js  one ESM entry per src/ui/islands/*.{ts,tsx}
 *   .nathan/ui-assets/__nathan/ui/chunk-<hash>.js     shared code (React, react-dom, Kumo) in one vendor chunk
 *   src/ui/generated/ui-manifest.json                 file names and SRI hashes, bundled into the Worker
 *   src/ui/generated/ui-assets.json                   the same files' contents, bundled into the Worker and
 *                                                     served by src/ui/assets.ts (no static-assets binding, so
 *                                                     CLI, ForgeGraph and hosted-installer deploys all carry them)
 *
 * Every file lives under /__nathan/ui/ (the gateway already reserves /__nathan/), so an asset
 * can never shadow a Worker route. Names carry content hashes, so caching them forever is safe.
 * echarts and shiki (Kumo's chart and code components) must never reach a bundle: the build fails
 * if any island pulls them in.
 */
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PREFIX = "__nathan/ui";
const assetsRoot = join(root, ".nathan/ui-assets");
const outDir = join(assetsRoot, PREFIX);
const islandsDir = join(root, "src/ui/islands");
const manifestPath = join(root, "src/ui/generated/ui-manifest.json");
const FORBIDDEN = /node_modules\/(echarts|zrender|shiki|@shikijs)\//;

const sri = bytes => "sha384-" + createHash("sha384").update(bytes).digest("base64");
const shortHash = bytes => createHash("sha256").update(bytes).digest("hex").slice(0, 16);

await rm(assetsRoot, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

// ---- CSS -------------------------------------------------------------------------------------
const kumoCss = await readFile(join(root, "node_modules/@cloudflare/kumo/dist/styles/kumo-standalone.css"), "utf8");
// Kumo switches to its dark tokens only on [data-mode=dark]. For data-mode="system", repeat that
// rule's declarations under prefers-color-scheme: dark so the page follows the OS without script.
const DARK_SELECTOR = ":root[data-mode=dark],[data-mode=dark]:not([data-theme]),[data-mode=dark] [data-theme=kumo],[data-theme=kumo][data-mode=dark],[data-theme=kumo] [data-mode=dark]{";
const darkStart = kumoCss.indexOf(DARK_SELECTOR);
if (darkStart < 0 || kumoCss.indexOf(DARK_SELECTOR, darkStart + 1) >= 0)
  throw Error("Kumo's dark token rule changed shape; update build-ui.mjs (system mode)");
const darkBody = kumoCss.slice(darkStart + DARK_SELECTOR.length, kumoCss.indexOf("}", darkStart));
if (darkBody.includes("{") || !darkBody.includes("--color-kumo-base:")) throw Error("Unexpected Kumo dark token rule");
const systemCss = "@media (prefers-color-scheme:dark){:root[data-mode=system]{color-scheme:dark;" + darkBody + "}}";
const css = [
  kumoCss,
  "/* Nathan: data-mode=system */", systemCss,
  await readFile(join(root, "src/ui/theme.css"), "utf8"),
  await readFile(join(root, "src/ui/layout.css"), "utf8")
].join("\n");
const cssBytes = Buffer.from(css);
const cssFile = "nathan-" + shortHash(cssBytes) + ".css";
await writeFile(join(outDir, cssFile), cssBytes);

// ---- Islands ---------------------------------------------------------------------------------
const { ISLAND_IDS } = await import(pathToFileURL(join(root, "src/ui/island-ids.ts")).href);
const entries = (await readdir(islandsDir)).filter(f => /\.(ts|tsx)$/.test(f) && !f.endsWith(".d.ts")).sort();
const ids = entries.map(f => basename(f, extname(f)));
if (ids.join() !== [...ISLAND_IDS].sort().join())
  throw Error("src/ui/islands/ (" + ids.join(", ") + ") does not match ISLAND_IDS in src/ui/island-ids.ts");

const result = await build({
  absWorkingDir: root,
  entryPoints: {
    // A synthetic entry that shares React, react-dom and Kumo's Button with the islands, so esbuild
    // splits them into one vendor chunk every island page reuses from cache. Nothing loads it.
    "_vendor": join(root, "src/ui/client/vendor.ts"),
    ...Object.fromEntries(entries.map((f, n) => [ids[n], join(islandsDir, f)]))
  },
  outdir: outDir,
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "browser",
  target: ["es2022", "chrome111", "firefox113", "safari16.4"],
  jsx: "automatic",
  minify: true,
  sourcemap: false,
  legalComments: "eof",
  entryNames: "[name]-[hash]",
  chunkNames: "chunk-[hash]",
  define: { "process.env.NODE_ENV": "\"production\"" },
  metafile: true,
  logLevel: "warning",
  // Kumo marks modules "use client"; that directive means nothing to a browser bundle.
  logOverride: { "module-level-directive": "silent" }
});

const forbidden = Object.keys(result.metafile.inputs).filter(p => FORBIDDEN.test(p));
if (forbidden.length) throw Error("An island bundles echarts or shiki: " + forbidden.join(", "));

const outputs = result.metafile.outputs;
const fileName = path => relative(outDir, resolve(root, path)).split("\\").join("/");
const describe = async name => ({ src: "/" + PREFIX + "/" + name, integrity: sri(await readFile(join(outDir, name))) });
const islands = {};
for (const [path, output] of Object.entries(outputs)) {
  if (!output.entryPoint || output.entryPoint.endsWith("client/vendor.ts")) continue;
  const id = basename(output.entryPoint, extname(output.entryPoint));
  const imports = [];
  const walk = target => {
    for (const imp of outputs[target]?.imports ?? []) {
      if (imp.external) throw Error("Island " + id + " imports an external module: " + imp.path);
      if (imports.includes(imp.path)) continue;
      imports.push(imp.path);
      walk(imp.path);
    }
  };
  walk(path);
  islands[id] = { ...(await describe(fileName(path))), imports: await Promise.all(imports.map(p => describe(fileName(p)))) };
}
for (const id of ISLAND_IDS) if (!islands[id]) throw Error("Island " + id + " was not built");
// The synthetic vendor entry only shaped the chunks; don't publish it.
for (const [path, output] of Object.entries(outputs))
  if (output.entryPoint?.endsWith("client/vendor.ts")) await rm(resolve(root, path));

// ---- Manifest and bundled asset contents ---------------------------------------------------
const manifest = {
  version: 1,
  base: "/" + PREFIX + "/",
  css: await describe(cssFile),
  islands: Object.fromEntries(Object.entries(islands).sort(([a], [b]) => a.localeCompare(b)))
};
await mkdir(dirname(manifestPath), { recursive: true });
await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
const TYPES = { css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8" };
const bundled = {};
for (const name of (await readdir(outDir)).sort()) {
  const bytes = await readFile(join(outDir, name));
  const text = bytes.toString("utf8");
  // The Worker re-encodes the string as UTF-8; the bytes must round-trip exactly or SRI fails.
  if (!Buffer.from(text, "utf8").equals(bytes)) throw Error(name + " is not valid UTF-8");
  bundled["/" + PREFIX + "/" + name] = { type: TYPES[extname(name).slice(1)], body: text };
}
await writeFile(join(dirname(manifestPath), "ui-assets.json"), JSON.stringify(bundled) + "\n");

const sizes = [];
for (const name of (await readdir(outDir)).sort()) {
  const bytes = await readFile(join(outDir, name));
  sizes.push(name + " " + bytes.length + " B (" + gzipSync(bytes).length + " B gz)");
}
console.log("Nathan UI assets in " + relative(root, assetsRoot) + ":\n  " + sizes.join("\n  "));
