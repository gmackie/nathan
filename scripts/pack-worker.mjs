/** Pack the mounted Worker, Kumo assets and identity migrations for installation in another app. */
import { chmod, copyFile, cp, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import ts from "typescript";
import { runCli } from "./lib/wrangler.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const { version, engines } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const output = join(root, "dist");
const filename = "nathan-worker-" + version + ".tgz";
await mkdir(join(root, ".nathan"), { recursive: true });
const stage = await mkdtemp(join(root, ".nathan/pack-worker-"));
const pkg = join(stage, "package");

try {
  // Use the same Wrangler configuration, UI build and compatibility settings as the identity Worker.
  const compiled = join(stage, "compiled");
  await runCli(process.execPath, [join(root, "node_modules/wrangler/bin/wrangler.js"), "deploy", "src/auth/embedded.ts",
    "--config", "wrangler.auth.jsonc", "--dry-run", "--outdir", compiled], { cwd: root });
  const runtime = join(pkg, "worker");
  await cp(compiled, runtime, {
    recursive: true, filter: path => !path.endsWith(".map") && path !== join(compiled, "README.md")
  });
  const main = join(runtime, "embedded.js");
  await writeFile(main, (await readFile(main, "utf8")).replace(/\n\/\/# sourceMappingURL=embedded\.js\.map\s*$/, "\n"));

  const declarations = join(stage, "declarations");
  await runCli(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--project", "tsconfig.json",
    "--noEmit", "false", "--declaration", "--emitDeclarationOnly", "--rootDir", ".", "--outDir", declarations], { cwd: root });
  const emitted = join(declarations, "src");
  // Follow the public entry's declaration imports so new API types ship with the same release.
  const publicTypes = ts.createProgram([join(emitted, "auth/embedded.d.ts")], {
    module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, types: [], noLib: true
  });
  for (const { fileName } of publicTypes.getSourceFiles()) {
    if (!fileName.startsWith(emitted + sep)) continue;
    const dest = join(pkg, "types", relative(emitted, fileName));
    await mkdir(dirname(dest), { recursive: true });
    await copyFile(fileName, dest);
  }

  await mkdir(join(pkg, "migrations"));
  for (const file of await readdir(join(root, "migrations"), { withFileTypes: true })) {
    if (file.isFile() && file.name.endsWith(".sql")) {
      await copyFile(join(root, "migrations", file.name), join(pkg, "migrations", file.name));
    }
  }
  const admin = join(pkg, "bin/nathan-worker-admin.mjs");
  await build({
    entryPoints: [join(root, "scripts/worker-admin.mjs")], outfile: admin, bundle: true,
    platform: "node", format: "esm", target: "node22"
  });
  await chmod(admin, 0o755);
  await copyFile(join(root, "LICENSE"), join(pkg, "LICENSE"));
  await copyFile(join(root, "docs/embedded-worker.md"), join(pkg, "README.md"));
  const manifest = {
    name: "@nathan/worker", version, description: "Nathan identity and Kumo Studio for Cloudflare Workers",
    license: "MIT", type: "module", engines,
    main: "./worker/embedded.js", types: "./types/auth/embedded.d.ts",
    exports: { ".": { types: "./types/auth/embedded.d.ts", import: "./worker/embedded.js" } },
    bin: { "nathan-worker-admin": "./bin/nathan-worker-admin.mjs" }
  };
  await writeFile(join(pkg, "package.json"), JSON.stringify(manifest, null, 2) + "\n");
  await runCli("npm", ["pack", "--silent", "--ignore-scripts", "--pack-destination", stage], { cwd: pkg });
  await mkdir(output, { recursive: true });
  await rename(join(stage, filename), join(output, filename));
  console.log("Worker package ready at " + join(output, filename));
} finally {
  await rm(stage, { recursive: true, force: true });
}
