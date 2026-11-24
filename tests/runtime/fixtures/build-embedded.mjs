/** Install the distribution in a clean app, typecheck its public API, then build the Worker for workerd. */
import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runCli } from "../../../scripts/lib/wrangler.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const { version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const archive = join(root, "dist", "nathan-worker-" + version + ".tgz");
const output = join(root, ".nathan/build-embedded");
const app = await mkdtemp(join(tmpdir(), "nathan-consumer-"));
try {
  await cp(new URL("./embedded/", import.meta.url), app, { recursive: true });
  await writeFile(join(app, "package.json"), JSON.stringify({ name: "library", type: "module", private: true }));
  const tools = join(root, "node_modules");
  // The tarball contains the runtime. The consumer only needs Cloudflare's ambient types to compile.
  await runCli("npm", ["install", "--offline", "--install-links", "--ignore-scripts", "--no-audit", "--no-fund",
    archive, join(tools, "@cloudflare/workers-types")], { cwd: app });
  await runCli(process.execPath, [join(tools, "typescript/bin/tsc"), "--project", "tsconfig.json"], { cwd: app });
  await runCli(join(app, "node_modules/.bin/nathan-worker-admin"), ["--help"], { cwd: app });
  const wrangler = join(tools, "wrangler/bin/wrangler.js");
  await runCli(process.execPath, [wrangler, "deploy", "--dry-run", "--config", "wrangler.jsonc", "--outdir", output], { cwd: app });
  await runCli(process.execPath, [wrangler, "deploy", "--dry-run", "--config", "peer/wrangler.jsonc",
    "--outdir", join(root, ".nathan/build-embedded-peer")], { cwd: app });

  const installed = join(app, "node_modules/@nathan/worker/migrations");
  const migrations = (await readdir(join(root, "migrations"))).filter(name => name.endsWith(".sql")).sort();
  assert.deepEqual((await readdir(installed)).sort(), migrations);
  for (const file of migrations) {
    assert.deepEqual(await readFile(join(installed, file)), await readFile(join(root, "migrations", file)), file);
  }
  await rm(join(output, "migrations"), { recursive: true, force: true });
  await cp(installed, join(output, "migrations"), { recursive: true });
} finally {
  await rm(app, { recursive: true, force: true });
}
