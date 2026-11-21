/**
 * Builds the test-only upstream Worker into <repo>/.nathan/build-upstream.
 * Wrangler resolves a relative --outdir against the config's directory for the bundle but against
 * the working directory for its README, so pass an absolute path computed from this file.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const result = spawnSync(process.execPath, [
  resolve(root, "node_modules/wrangler/bin/wrangler.js"), "deploy",
  "--config", resolve(root, "tests/runtime/fixtures/wrangler.upstream.jsonc"),
  "--dry-run", "--outdir", resolve(root, ".nathan/build-upstream")
], { cwd: root, stdio: "inherit" });
process.exit(result.status ?? 1);
