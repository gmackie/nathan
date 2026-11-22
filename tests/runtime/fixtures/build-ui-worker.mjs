/**
 * NATH-37: builds the test-only UI Worker into <repo>/.nathan/build-ui-fixture, after the UI
 * assets (its pages read their manifest). Absolute --outdir, as in build-upstream.mjs.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
for (const args of [
  [resolve(root, "scripts/build-ui.mjs")],
  [resolve(root, "node_modules/wrangler/bin/wrangler.js"), "deploy",
    "--config", resolve(root, "tests/runtime/fixtures/wrangler.ui.jsonc"),
    "--dry-run", "--outdir", resolve(root, ".nathan/build-ui-fixture")]
]) {
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
