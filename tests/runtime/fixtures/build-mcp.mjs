/**
 * Builds the test-only remote MCP server Worker (NATH-14) into <repo>/.nathan/build-mcp, with an
 * absolute --outdir for the same reason as build-upstream.mjs.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const result = spawnSync(process.execPath, [
  resolve(root, "node_modules/wrangler/bin/wrangler.js"), "deploy",
  "--config", resolve(root, "tests/runtime/fixtures/wrangler.mcp.jsonc"),
  "--dry-run", "--outdir", resolve(root, ".nathan/build-mcp")
], { cwd: root, stdio: "inherit" });
process.exit(result.status ?? 1);
