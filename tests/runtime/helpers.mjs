/** Shared helpers for tests that run built Worker bundles in workerd via Miniflare. */
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

export const COMPAT = { compatibilityDate: "2026-10-27", compatibilityFlags: ["nodejs_compat"] };

export function bundle(name) {
  const path = ".nathan/build-" + name + "/worker.js";
  if (!existsSync(path)) throw Error("Missing " + path + ": run `npm run test:runtime`, which builds bundles first");
  return path;
}

/** Applies a migration file statement by statement; D1's exec() rejects multi-line statements. */
export async function migrate(db, file) {
  const sql = readFileSync(file, "utf8")
    .split("\n").filter(line => !line.trim().startsWith("--")).join("\n");
  for (const statement of sql.split(/;\s*(?:\n|$)/).map(s => s.trim()).filter(Boolean))
    await db.prepare(statement).run();
}

export function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}
export const randomKey = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

export function cookiesOf(response) {
  const jar = {};
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const index = pair.indexOf("=");
    jar[pair.slice(0, index)] = { value: pair.slice(index + 1), raw: line };
  }
  return jar;
}

/** Miniflare 5 uses a config schema; convert from the documented v4 option shape. */
export async function start(options) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, ...COMPAT, ...options }));
  await mf.ready;
  return mf;
}

/**
 * The built identity Worker with every top-level migration applied. Caller disposes it.
 * `options` adds Miniflare options such as `outboundService` (mocked outbound HTTP, including
 * workerd's node:dns, which resolves over DNS-over-HTTPS at cloudflare-dns.com).
 */
export async function authWorker(host, vars = {}, options = {}) {
  const mf = await start({
    ...options,
    scriptPath: bundle("auth"),
    d1Databases: { DB: "auth-db-" + crypto.randomUUID() },
    durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
    bindings: {
      NATHAN_ISSUER: "https://" + host, NATHAN_ADMIN_EMAILS: "admin@example.test",
      NATHAN_SECURITY_PROFILE: "business", NATHAN_BOOTSTRAP_REQUIRED: "true",
      NATHAN_INSTALL_ACTIVE: "true", NATHAN_MCP_WRITE_ENABLED: "false", NATHAN_REALM_APEX: "",
      ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false", NATHAN_ADMIN_STEPUP_REQUIRED: "true",
      BETTER_AUTH_SECRET: randomKey() + randomKey(), NATHAN_CONFIG_KEY: randomKey(), ...vars
    }
  });
  const db = await mf.getD1Database("DB");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort())
    await migrate(db, "migrations/" + file);
  return mf;
}
