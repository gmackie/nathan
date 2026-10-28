import { readFile, writeFile, mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { resolve } from "node:path";

export function stripJsonc(input) {
  let result = "", inside = false, escaped = false, line = false, block = false;
  for (let i = 0; i < input.length; i++) {
    const c = input[i], n = input[i+1];
    if (line) { if (c === "\n") { line = false; result += "\n"; } continue; }
    if (block) { if (c === "*" && n === "/") { block = false; i++; } continue; }
    if (inside) { result += c; if (escaped) escaped = false; else if (c === "\\") escaped = true; else if (c === '"') inside = false; continue; }
    if (c === '"') { inside = true; result += c; continue; }
    if (c === "/" && n === "/") { line = true; i++; continue; }
    if (c === "/" && n === "*") { block = true; i++; continue; }
    result += c;
  }
  return result.replace(/,\s*([}\]])/g, "$1");
}
export async function discoverWrangler(path = "wrangler.jsonc") {
  try { return JSON.parse(stripJsonc(await readFile(path, "utf8"))); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
}
export function runCli(command, args, { input, cwd } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: ["pipe", "inherit", "inherit"], shell: false });
    child.on("error", reject);
    child.on("close", code => code === 0 ? resolve() : reject(Error(command + " exited with status " + code)));
    if (input !== undefined) child.stdin.end(input + "\n"); else child.stdin.end();
  });
}
export async function createGeneratedConfig(cfg, databaseId, gateway = null) {
  const templateName = gateway ? "wrangler.gateway.jsonc" : "wrangler.auth.jsonc";
  const wrangler = JSON.parse(stripJsonc(await readFile(resolve(templateName), "utf8")));
  wrangler.account_id = cfg.accountId;
  wrangler.main = resolve(wrangler.main);
  for (const database of wrangler.d1_databases || []) database.migrations_dir = resolve(database.migrations_dir);
  if (!gateway) {
    wrangler.name = cfg.name + "-auth";
    wrangler.routes = [{ pattern: cfg.hostname, custom_domain: true }];
    wrangler.vars.NATHAN_ISSUER = "https://" + cfg.hostname;
    wrangler.vars.NATHAN_REALM_APEX = cfg.realm?.apex || "";
    wrangler.vars.NATHAN_ADMIN_EMAILS = (cfg.adminEmails || []).join(",");
    wrangler.vars.NATHAN_SECURITY_PROFILE = cfg.securityProfile;
    wrangler.vars.NATHAN_BOOTSTRAP_REQUIRED = "true";
    wrangler.d1_databases[0].database_name = cfg.database.name;
    wrangler.d1_databases[0].database_id = databaseId;
  } else {
    wrangler.name = cfg.name + "-" + gateway.id + "-gateway";
    wrangler.routes = [{ pattern: gateway.hostname, custom_domain: true }];
    wrangler.services[0].service = gateway.workerName;
    wrangler.vars.PUBLIC_ORIGIN = "https://" + gateway.hostname;
    wrangler.vars.APPLICATION_ID = gateway.id;
    wrangler.vars.NATHAN_ISSUER = "https://" + cfg.hostname + "/api/auth";
    wrangler.vars.OIDC_CLIENT_ID = gateway.oidcClientId || "REGISTER_CLIENT_FIRST";
    wrangler.d1_databases[0].database_name = cfg.name + "-" + gateway.id + "-sessions";
    wrangler.d1_databases[0].database_id = databaseId;
  }
  await mkdir(".nathan/generated", { recursive: true, mode: 0o700 });
  const path = ".nathan/generated/" + wrangler.name + ".json";
  await writeFile(path, JSON.stringify(wrangler, null, 2) + "\n", { mode: 0o600 });
  return path;
}
