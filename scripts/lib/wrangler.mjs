import { readFile, writeFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";

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
export async function createGeneratedConfig(cfg, databaseId, gateway = null, studioBindings = null) {
  const templateName = gateway ? "wrangler.gateway.jsonc" : "wrangler.auth.jsonc";
  const wrangler = JSON.parse(stripJsonc(await readFile(resolve(templateName), "utf8")));
  wrangler.account_id = cfg.accountId;
  wrangler.main = resolve(wrangler.main);
  for (const database of wrangler.d1_databases || []) database.migrations_dir = resolve(database.migrations_dir);
  // NATH-32: the config's build step runs from the repository root, not .nathan/generated/.
  if (wrangler.build?.command) wrangler.build = { ...wrangler.build, cwd: resolve(wrangler.build.cwd ?? ".") };
  if (!gateway) {
    wrangler.name = cfg.name + "-auth";
    wrangler.routes = [{ pattern: cfg.hostname, custom_domain: true }];
    if (cfg.studioAccess) {
      if (!studioBindings || studioBindings.NATHAN_ADMIN_ORIGIN !== "https://admin." + cfg.hostname)
        throw Error("Verified Studio Access settings required to generate the auth Worker configuration");
      Object.assign(wrangler.vars, studioBindings);
      wrangler.routes.push({ pattern: "admin." + cfg.hostname, custom_domain: true });
    }
    wrangler.vars.NATHAN_ISSUER = "https://" + cfg.hostname;
    wrangler.vars.NATHAN_REALM_APEX = cfg.realm?.apex || "";
    wrangler.vars.NATHAN_ADMIN_EMAILS = (cfg.adminEmails || []).join(",");
    wrangler.vars.NATHAN_SECURITY_PROFILE = cfg.securityProfile;
    wrangler.vars.NATHAN_BOOTSTRAP_REQUIRED = "true";
    wrangler.vars.NATHAN_ADMIN_STEPUP_REQUIRED = "true";
    wrangler.vars.NATHAN_ADMIN_STEPUP_METHOD = cfg.securityProfile === "standard" ? "passkey-or-totp" : "passkey";
    wrangler.d1_databases[0].database_name = cfg.database.name;
    wrangler.d1_databases[0].database_id = databaseId;
  } else {
    wrangler.name = cfg.name + "-" + gateway.id + "-gateway";
    wrangler.routes = [{ pattern: gateway.hostname, custom_domain: true }];
    wrangler.services.find(s => s.binding === "UPSTREAM").service = gateway.workerName;
    // NATH-13: roles and permissions come from the identity Worker's evaluator over RPC.
    const nathanBinding = wrangler.services.find(s => s.binding === "NATHAN");
    nathanBinding.service = cfg.name + "-auth";
    // The identity Worker answers this binding only for the application pinned here.
    nathanBinding.props = { applicationId: gateway.id };
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

// Wrangler's ordinary deploy may upload a version and then activate it in a second API call.
// A single script PUT retains omitted live bindings at the same instant that the code goes live.
export async function uploadIdentityWorker(api, configPath, config, verify, run = runCli) {
  const folder = await mkdtemp(join(tmpdir(), "nathan-worker-upload-"));
  try {
    const bundle = join(folder, "worker.multipart");
    await run("npx", ["wrangler", "deploy", "--config", configPath, "--dry-run", "--outfile", bundle]);
    const bytes = await readFile(bundle);
    const header = bytes.subarray(0, 128).toString("latin1").match(/^--([A-Za-z0-9'-]{1,70})\r\n/);
    if (!header) throw Error("Wrangler produced an invalid multipart Worker bundle");
    const form = await new Response(bytes, { headers: { "Content-Type": "multipart/form-data; boundary=" + header[1] } }).formData();
    const current = await verify();
    await activateIdentityWorker(api, config, form, current.workerMigrationTag);
    await run("npx", ["wrangler", "triggers", "deploy", "--config", configPath]);
  } finally { await rm(folder, { recursive: true, force: true }); }
}

export async function activateIdentityWorker(api, config, form, currentTag) {
  const part = form.get("metadata");
  const metadata = JSON.parse(typeof part === "string" ? part : await part.text());
  if (!form.has(metadata.main_module) || !["plain_text", "json", "secret_text"].every(t => metadata.keep_bindings?.includes(t)))
    throw Error("Worker bundle must retain live variables and secrets");
  const chain = config.migrations ?? [];
  const index = currentTag ? chain.findIndex(step => step.tag === currentTag) : -1;
  if (currentTag && index < 0) throw Error("Live Durable Object migration tag is unknown to this installer");
  const pending = chain.slice(index + 1);
  delete metadata.migrations;
  if (pending.length) metadata.migrations = { ...(currentTag ? { old_tag: currentTag } : {}),
    new_tag: pending.at(-1).tag, steps: pending.map(({ tag, ...operations }) => operations) };
  form.set("metadata", new File([JSON.stringify(metadata)], "metadata.json", { type: "application/json" }));
  await api.request("/accounts/" + api.accountId + "/workers/scripts/" + config.name, { method: "PUT", body: form });
}
