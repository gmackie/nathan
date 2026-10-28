#!/usr/bin/env node
import { readFile, writeFile, access } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { loadConfig, validateConfig, buildPlan } from "./lib/config.mjs";
import { CloudflareClient, inspectDeployment } from "./lib/cloudflare.mjs";
import { ask, yesNo, secretPrompt } from "./lib/prompts.mjs";
import { discoverWrangler, runCli, createGeneratedConfig } from "./lib/wrangler.mjs";

const [command = "help", ...args] = process.argv.slice(2);
const file = args.find(x => x.endsWith(".json")) || "nathan.config.json";
const apply = args.includes("--apply");
function out(value) { console.log(JSON.stringify(value, null, 2)); }
async function init() {
  let existing;
  try { existing = await loadConfig(file); } catch (e) {
    if (e.code !== "ENOENT") {
      // JSON parse and validation errors must not be silently overwritten.
      try { await access(file); throw e; } catch (check) { if (check.code !== "ENOENT") throw e; }
    }
  }
  const detected = await discoverWrangler();
  console.log("Nathan setup. No Cloudflare resources are created by init.");
  const name = await ask("Deployment name", existing?.name || "nathan");
  const hostname = await ask("Identity hostname", existing?.hostname || "auth.example.com");
  const accountId = await ask("Cloudflare account ID (optional for local planning)", existing?.accountId || "");
  const profile = await ask("Security profile (standard/business/high)", existing?.securityProfile || "business");
  const adminEmail = await ask("Admin allowlist email (requires verified account + admin role)", existing?.adminEmails?.[0] || "");
  const appName = await ask("Worker to protect (blank to skip)", existing?.applications?.[0]?.workerName || detected?.name || "");
  const cfg = {
    name, hostname, ...(accountId ? {accountId} : {}), securityProfile: profile,
    adminEmails: adminEmail ? [adminEmail] : [],
    database: { type:"d1", name: existing?.database?.name || name + "-auth" },
    providers: existing?.providers || { google: { enabled:false }, github: { enabled:false } },
    applications: appName ? [{id: appName.replace(/[^a-z0-9-]/g,"-"), kind:"worker",workerName:appName,protection:"binding"}] : []
  };
  const errors = validateConfig(cfg);
  if (errors.length) throw Error(errors.join("\n"));
  out({configuration:cfg,proposal:buildPlan(cfg)});
  if (!(await yesNo("Write configuration?"))) return;
  await writeFile(file, JSON.stringify(cfg,null,2)+"\n", {flag:"w"});
  console.log("Configuration saved (no secrets). Run npm run plan or node scripts/nathan.mjs deploy --apply.");
}
async function planOrDoctor(live) {
  const cfg = await loadConfig(file);
  const result = { proposalOnly:true, resources: buildPlan(cfg) };
  if (process.env.CLOUDFLARE_API_TOKEN && cfg.accountId) {
    const client = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN,cfg.accountId);
    result.discovery = await inspectDeployment(client,cfg);
    if (result.discovery.dnsConflicts.length) result.warning = "DNS records exist. Review manually before deploy.";
  } else result.discovery = "Supply CLOUDFLARE_API_TOKEN and accountId for account/zone/DNS discovery";
  if (live) {
    const issuer = "https://" + cfg.hostname + "/api/auth";
    const url = issuer + "/.well-known/openid-configuration";
    const response = await fetch(url, {signal:AbortSignal.timeout(6000)});
    if (!response.ok) throw Error("Live OIDC discovery HTTP " + response.status);
    const metadata = await response.json();
    if (metadata.issuer !== issuer) throw Error("OIDC discovery issuer mismatch");
    result.live = { issuer:metadata.issuer, authorization_endpoint:metadata.authorization_endpoint, jwks_uri:metadata.jwks_uri };
  }
  out(result);
}
async function provision() {
  const cfg = await loadConfig(file);
  if (!cfg.accountId) throw Error("accountId required for deploy");
  if (!apply) throw Error("Explicit --apply required. First run 'npm run plan'.");
  const client = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN,cfg.accountId);
  const snapshot = await inspectDeployment(client,cfg);
  if (!snapshot.zone || snapshot.zone.status !== "active") throw Error("Auth hostname is not in an active Cloudflare zone");
  if (snapshot.dnsConflicts.length) throw Error("Conflicting DNS records detected; resolve them manually before deploying");
  if (cfg.applications.some(a=>a.protection==="gateway")) {
    throw Error("Gateway deployment requires per-app OIDC client registration and a private upstream. Deploy the IdP first; use docs/deploy.md.");
  }
  out({notice:"This creates a D1 database, migrates schema and publishes the auth Worker", accountId:cfg.accountId, hostname:cfg.hostname});
  if (!(await yesNo("Apply changes to this account and hostname?"))) throw Error("Cancelled");
  const name = cfg.database.name;
  const database = snapshot.existingDatabase || await client.createDatabase(name);
  const dbId = database.uuid || database.id;
  if (!/^[a-f0-9-]{36}$/.test(dbId)) throw Error("Cloudflare did not return a valid D1 database UUID");
  const configPath = await createGeneratedConfig(cfg,dbId);
  console.log("Applying D1 migrations. Generate Better Auth schema first with npm run schema:generate.");
  await runCli("npx",["wrangler","d1","migrations","apply",name,"--remote","--config",configPath]);
  if (!snapshot.existingAuthWorker) {
    const secret = await secretPrompt("Existing or newly generated BETTER_AUTH_SECRET (blank to generate)");
    const value = secret || randomBytes(48).toString("base64url");
    // Secrets must be added immediately after the initial private publish. No public hostname is enabled until after readiness.
    await runCli("npx",["wrangler","deploy","--config",configPath,"--dry-run"]);
    await runCli("npx",["wrangler","deploy","--config",configPath]);
    await runCli("npx",["wrangler","secret","put","BETTER_AUTH_SECRET","--config",configPath],{input:value});
  } else {
    await runCli("npx",["wrangler","deploy","--config",configPath]);
  }
  console.log("Worker deployed. Configure at least one social identity provider and verify OIDC discovery before using it.");
}
(async () => {
  if (command === "init") return init();
  if (command === "plan") return planOrDoctor(false);
  if (command === "doctor") return planOrDoctor(args.includes("--live"));
  if (command === "deploy") return provision();
  console.log("Nathan CLI\n  init                 guided local config\n  plan                 read-only plan + optional Cloudflare discovery\n  doctor [--live]      validate config and optionally OIDC discovery\n  deploy --apply       provision D1 and deploy Worker (requires Cloudflare token)\n\nNo password or OAuth client secret is accepted as a CLI flag.");
})().catch(e => { console.error("Nathan error:",e.message); process.exitCode=1; });
