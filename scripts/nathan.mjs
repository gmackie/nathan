#!/usr/bin/env node
import { readFile, writeFile, access } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { loadConfig, validateConfig, buildPlan } from "./lib/config.mjs";
import { CloudflareClient, inspectDeployment } from "./lib/cloudflare.mjs";
import { ask, yesNo, secretPrompt } from "./lib/prompts.mjs";
import { discoverWrangler, runCli, createGeneratedConfig } from "./lib/wrangler.mjs";
import { providerCommand } from "./lib/provider-wizard.mjs";
import { protectCommand } from "./lib/protect-wizard.mjs";
import { adminCommand } from "./lib/admin-wizard.mjs";
import { domainCommand } from "./lib/domain-wizard.mjs";
import { realmForLoginHostname } from "../src/shared/realm.mjs";

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
  let suggestedAccount = existing?.accountId || detected?.account_id || "";
  let suggestedZone = "";
  let availableWorkers = [];
  if (process.env.CLOUDFLARE_API_TOKEN) {
    try {
      const cf = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN);
      const accounts = await cf.accounts();
      if (Array.isArray(accounts) && accounts.length) {
        console.log("Accessible Cloudflare accounts:");
        accounts.slice(0,20).forEach((a,i)=>console.log("  "+(i+1)+". "+a.name+" ("+a.id+")"));
        if (!suggestedAccount && accounts.length === 1) suggestedAccount = accounts[0].id;
      }
    } catch (error) {
      console.error("Cloudflare account discovery unavailable:", error.message);
    }
  }
  const accountId = await ask("Cloudflare account ID (optional for local planning)", suggestedAccount);
  if (process.env.CLOUDFLARE_API_TOKEN && accountId) {
    try {
      const cf = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN,accountId);
      const zones=await cf.zones();
      const active=Array.isArray(zones)?zones.filter(z=>z.status==="active"):[];
      if(active.length) {
        console.log("Active DNS zones:",active.slice(0,15).map(z=>z.name).join(", "));
        suggestedZone=active[0].name;
      }
      const workers=await cf.workers();
      if(Array.isArray(workers)) {
        availableWorkers=workers.map(w=>w.id).filter(Boolean);
        if(availableWorkers.length) console.log("Existing Workers:",availableWorkers.slice(0,20).join(", "));
      }
    } catch (error) {
      console.error("Worker / DNS discovery unavailable:",error.message);
    }
  }
  const hostname = await ask("Identity hostname", existing?.hostname || (suggestedZone?"login."+suggestedZone:"login.example.com"));
  let realm=existing?.realm;
  if(!realm && hostname.startsWith("login.") &&
     await yesNo("Use this as shared OIDC login for the root and authorized subdomains?",false)){
    realm=realmForLoginHostname(hostname);
  }
  const profile = await ask("Security profile (standard/business/high)", existing?.securityProfile || "business");
  const adminEmail = await ask("Admin allowlist email (requires verified account + admin role)", existing?.adminEmails?.[0] || "");
  const appName = await ask("Worker to protect (blank to skip)", existing?.applications?.[0]?.workerName || detected?.name || availableWorkers[0] || "");
  const cfg = {
    name, hostname, ...(realm?{realm}:{}), ...(accountId ? {accountId} : {}), securityProfile: profile,
    adminEmails: adminEmail ? [adminEmail] : [],
    database: { type:"d1", name: existing?.database?.name || name + "-auth" },
    providers: existing?.providers || { google: { enabled:false }, github: { enabled:false } },
    applications: existing?.applications || (appName ? [{id: appName.replace(/[^a-z0-9-]/g,"-"), kind:"worker",workerName:appName,protection:"binding"}] : [])
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
async function provision(forceApply=false) {
  const cfg = await loadConfig(file);
  // A Worker without the matching Better Auth schema cannot serve logins.
  let schema;
  try { schema = await readFile("migrations/0002_better_auth.sql", "utf8"); }
  catch { throw Error("Generated Better Auth migration missing. Run npm run schema:generate; review migrations/0002_better_auth.sql."); }
  if (schema.trim().length < 150) throw Error("Better Auth SQL migration is empty or unexpectedly small");
  if (cfg.securityProfile === "high") throw Error("High-assurance deployment is not supported until validated AAL, FAPI, signing-key and recovery controls pass their release gates");
  if (!cfg.accountId) throw Error("accountId required for deploy");
  if (!apply && !forceApply) throw Error("Explicit --apply required. First run 'npm run plan'.");
  const client = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN,cfg.accountId);
  const snapshot = await inspectDeployment(client,cfg);
  if (!snapshot.zone || snapshot.zone.status !== "active") throw Error("Auth hostname is not in an active Cloudflare zone");
  if (snapshot.dnsConflicts.length) throw Error("Conflicting DNS records detected; resolve them manually before deploying");
  // The IdP is deployed independently. Per-application gateways are registered
  // and published in a separate step after their OIDC clients exist.
  out({notice:"This creates a D1 database, migrates schema and publishes the auth Worker", accountId:cfg.accountId, hostname:cfg.hostname});
  if (!(await yesNo("Apply changes to this account and hostname?"))) throw Error("Cancelled");
  const name = cfg.database.name;
  const database = snapshot.existingDatabase || await client.createDatabase(name);
  const dbId = database.uuid || database.id;
  if (!/^[a-f0-9-]{36}$/.test(dbId)) throw Error("Cloudflare did not return a valid D1 database UUID");
  const configPath = await createGeneratedConfig(cfg,dbId);
  const liveConfig = JSON.parse(await readFile(configPath,"utf8"));
  console.log("Applying reviewed D1 migrations before publishing the identity hostname.");
  await runCli("npx",["wrangler","d1","migrations","apply",name,"--remote","--config",configPath]);
  // A scoped Cloudflare token and an exact administrator allowlist establish
  // ownership for CLI bootstraps. The verified Better Auth user must still
  // sign in and enroll authenticators before privileged UI access is enabled.
  if(cfg.adminEmails?.length){
    const email=cfg.adminEmails[0].trim().toLowerCase();
    const caller="cli:"+cfg.accountId;
    await client.queryDatabase(dbId,
      "INSERT OR IGNORE INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')",
      [caller,email]);
    const rows=await client.queryDatabase(dbId,
      "SELECT cloudflare_user_id,admin_email FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1",[]);
    if(rows.length!==1 || rows[0].cloudflare_user_id!==caller || rows[0].admin_email!==email)
      throw Error("Admin bootstrap ownership mismatch; refusing to publish identity Worker");
  }

  if (cfg.realm) {
    if (!snapshot.zone?.id) throw Error("Cannot verify realm's Cloudflare zone");
    const apex=cfg.realm.apex;
    // The account/zone that owns login.<apex> is the authority for this realm.
    await client.queryDatabase(dbId,
      "INSERT OR IGNORE INTO nathan_domain_realms(apex,issuer_hostname,account_id,zone_id,registered_by) VALUES (?,?,?,?,?)",
      [apex,cfg.hostname,cfg.accountId,snapshot.zone.id,"cli:"+cfg.adminEmails?.[0]||"cli"]);
    const rows=await client.queryDatabase(dbId,
      "SELECT issuer_hostname,account_id,zone_id FROM nathan_domain_realms WHERE apex=? LIMIT 1",[apex]);
    if(rows.length!==1 || rows[0].issuer_hostname!==cfg.hostname ||
       rows[0].account_id!==cfg.accountId || rows[0].zone_id!==snapshot.zone.id)
      throw Error("Existing domain realm does not match the verified account, zone, or issuer");
  }
  if (!snapshot.existingAuthWorker) {
    // Bootstrap without an ingress route. Only expose the hostname after its secret is installed.
    const stagingPath = ".nathan/generated/" + liveConfig.name + ".staging.json";
    const stagingConfig = { ...liveConfig, routes:[], workers_dev:false, preview_urls:false };
    await writeFile(stagingPath,JSON.stringify(stagingConfig,null,2)+"\n",{mode:0o600});
    await runCli("npx",["wrangler","deploy","--config",stagingPath,"--dry-run"]);
    await runCli("npx",["wrangler","deploy","--config",stagingPath]);
    const secret = await secretPrompt("BETTER_AUTH_SECRET (blank to generate securely)");
    const value = secret || randomBytes(48).toString("base64url");
    await runCli("npx",["wrangler","secret","put","BETTER_AUTH_SECRET","--config",stagingPath],{input:value});
    await runCli("npx",["wrangler","secret","put","NATHAN_CONFIG_KEY","--config",stagingPath],{input:randomBytes(32).toString("base64url")});
  }
  // Existing installations retain their current secret, avoiding accidental session invalidation.
  await runCli("npx",["wrangler","deploy","--config",configPath]);
  console.log("Identity Worker published. Configure a trusted login provider and verify OIDC discovery.");
}

async function wizard(){
  console.log("\n🌭 Nathan setup wizard — customer-owned Cloudflare authentication\n");
  console.log("This workflow builds on the CLI installer. No Cloudflare resources are changed without explicit approval.");
  await init();
  let cfg=await loadConfig(file);
  console.log("\nCloudflare resource plan:");
  await planOrDoctor(false);
  if(!process.env.CLOUDFLARE_API_TOKEN){
    console.log("\nSet CLOUDFLARE_API_TOKEN using your secret manager, then run 'npm run wizard' again.");
    console.log("The hosted wizard can instead use Cloudflare OAuth without pasting a token.");
    return;
  }
  if(!cfg.accountId)throw Error("Choose an accountId in nathan.config.json before deploying");
  if(await yesNo("Deploy the Nathan identity Worker and D1 database?")){
    await provision(true);
  }else{
    console.log("Deployment skipped. You can resume by running npm run wizard again.");
    return;
  }
  let provider=await ask("Initial upstream login provider (google/github)","google");
  if(!["google","github"].includes(provider))throw Error("Select google or github");
  await providerCommand(["guide",provider],file,false);
  if(await yesNo("Have you created that OAuth client and want to securely store its credentials?")){
    await providerCommand(["add",provider],file,true);
  }else{
    console.log("Add the provider using 'node scripts/nathan.mjs providers add "+provider+" --apply' before signing in.");
    return;
  }
  if(await yesNo("Add a second provider?")){
    provider=provider==="google"?"github":"google";
    await providerCommand(["guide",provider],file,false);
    if(await yesNo("Store second provider credentials?")){
      await providerCommand(["add",provider],file,true);
    }
  }
  console.log("\nIdentity URL: https://"+cfg.hostname);
  console.log("1. Sign in with your configured provider at https://"+cfg.hostname+"/sign-in");
  console.log("2. Verify your identity account before admin promotion.");
  if(cfg.adminEmails?.length){
    if(await yesNo("Have you signed in as the verified admin and want to promote that account?")){
      await adminCommand(["promote"],file,true);
    }
  }
  console.log("\nIdentity Studio: https://"+cfg.hostname+"/studio");
  console.log("Self-service passkeys and TOTP: https://"+cfg.hostname+"/security");
  console.log("Admin MCP endpoint: https://"+cfg.hostname+"/mcp (read-only by default)");
  console.log("Register external and Worker OIDC clients in Studio. Copy the one-time secret to a secure manager.");
  cfg=await loadConfig(file);
  if(cfg.applications.length && await yesNo("Configure an Access-style gateway for an existing private Worker?")){
    const app=cfg.applications[0];
    if(!app.hostname){
      const hostname=await ask("Protected app hostname (must belong to an active Cloudflare zone)","app."+cfg.hostname.split(".").slice(1).join("."));
      cfg.applications[0]={...app,hostname,protection:"gateway"};
      const validation=validateConfig(cfg);
      if(validation.length)throw Error(validation.join("\n"));
      await writeFile(file,JSON.stringify(cfg,null,2)+"\n",{mode:0o600});
    }
    console.log("Register a confidential OIDC client in Identity Studio using exact callback:");
    await protectCommand([cfg.applications[0].id],file,false);
    console.log("Make sure the original Worker has no public routes, workers.dev or preview URLs.");
    if(await yesNo("OIDC client registered and upstream proven private; deploy gateway?")){
      await protectCommand([cfg.applications[0].id],file,true);
    }
  }
  console.log("\nNathan setup complete. Run 'npm run doctor -- --live' to verify discovery and check the staging login, session and logout flows.");
  console.log("Do not deploy for regulated or production workloads before the security release gates pass.");
}

(async () => {
  if (command === "init") return init();
  if (command === "wizard") return wizard();
  if (command === "plan") return planOrDoctor(false);
  if (command === "doctor") return planOrDoctor(args.includes("--live"));
  if (command === "deploy") return provision();
  if (command === "providers") return providerCommand(args.filter(a=>a!=="--apply"&&!a.endsWith(".json")),file,apply);
  if (command === "protect") return protectCommand(args.filter(a=>a!=="--apply"&&!a.endsWith(".json")),file,apply);
  if (command === "admin") return adminCommand(args.filter(a=>a!=="--apply"&&!a.endsWith(".json")),file,apply);
  if (command === "domains") return domainCommand(args.filter(a=>!a.endsWith(".json")),file);
  console.log("Nathan CLI\n  wizard               guided end-to-end installer\n  init                 guided local config\n  plan                 read-only plan + optional Cloudflare discovery\n  doctor [--live]      validate config and optionally OIDC discovery\n  deploy --apply       provision D1 and deploy Worker (requires Cloudflare token)\n  providers guide      OAuth callback and provider-specific setup\n  providers add --apply    configure provider secrets securely\n  protect <app>        plan a gateway for a private upstream\n  protect <app> --apply   deploy only after public-origin isolation\n  admin promote --apply     elevate a verified allowlisted user\n  domains discover         Cloudflare DNS/Worker host inventory and exact OIDC callbacks\n  domains callback <host>  Exact root/subdomain OIDC callback\n  domains routes           Wildcard proxy routing preview (not applied)\n\nNo password or OAuth client secret is accepted as a CLI flag.");
})().catch(e => { console.error("Nathan error:",e.message); process.exitCode=1; });
