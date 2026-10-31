import { loadConfig } from "./config.mjs";
import { CloudflareClient, inspectDeployment, zoneForHostname } from "./cloudflare.mjs";
import { ask, yesNo, secretPrompt } from "./prompts.mjs";
import { createGeneratedConfig, runCli } from "./wrangler.mjs";
import { randomBytes } from "node:crypto";

export function gatewayChecklist(cfg, app) {
  if (!app || app.kind !== "worker" || !app.workerName || !app.hostname) throw Error("A Worker application with a hostname is required");
  if (app.hostname === cfg.hostname) throw Error("Application hostname must differ from the IdP");
  return {
    application:app.id,
    authIssuer:"https://" + cfg.hostname + "/api/auth",
    gatewayHostname:app.hostname,
    upstream:app.workerName,
    callback:"https://" + app.hostname + "/__nathan/callback",
    backchannelLogout:"https://" + app.hostname + "/__nathan/backchannel",
    requirement:"The original upstream must have no public custom domains, routes, workers.dev, or preview URLs before gateway publication"
  };
}
export async function protectCommand(args,file,apply){
  const cfg=await loadConfig(file);
  const app=cfg.applications.find(x=>x.id===args[0]);
  const plan=gatewayChecklist(cfg,app);
  console.log(JSON.stringify(plan,null,2));
  if(!apply){
    console.log("Proposal only. Register a confidential OIDC client in Nathan Studio first, then use --apply.");
    return;
  }
  if(!cfg.accountId)throw Error("accountId required to protect a Worker");
  const cf=new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN,cfg.accountId);
  const info=await inspectDeployment(cf,cfg);
  const zone=zoneForHostname(await cf.zones(),app.hostname);
  if(!zone||zone.status!=="active")throw Error("Application hostname not in an active Cloudflare zone");
  const exposure=await cf.workerExposure(app.workerName,zone.id);
  if(exposure.unknown.length)throw Error("Cannot prove upstream is private: "+exposure.unknown.join(", "));
  if(exposure.public.length)throw Error("Upstream is still publicly accessible: "+JSON.stringify(exposure.public));
  const oidcClientId=await ask("OIDC client ID (from Nathan Studio)");
  const oidcSecret=await secretPrompt("OIDC client secret (masked)");
  if(!oidcClientId||!oidcSecret)throw Error("Confidential OIDC client credentials required");
  const name=cfg.name+"-"+app.id+"-sessions";
  const available=await cf.databases();
  const database=available.find(x=>x.name===name)||await cf.createDatabase(name);
  const dbId=database.uuid||database.id;
  const config=await createGeneratedConfig(cfg,dbId,{...app,oidcClientId});
  if(!(await yesNo("Publish gateway at "+app.hostname+"?")))throw Error("Cancelled");
  // Private staging before a public custom domain; secrets are never written to disk.
  const fs=await import("node:fs/promises");
  const gateway=JSON.parse(await fs.readFile(config,"utf8"));
  const privateCfg={...gateway,routes:[],workers_dev:false,preview_urls:false};
  const privatePath=config.replace(/\.json$/,".private.json");
  await fs.writeFile(privatePath,JSON.stringify(privateCfg,null,2),{mode:0o600});
  await runCli("npx",["wrangler","d1","migrations","apply",name,"--remote","--config",privatePath]);
  await runCli("npx",["wrangler","deploy","--config",privatePath]);
  await runCli("npx",["wrangler","secret","put","OIDC_CLIENT_SECRET","--config",privatePath],{input:oidcSecret});
  await runCli("npx",["wrangler","secret","put","SESSION_ENCRYPTION_KEY","--config",privatePath],{input:randomBytes(32).toString("base64url")});
  // Recheck just before publication: public state may have changed during deployment.
  const last=await cf.workerExposure(app.workerName,zone.id);
  if(last.unknown.length||last.public.length)throw Error("Upstream exposure changed; leaving gateway unpublished");
  await runCli("npx",["wrangler","deploy","--config",config]);
  console.log("Gateway deployed. Test non-interactive 401, browser login, back-channel logout, and origin isolation before use.");
}
