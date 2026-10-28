#!/usr/bin/env node
/**
 * Bootstrap a self-hosted Nathan browser installer.
 * Subsequent customer deployments use Cloudflare OAuth; no CLI/API token is
 * ever sent to the browser installer.
 */
import { randomBytes } from "node:crypto";
import { readFile,writeFile,mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { CloudflareClient, zoneForHostname } from "./lib/cloudflare.mjs";
import { ask,yesNo,secretPrompt } from "./lib/prompts.mjs";
import { stripJsonc,runCli } from "./lib/wrangler.mjs";

async function main(){
  console.log("\n🌭 Nathan hosted installer bootstrap\n");
  console.log("Requires a scoped CLOUDFLARE_API_TOKEN in the environment.");
  console.log("This configures one installer Worker and its isolated D1 database.\n");
  const api=new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN);
  const accounts=await api.accounts();
  if(!Array.isArray(accounts)||!accounts.length)throw Error("No accessible Cloudflare accounts");
  accounts.forEach((a,i)=>console.log("  "+(i+1)+". "+a.name+" ("+a.id+")"));
  const accountId=await ask("Account ID",accounts.length===1?accounts[0].id:"");
  if(!accounts.some(a=>a.id===accountId))throw Error("Account ID is not accessible");
  const cf=new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN,accountId);
  const zones=(await cf.zones()).filter(z=>z.status==="active");
  if(!zones.length)throw Error("A Cloudflare-managed active zone is required");
  console.log("Active zones:",zones.map(z=>z.name).join(", "));
  const hostname=await ask("Installer hostname","install."+zones[0].name);
  const zone=zoneForHostname(zones,hostname);
  if(!zone||!/^[a-z0-9.-]+$/.test(hostname)||hostname.includes(".."))
    throw Error("Invalid hostname or no active managed zone");
  const workerName=await ask("Installer Worker name","nathan-installer");
  if(!/^[a-z][a-z0-9-]{0,62}$/.test(workerName))throw Error("Invalid Worker name");
  const callback="https://"+hostname+"/api/callback";
  console.log("\nCloudflare OAuth client setup:");
  console.log("1. Open https://dash.cloudflare.com → Account → Manage Account → OAuth clients.");
  console.log("2. Use authorization code + refresh token, client_secret_basic, and PKCE S256.");
  console.log("3. Exact callback URL: "+callback);
  const scopes="user-details.read account-settings.read zone.read workers-scripts.admin workers-routes.write d1.write";
  console.log("4. Suggested required scopes: "+scopes);
  console.log("5. Confirm the scope IDs with 'cf oauth-scopes list' in your current Cloudflare CLI.");
  if(!(await yesNo("I have configured the OAuth client and permissions?")))throw Error("Create OAuth client before setup");
  const oauthClientId=await ask("Cloudflare OAuth client ID");
  const oauthSecret=await secretPrompt("Cloudflare OAuth client secret (masked)");
  const installedScopes=await ask("Granted OAuth scopes",scopes);
  if(!oauthClientId||!oauthSecret||!installedScopes)throw Error("OAuth credentials and scopes required");
  const [workers,databases,dns]=await Promise.all([
    cf.workers(),cf.databases(),cf.dnsRecords(zone.id,hostname)
  ]);
  if(dns.length)throw Error("Installer hostname has existing DNS records; no changes made");
  if(workers.some(w=>w.id===workerName)){
    throw Error("An installer Worker already exists with that name. This bootstrap only creates fresh installers.");
  }
  const dbName=workerName+"-db";
  if(databases.some(d=>d.name===dbName))throw Error("Installer D1 name is already in use; choose a different Worker name");
  const plan={accountId,hostname,workerName,dbName,zone:zone.name,
    resources:["New D1 database","Private installer Worker upload","Installer migrations","Cloudflare OAuth secrets","Custom domain publish"]};
  console.log("\nDeployment plan:",JSON.stringify(plan,null,2));
  if(!(await yesNo("Create the installer resources?")))throw Error("Cancelled");
  console.log("Packaging the exact pinned Nathan Worker release...");
  await runCli("npm",["run","pack:release"]);
  const database=await cf.createDatabase(dbName);
  const dbId=database.uuid||database.id;
  if(!/^[a-f0-9-]{36}$/.test(dbId))throw Error("Invalid D1 ID");
  const config=JSON.parse(stripJsonc(await readFile("wrangler.installer.jsonc","utf8")));
  config.name=workerName;
  config.account_id=accountId;
  config.main=resolve(config.main);
  config.assets.directory=resolve(config.assets.directory);
  config.d1_databases[0].database_name=dbName;
  config.d1_databases[0].database_id=dbId;
  config.d1_databases[0].migrations_dir=resolve(config.d1_databases[0].migrations_dir);
  config.vars.PUBLIC_ORIGIN="https://"+hostname;
  config.vars.CF_OAUTH_CLIENT_ID=oauthClientId;
  config.vars.CF_OAUTH_SCOPES=installedScopes;
  config.routes=[{pattern:hostname,custom_domain:true}];
  await mkdir(".nathan/generated",{recursive:true,mode:0o700});
  const staging=".nathan/generated/"+workerName+".private.json";
  const live=".nathan/generated/"+workerName+".json";
  await writeFile(staging,JSON.stringify({...config,routes:[],workers_dev:false,preview_urls:false},null,2)+"\n",{mode:0o600});
  await writeFile(live,JSON.stringify(config,null,2)+"\n",{mode:0o600});
  await runCli("npx",["wrangler","d1","migrations","apply",dbName,"--remote","--config",staging]);
  await runCli("npx",["wrangler","deploy","--config",staging]);
  await runCli("npx",["wrangler","secret","put","CF_OAUTH_CLIENT_SECRET","--config",staging],{input:oauthSecret});
  const encKey=randomBytes(32).toString("base64url");
  await runCli("npx",["wrangler","secret","put","INSTALLER_ENCRYPTION_KEY","--config",staging],{input:encKey});
  console.log("Installer staged privately with secrets. Final hostname: "+hostname);
  if(!(await yesNo("Publish the installer custom domain now?")))throw Error("Private installer staged; publication skipped");
  await runCli("npx",["wrangler","deploy","--config",live]);
  console.log("\nInstaller published: https://"+hostname);
  console.log("Open the URL and sign in with Cloudflare OAuth to install Nathan in a customer account.");
  console.log("Back up INSTALLER_ENCRYPTION_KEY securely; rotation invalidates active installer sessions.");
  console.log("For production use, complete the release gates in docs/roadmap.md.");
}
main().catch(e=>{console.error("Nathan installer setup failed:",e.message);process.exitCode=1});
