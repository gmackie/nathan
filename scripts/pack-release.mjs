#!/usr/bin/env node
/**
 * Build and seal the exact worker release the hosted installer is allowed to deploy.
 * Uses Wrangler's dry-run output, not raw TS source or npm packages at runtime.
 */
import { readFile,writeFile,readdir,mkdir,copyFile,rm,stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { join,relative,resolve,sep,extname } from "node:path";
import { stripJsonc } from "./lib/wrangler.mjs";

const root=resolve(".");
const out=join(root,"installer/public/release");
const compiled=join(root,".nathan/build-auth");
const config=JSON.parse(stripJsonc(await readFile("wrangler.auth.jsonc","utf8")));
const version=JSON.parse(await readFile("package.json","utf8")).version;
const run=spawnSync("npm",["run","build:auth"],
  {stdio:"inherit"});
if(run.status!==0)throw Error("Worker dry-run build failed");
async function walk(path){
  const entries=await readdir(path,{withFileTypes:true});
  const out=[];
  for(const entry of entries){
    const full=join(path,entry.name);
    if(entry.isDirectory())out.push(...await walk(full));
    else if(entry.isFile())out.push(full);
  }
  return out;
}
const modules=(await walk(compiled)).filter(p=>[".js",".mjs",".wasm"].includes(extname(p)))
  .map(p=>({full:p,name:relative(compiled,p).split(sep).join("/")}));
if(!modules.length)throw Error("Wrangler produced no Worker module");
if(modules.some(m=>m.name.includes("..")||m.name.startsWith("/")))throw Error("Unsafe module path");
const main=modules.find(m=>/^(index|worker)\.(js|mjs)$/.test(m.name))||modules.find(m=>m.name.endsWith(".js"));
if(!main)throw Error("Could not identify Worker entrypoint");
await rm(out,{recursive:true,force:true});
await mkdir(join(out,"modules"),{recursive:true});
await mkdir(join(out,"migrations"),{recursive:true});
const digest=bytes=>createHash("sha256").update(bytes).digest("hex");
const pieces=[];
for(const mod of modules){
  const bytes=await readFile(mod.full);
  if(bytes.byteLength>12*1024*1024)throw Error("Module exceeds 12 MiB packaging limit: "+mod.name);
  const location=join(out,"modules",mod.name);
  await mkdir(location.slice(0,location.lastIndexOf(sep)),{recursive:true});
  await copyFile(mod.full,location);
  pieces.push({type:"module",path:"modules/"+mod.name,name:mod.name,sha256:digest(bytes),size:bytes.byteLength,
    contentType:extname(mod.name)===".wasm"?"application/wasm":"application/javascript+module"});
}
for(const name of ["0001_nathan_registry.sql","0002_better_auth.sql","0003_security_audit.sql","0004_mcp_limits.sql","0005_domain_realm.sql","0006_control_plane.sql","0007_scim_registry.sql","0008_admin_assurance.sql","0009_admin_grants.sql"]){
  const bytes=await readFile(join(root,"migrations",name));
  if(bytes.byteLength>1_000_000)throw Error("Migration too large");
  await copyFile(join(root,"migrations",name),join(out,"migrations",name));
  pieces.push({type:"migration",name,path:"migrations/"+name,sha256:digest(bytes),size:bytes.length,contentType:"text/plain"});
}
const git=spawnSync("git",["rev-parse","--short","HEAD"],{encoding:"utf8"});
const release={
  version:1,
  release:version+"+"+(git.status===0?git.stdout.trim():process.env.GITHUB_SHA?.slice(0,12)||"local"),
  builtAt:new Date().toISOString(),
  worker:{mainModule:main.name,
    compatibilityDate:config.compatibility_date,
    compatibilityFlags:config.compatibility_flags||[],
    observability:config.observability||{enabled:true},
    durableObjectClasses:config.migrations?.flatMap(m=>m.new_sqlite_classes||[])||[]},
  files:pieces
};
await writeFile(join(out,"manifest.json"),JSON.stringify(release,null,2)+"\n");
console.log("Nathan release ready: "+release.release+" ("+pieces.length+" files) in "+out);
