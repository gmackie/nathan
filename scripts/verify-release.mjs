#!/usr/bin/env node
import { readFile,stat } from "node:fs/promises";
import { join,resolve } from "node:path";
import { createHash } from "node:crypto";

const dir=resolve("installer/public/release");
const manifest=JSON.parse(await readFile(join(dir,"manifest.json"),"utf8"));
if(manifest.version!==1||!Array.isArray(manifest.files)||manifest.files.length<5||manifest.files.length>64)
  throw Error("Release manifest missing or invalid");
if(!manifest.files.some(f=>f.name===manifest.worker.mainModule&&f.type==="module"))
  throw Error("Main Worker module not packaged");
let total=0;
for(const file of manifest.files){
  if(!/^(modules|migrations)\/[A-Za-z0-9_./-]+$/.test(file.path)||
     file.path.includes("..")||file.path.includes("//"))throw Error("Invalid asset path");
  const bytes=await readFile(join(dir,file.path));
  const hash=createHash("sha256").update(bytes).digest("hex");
  if(hash!==file.sha256||bytes.length!==file.size)throw Error("Release file integrity mismatch: "+file.name);
  total+=bytes.length;
}
for(const name of ["0001_nathan_registry.sql","0002_better_auth.sql","0003_security_audit.sql","0004_mcp_limits.sql","0005_domain_realm.sql"]){
  if(!manifest.files.some(f=>f.type==="migration"&&f.name===name))
    throw Error("Missing security migration: "+name);
}
if(total>20*1024*1024)throw Error("Oversize installer payload");
console.log("Verified Nathan release "+manifest.release+" with "+manifest.files.length+" assets ("+total+" bytes)");
