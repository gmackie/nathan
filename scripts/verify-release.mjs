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
for(const name of ["0001_nathan_registry.sql","0002_better_auth.sql","0003_security_audit.sql","0004_mcp_limits.sql","0005_domain_realm.sql","0006_control_plane.sql","0007_scim_registry.sql","0008_admin_assurance.sql","0009_admin_grants.sql","0010_security_overrides.sql","0011_rbac.sql","0012_social_providers.sql","0013_saml.sql","0014_token_profile.sql","0015_remote_mcp.sql","0016_scim_lifecycle.sql","0017_admission_provider_health.sql","0018_saml_idp.sql","0019_email_otp.sql","0020_hosted_email_sign_in.sql","0021_email_delivery_order.sql","0022_app_provisioning.sql"]){
  if(!manifest.files.some(f=>f.type==="migration"&&f.name===name))
    throw Error("Missing security migration: "+name);
}
if(total>20*1024*1024)throw Error("Oversize installer payload");
console.log("Verified Nathan release "+manifest.release+" with "+manifest.files.length+" assets ("+total+" bytes)");
