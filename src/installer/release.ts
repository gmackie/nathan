import type { InstallerEnv } from "./env";
export type ReleaseFile={type:"module"|"migration";name:string;path:string;sha256:string;size:number;contentType:string};
export type NathanRelease={version:1;release:string;builtAt:string;
  worker:{mainModule:string;compatibilityDate:string;compatibilityFlags:string[];observability:{enabled:boolean}};
  files:ReleaseFile[]};
const MAX_FILE=12*1024*1024;
function validateManifest(value:any):NathanRelease {
  if(!value||value.version!==1||!value.release||!Array.isArray(value.files)||value.files.length>64||
    !value.worker?.mainModule||!value.worker?.compatibilityDate)throw Error("Invalid release manifest");
  for(const file of value.files) {
    if(!["module","migration"].includes(file.type)||typeof file.path!=="string"||
      !/^(modules|migrations)\/[a-zA-Z0-9_./-]+$/.test(file.path)||
      file.path.includes("..")||file.path.includes("//")||
      !/^[a-f0-9]{64}$/.test(file.sha256)||!Number.isSafeInteger(file.size)||
      file.size<1||file.size>MAX_FILE)throw Error("Invalid release file entry");
  }
  if(!value.files.some((f:ReleaseFile)=>f.type==="module"&&f.name===value.worker.mainModule))
    throw Error("Release entry module missing");
  return value as NathanRelease;
}
async function hash(value:ArrayBuffer) {
  const bytes=new Uint8Array(await crypto.subtle.digest("SHA-256",value));
  return [...bytes].map(b=>b.toString(16).padStart(2,"0")).join("");
}
export async function loadRelease(env:InstallerEnv):Promise<NathanRelease>{
  const response=await env.ASSETS.fetch(new Request("https://assets.local/release/manifest.json"));
  if(!response.ok)throw Error("No sealed release packaged into installer; run npm run pack:release");
  return validateManifest(await response.json());
}
export async function releaseFile(env:InstallerEnv,entry:ReleaseFile):Promise<ArrayBuffer>{
  if(!entry.path.startsWith("modules/")&&!entry.path.startsWith("migrations/"))throw Error("Invalid release path");
  const response=await env.ASSETS.fetch(new Request("https://assets.local/release/"+entry.path));
  if(!response.ok)throw Error("Missing release asset: "+entry.path);
  const bytes=await response.arrayBuffer();
  if(bytes.byteLength!==entry.size||await hash(bytes)!==entry.sha256)throw Error("Release integrity mismatch: "+entry.path);
  return bytes;
}
