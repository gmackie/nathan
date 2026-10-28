import type {AuthEnv} from "../env";
import {sha256} from "../../gateway/crypto";
import {validateScimConnection} from "./validation.mjs";
import {audit} from "../admin-service";

const CID=/^[a-z][a-z0-9-]{1,62}$/;
function randomToken(){
  const bytes=crypto.getRandomValues(new Uint8Array(32));
  let s="";for(const b of bytes)s+=String.fromCharCode(b);
  return "nathscim_"+btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
export async function listScimConnections(env:AuthEnv){
  const result=await env.DB.prepare(
    "SELECT id,domain,organization_id AS organizationId,mode,enabled,created_at AS createdAt,updated_at AS updatedAt "+
    "FROM nathan_scim_connections ORDER BY created_at DESC LIMIT 100"
  ).all();
  return result.results.map((r:any)=>({...r,enabled:r.enabled===1,baseUrl:new URL(
    "/scim/v2/"+r.id,env.NATHAN_ISSUER).href}));
}
export async function createScimConnection(env:AuthEnv,input:any,actor:string) {
  if(!env.SCIM_DIRECTORY)throw Error("Transaction-backed SCIM directory binding is missing");
  const v=validateScimConnection(input);
  const token=randomToken(),hash=await sha256(token);
  const credentialId=crypto.randomUUID();
  const statements=[
    env.DB.prepare(
      "INSERT INTO nathan_scim_connections(id,domain,organization_id,mode,enabled,created_by) VALUES (?,?,?,'directory-only',0,?)"
    ).bind(v.id,v.domain,v.organizationId,actor),
    env.DB.prepare(
      "INSERT INTO nathan_scim_credentials(id,connection_id,token_hash) VALUES(?,?,?)"
    ).bind(credentialId,v.id,hash)
  ];
  await audit(env,actor,"scim_connection_create",v.id,"attempted");
  try {
    await env.DB.batch(statements);
    await audit(env,actor,"scim_connection_create",v.id,"succeeded");
    return {
      id:v.id,domain:v.domain,enabled:false,
      mode:"directory-only",
      baseUrl:new URL("/scim/v2/"+v.id,env.NATHAN_ISSUER).href,
      bearerToken:token,
      warning:"This credential is shown only once. SCIM data is staged transactionally; no user login or application access is granted by these directory records."
    };
  }catch{
    await audit(env,actor,"scim_connection_create",v.id,"failed");
    throw Error("SCIM connection already exists or could not be provisioned");
  }
}
export async function setScimConnectionEnabled(env:AuthEnv,input:any,actor:string) {
  if(!CID.test(input?.id||"")||typeof input.enabled!=="boolean")
    throw Error("Invalid SCIM connection status");
  if(input.confirm!=="CONFIRM "+(input.enabled?"ENABLE ":"DISABLE ")+input.id)
    throw Error("Exact confirmation required");
  const current=await env.DB.prepare(
    "SELECT id FROM nathan_scim_connections WHERE id=? LIMIT 1"
  ).bind(input.id).first();
  if(!current)throw Error("SCIM connection not found");
  await env.DB.prepare(
    "UPDATE nathan_scim_connections SET enabled=?,updated_at=unixepoch() WHERE id=?"
  ).bind(input.enabled?1:0,input.id).run();
  await audit(env,actor,input.enabled?"scim_connection_enable":"scim_connection_disable",input.id,"succeeded");
  return {id:input.id,enabled:input.enabled,mode:"directory-only"};
}
export async function rotateScimToken(env:AuthEnv,input:any,actor:string){
  if(!CID.test(input?.id||"")||input.confirm!=="CONFIRM ROTATE "+input.id)
    throw Error("Exact SCIM token rotation confirmation required");
  const existing=await env.DB.prepare(
    "SELECT id FROM nathan_scim_connections WHERE id=? LIMIT 1"
  ).bind(input.id).first();
  if(!existing)throw Error("SCIM connection not found");
  const token=randomToken(),digest=await sha256(token),credentialId=crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE nathan_scim_credentials SET expires_at=unixepoch()+300 WHERE connection_id=? AND revoked_at IS NULL AND expires_at IS NULL"
    ).bind(input.id),
    env.DB.prepare(
      "INSERT INTO nathan_scim_credentials(id,connection_id,token_hash) VALUES(?,?,?)"
    ).bind(credentialId,input.id,digest)
  ]);
  await audit(env,actor,"scim_token_rotate",input.id,"succeeded");
  return {id:input.id,bearerToken:token,
    warning:"New bearer token shown once. Previous tokens expire after a five-minute grace period."};
}
