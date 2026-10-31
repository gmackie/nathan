import type { AuthEnv } from "./env";
import {encryptProviderSecret,decryptProviderSecret,validateOAuthProviderInput} from "./config-crypto.mjs";
import { audit } from "./admin-service";

type ProviderId="google"|"github";
type ProviderRow={
  id:ProviderId;client_id:string;secret_cipher:string;
  enabled:number;updated_at:number;updated_by:string;
};
type ProviderValue={clientId:string;clientSecret:string};
export type SocialCredentials=Partial<Record<ProviderId,ProviderValue>>;
const ALL:ProviderId[]=["google","github"];
function fromLegacy(env:AuthEnv,id:ProviderId):ProviderValue|null{
  const clientId=id==="google"?env.GOOGLE_CLIENT_ID:env.GITHUB_CLIENT_ID;
  const clientSecret=id==="google"?env.GOOGLE_CLIENT_SECRET:env.GITHUB_CLIENT_SECRET;
  return clientId&&clientSecret?{clientId,clientSecret}:null;
}
async function allRows(env:AuthEnv){
  const result=await env.DB.prepare(
    "SELECT id,client_id,secret_cipher,enabled,updated_at,updated_by FROM nathan_oauth_providers"
  ).all<ProviderRow>();
  return new Map(result.results.map(r=>[r.id,r]));
}
/** Read on every auth request: provider disable and rotation take effect immediately. */
export async function loadSocialCredentials(env:AuthEnv):Promise<SocialCredentials>{
  const rows=await allRows(env);
  const providers:SocialCredentials={};
  for(const id of ALL){
    const r=rows.get(id);
    if(r){
      if(r.enabled===1){
        if(!env.NATHAN_CONFIG_KEY)throw Error("Configured provider cannot be decrypted: NATHAN_CONFIG_KEY missing");
        providers[id]={clientId:r.client_id,
          clientSecret:await decryptProviderSecret(id,r.secret_cipher,env.NATHAN_CONFIG_KEY)};
      }
    }else {
      const fallback=fromLegacy(env,id);
      if(fallback)providers[id]=fallback;
    }
  }
  return providers;
}
export async function providerStatus(env:AuthEnv) {
  const rows=await allRows(env);
  return ALL.map(id=>{
    const r=rows.get(id);
    const legacy=fromLegacy(env,id);
    return {
      id,
      enabled:r?r.enabled===1:Boolean(legacy),
      configured:Boolean(r||legacy),
      source:r?"encrypted-d1":legacy?"worker-secret":"not-configured",
      clientIdHint:r?r.client_id.slice(0,5)+"…":legacy?legacy.clientId.slice(0,5)+"…":null,
      updatedAt:r?.updated_at||null,
      callbackUrl:new URL("/api/auth/callback/"+id,env.NATHAN_ISSUER).href,
      canUpdate:Boolean(env.NATHAN_CONFIG_KEY)
    };
  });
}
export async function upsertSocialProvider(env:AuthEnv,input:any,actor:string) {
  const v=validateOAuthProviderInput(input);
  if(!env.NATHAN_CONFIG_KEY)throw Error("NATHAN_CONFIG_KEY missing: provision the encryption key before updating providers");
  const cipher=await encryptProviderSecret(v.id,v.clientSecret,env.NATHAN_CONFIG_KEY);
  await audit(env,actor,"oauth_provider_update",v.id,"attempted");
  try {
    await env.DB.prepare(
      "INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,enabled,updated_at,updated_by) "+
      "VALUES (?,?,?,1,unixepoch(),?) ON CONFLICT(id) DO UPDATE SET "+
      "client_id=excluded.client_id,secret_cipher=excluded.secret_cipher,enabled=1,"+
      "updated_at=unixepoch(),updated_by=excluded.updated_by"
    ).bind(v.id,v.clientId,cipher,actor).run();
    await audit(env,actor,"oauth_provider_update",v.id,"succeeded");
    return {id:v.id,enabled:true,callbackUrl:new URL("/api/auth/callback/"+v.id,env.NATHAN_ISSUER).href,
      note:"Credentials are encrypted in your D1 database. Use a test account to validate this provider."};
  }catch(e){
    await audit(env,actor,"oauth_provider_update",v.id,"failed");
    throw e;
  }
}
export async function setSocialProviderEnabled(env:AuthEnv,input:any,actor:string){
  const id=input?.id;
  if(!ALL.includes(id) || typeof input?.enabled!=="boolean")throw Error("Invalid provider state update");
  const expected="CONFIRM "+(input.enabled?"ENABLE ":"DISABLE ")+id;
  if(input.confirm!==expected)throw Error("Exact provider confirmation required");
  const current=await allRows(env);
  if(!input.enabled){
    const other=ALL.find(name=>name!==id &&
      (current.has(name)?current.get(name)!.enabled===1:Boolean(fromLegacy(env,name))));
    if(!other && env.ENABLE_PASSWORD!=="true" && env.ENTERPRISE_SSO!=="true")
      throw Error("Cannot disable the last configured login provider without another verified recovery path");
  }
  const row=current.get(id);
  if(!row){
    const old=fromLegacy(env,id);
    if(!old||!env.NATHAN_CONFIG_KEY)throw Error("No managed credential exists; configure the provider first");
    const cipher=await encryptProviderSecret(id,old.clientSecret,env.NATHAN_CONFIG_KEY);
    await env.DB.prepare(
      "INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,enabled,updated_at,updated_by) VALUES(?,?,?,?,unixepoch(),?)"
    ).bind(id,old.clientId,cipher,input.enabled?1:0,actor).run();
  }else {
    await env.DB.prepare(
      "UPDATE nathan_oauth_providers SET enabled=?,updated_at=unixepoch(),updated_by=? WHERE id=?"
    ).bind(input.enabled?1:0,actor,id).run();
  }
  await audit(env,actor,input.enabled?"oauth_provider_enable":"oauth_provider_disable",id,"succeeded");
  return {id,enabled:input.enabled};
}
