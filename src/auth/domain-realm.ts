import type { AuthEnv } from "./env";
import {assertRealmClientHost,realmCallback,realmIssuerHostname,validateDomainName,parseRealmHostSelection} from "../shared/realm.mjs";
import {audit} from "./admin-service";

export type VerifiedRealm={
  apex:string;
  issuerHostname:string;
  accountId:string;
  zoneId:string;
  registration:"approved-only";
  issuer:string;
  coverage:string[];
};
type RealmRow={
  apex:string;issuer_hostname:string;account_id:string;zone_id:string;
  registered_by:string;registration_mode:string;
};
/** Only the installer or a verified Cloudflare-owner CLI can register an apex. */
export async function loadVerifiedRealm(env:AuthEnv):Promise<VerifiedRealm|null> {
  if(!env.NATHAN_REALM_APEX)return null;
  const apex=validateDomainName(env.NATHAN_REALM_APEX);
  const issuerHostname=new URL(env.NATHAN_ISSUER).hostname;
  if(issuerHostname!==realmIssuerHostname(apex))throw Error("Issuer/domain-wide realm misconfigured");
  const row=await env.DB.prepare(
    "SELECT apex,issuer_hostname,account_id,zone_id,registered_by,registration_mode FROM nathan_domain_realms WHERE apex=? LIMIT 1"
  ).bind(apex).first<RealmRow>();
  if(!row||row.issuer_hostname!==issuerHostname||row.registration_mode!=="approved-only")
    throw Error("Domain-wide realm is not verified for this issuer");
  return {
    apex,issuerHostname,accountId:row.account_id,zoneId:row.zone_id,
    registration:"approved-only",
    issuer:"https://"+issuerHostname+"/api/auth",
    coverage:[apex,"*."+apex]
  };
}
export async function listRealmClients(env:AuthEnv) {
  const realm=await loadVerifiedRealm(env);
  if(!realm)return {realm:null,clients:[]};
  const result=await env.DB.prepare(
    "SELECT hostname,kind,callback_uri AS callbackUri,status,oauth_client_id AS clientId,created_at AS createdAt FROM nathan_realm_clients WHERE realm_apex=? ORDER BY hostname LIMIT 250"
  ).bind(realm.apex).all<{
    hostname:string;kind:string;callbackUri:string;status:string;clientId:string|null;createdAt:number;
  }>();
  return {realm,clients:result.results};
}
export function validateRealmRegistration(input:any,realm:VerifiedRealm) {
  if(!input||typeof input!=="object"||Array.isArray(input))throw Error("Invalid client registration");
  if(!["web","worker","gateway","external"].includes(input.kind))throw Error("Select a supported application type");
  if(input.publicClient!==undefined && typeof input.publicClient!=="boolean")
    throw Error("publicClient must be a boolean");
  if(input.kind==="gateway"&&input.publicClient===true)
    throw Error("Gateway must be a confidential OIDC client");
  const hostname=assertRealmClientHost(input.hostname,realm.apex,realm.issuerHostname);
  const callbackUri=realmCallback(hostname,realm.apex,realm.issuerHostname,input.kind,input.callbackPath);
  if(input.clientName!==undefined &&
    (typeof input.clientName!=="string"||!input.clientName.trim()||input.clientName.length>100))
    throw Error("Client name must be 1-100 characters");
  return {
    hostname,kind:input.kind as "web"|"worker"|"gateway"|"external",
    callbackUri,clientName:input.clientName?.trim()||hostname,
    publicClient:input.publicClient===true
  };
}
/**
 * Register exactly ONE relying party hostname. Register disabled: the owner
 * must install its client configuration and explicitly enable it afterwards.
 * Never auto-register wildcard redirects or skip consent based solely on DNS.
 */
export async function registerRealmClient(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string) {
  const realm=await loadVerifiedRealm(env);
  if(!realm)throw Error("Domain-wide realm was not installed or verified");
  const client=validateRealmRegistration(input,realm);
  const claimed=await env.DB.prepare(
    "INSERT OR IGNORE INTO nathan_realm_clients(hostname,realm_apex,kind,callback_uri,status,requested_by) VALUES (?,?,?,?,?,?)"
  ).bind(client.hostname,realm.apex,client.kind,client.callbackUri,"creating",actor).run();
  if(claimed.meta?.changes!==1)throw Error("Hostname already registered or pending reconciliation; inspect existing client before retrying");

  await audit(env,actor,"realm_client_create",client.hostname,"attempted");
  try {
    const raw=await auth.api.adminCreateOAuthClient({
      headers,
      body:{
        client_name:client.clientName,
        redirect_uris:[client.callbackUri],
        token_endpoint_auth_method:client.publicClient?"none":"client_secret_basic",
        application_type:"web",
        grant_types:["authorization_code","refresh_token"],
        require_pkce:true,
        skip_consent:false,
        disabled:true,
        ...(client.kind==="gateway" ? {
          backchannel_logout_uri:"https://"+client.hostname+"/__nathan/backchannel",
          enable_end_session:true
        }:{})
      }
    }) as any;
    const id=raw?.client_id||raw?.clientId;
    if(typeof id!=="string"||id.length<1||id.length>200)
      throw Error("OIDC provider returned no client_id; manual reconciliation required");
    const saved=await env.DB.prepare(
      "UPDATE nathan_realm_clients SET oauth_client_id=?,status='disabled',updated_at=unixepoch() WHERE hostname=? AND status='creating'"
    ).bind(id,client.hostname).run();
    if(saved.meta?.changes!==1)
      throw Error("OIDC client exists but realm link was not saved; manual reconciliation required");
    await audit(env,actor,"realm_client_create",client.hostname,"succeeded");
    return {
      ...raw,
      realm:realm.apex,
      hostname:client.hostname,
      callback_uri:client.callbackUri,
      enabled:false,
      note:"Client registered disabled. Configure the relying party, verify its callback, then explicitly enable in Identity Studio."
    };
  }catch(e) {
    // Do not release the reservation automatically: an upstream success could
    // have happened even if linking the resulting client ID failed.
    await audit(env,actor,"realm_client_create",client.hostname,"failed");
    throw e;
  }
}
export async function updateRealmClientStatus(env:AuthEnv,clientId:string,disabled:boolean) {
  if(typeof clientId!=="string"||clientId.length>200)return;
  await env.DB.prepare(
    "UPDATE nathan_realm_clients SET status=?,updated_at=unixepoch() WHERE oauth_client_id=?"
  ).bind(disabled?"disabled":"registered",clientId).run();
}

/** Batch register only a user-approved finite inventory. Never retry a failed
 * registration automatically: the provider may have created the client before
 * the realm link was persisted. All new clients start disabled.
 */
export async function registerRealmClientsBatch(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string) {
  const realm=await loadVerifiedRealm(env);
  if(!realm)throw Error("Verified domain realm required");
  if(input?.confirm!=="REGISTER DOMAIN CLIENTS")throw Error("Explicit registration confirmation required");
  const hosts=parseRealmHostSelection(input.hostnames,realm.apex,realm.issuerHostname,{max:20});
  // Validate every requested application before starting any write.
  const configs=hosts.map(hostname=>validateRealmRegistration({
    hostname,kind:input.kind||"web",callbackPath:input.callbackPath,
    publicClient:input.publicClient===true
  },realm));
  const results:Array<{hostname:string,created:boolean,client?:unknown,error?:string}>=[];
  for(const item of configs){
    try{
      const registered=await registerRealmClient(auth,env,headers,item,actor);
      results.push({hostname:item.hostname,created:true,client:registered});
    }catch{
      results.push({hostname:item.hostname,created:false,error:
        "Registration failed or requires reconciliation. Inspect domain clients and audit log before retrying."});
    }
  }
  return {realm:realm.apex,requested:configs.length,created:results.filter(r=>r.created).length,results,
    warning:"Save any one-time confidential client secrets immediately. No application was routed or protected by this operation."};
}
