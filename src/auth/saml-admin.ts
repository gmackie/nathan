/**
 * Identity Studio service for inbound enterprise SAML connections (NATH-10).
 * Nathan is the SAML service provider; the @better-auth/sso plugin owns the
 * protocol. Every mutation is admin-only (enforced by the route), audited,
 * and goes through this server-side code; the plugin's raw /api/auth/sso/*
 * management endpoints stay blocked.
 */
import type { AuthEnv } from "./env";
import { audit } from "./admin-service";
import { parseIdpMetadata, fetchIdpMetadata, buildIdpMetadata, spValues, certificateFromInput,
  EXPIRY_WARNING_DAYS } from "./saml-metadata.mjs";
import { attributeMapping, ATTRIBUTE_PRESETS } from "./saml-policy.mjs";

type Certificate = { der:string; sha256:string; bits:number; signatureAlgorithm:string;
  notBefore:string; notAfter:string; role:"active"|"next"; addedAt:string };
type ConnectionRow = { provider_id:string; domain:string; idp_entity_id:string; sso_url:string;
  sso_post_url:string|null; certificates:string; provisioning:string; attribute_preset:string;
  enabled:number; created_by:string; created_at:number; updated_at:number; domain_verified:number|null };

const PROVISIONING = ["invitation-only","just-in-time"] as const;
const MAX_CERTIFICATES = 3;
const DAY = 86400e3;

function providerIdOf(value:unknown):string{
  if(typeof value!=="string"||!/^[a-z][a-z0-9-]{1,62}$/.test(value))throw Error("Invalid connection ID");
  return value;
}
function domainOf(value:unknown):string{
  if(typeof value!=="string")throw Error("Invalid domain");
  const d=value.trim().toLowerCase();
  if(d.length>253||!/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$/.test(d))
    throw Error("Invalid email domain");
  return d;
}
function requireEnterpriseSso(env:AuthEnv){
  if(env.ENTERPRISE_SSO!=="true")throw Error("Enterprise SSO plugin is disabled; redeploy with ENTERPRISE_SSO=true");
}

function certificateStatus(c:Certificate,now=Date.now()){
  const notAfter=Date.parse(c.notAfter);
  const daysLeft=Math.floor((notAfter-now)/DAY);
  return {sha256:c.sha256,role:c.role,bits:c.bits,signatureAlgorithm:c.signatureAlgorithm,
    notBefore:c.notBefore,notAfter:c.notAfter,addedAt:c.addedAt,daysLeft,
    expired:notAfter<=now,expiringSoon:notAfter>now&&notAfter-now<EXPIRY_WARNING_DAYS*DAY};
}
function warningsFor(certs:Certificate[],verified:boolean,enabled:boolean){
  const out:string[]=[];
  const statuses=certs.map(c=>certificateStatus(c));
  for(const s of statuses){
    if(s.expired)out.push("Certificate "+s.sha256.slice(0,23)+"… expired on "+s.notAfter+". Retire it once the IdP signs with a newer certificate.");
    else if(s.expiringSoon)out.push("Certificate "+s.sha256.slice(0,23)+"… expires in "+s.daysLeft+" days. Add the IdP's next certificate now.");
  }
  if(statuses.length&&statuses.every(s=>s.expired))out.push("Every signing certificate has expired.");
  if(!verified)out.push("Domain not verified: publish the DNS TXT record and verify before enabling.");
  if(!enabled)out.push("Connection is disabled; users cannot sign in with it.");
  return out;
}
function present(row:ConnectionRow,issuer:string){
  const certs=JSON.parse(row.certificates) as Certificate[];
  const verified=Number(row.domain_verified)===1, enabled=row.enabled===1;
  return {providerId:row.provider_id,domain:row.domain,enabled,domainVerified:verified,
    provisioning:row.provisioning,attributePreset:row.attribute_preset,
    idp:{entityID:row.idp_entity_id,ssoUrl:row.sso_url,ssoPostUrl:row.sso_post_url},
    sp:spValues(issuer,row.provider_id),
    certificates:certs.map(c=>certificateStatus(c)),
    warnings:warningsFor(certs,verified,enabled),
    createdBy:row.created_by,createdAt:row.created_at,updatedAt:row.updated_at};
}
async function loadConnection(env:AuthEnv,id:string):Promise<ConnectionRow>{
  const row=await env.DB.prepare(
    'SELECT c.*,p."domainVerified" AS domain_verified FROM nathan_saml_connections c '+
    'JOIN "ssoProvider" p ON p."providerId"=c.provider_id WHERE c.provider_id=? AND p."samlConfig" IS NOT NULL LIMIT 1'
  ).bind(id).first<ConnectionRow>();
  if(!row)throw Error("SAML connection not found");
  return row;
}

export async function listSamlConnections(env:AuthEnv){
  const rows=await env.DB.prepare(
    'SELECT c.*,p."domainVerified" AS domain_verified FROM nathan_saml_connections c '+
    'JOIN "ssoProvider" p ON p."providerId"=c.provider_id WHERE p."samlConfig" IS NOT NULL ORDER BY c.provider_id LIMIT 100'
  ).all<ConnectionRow>();
  return rows.results.map(r=>present(r,env.NATHAN_ISSUER));
}

async function metadataFrom(input:any):Promise<string>{
  if(typeof input?.metadataXml==="string"&&input.metadataXml.trim())return input.metadataXml;
  if(typeof input?.metadataUrl==="string"&&input.metadataUrl.trim())return fetchIdpMetadata(input.metadataUrl.trim());
  throw Error("Paste the IdP metadata XML or give its HTTPS metadata URL");
}

/** Validates metadata without saving anything (Studio "Check metadata"). */
export async function previewSamlMetadata(env:AuthEnv,input:any){
  requireEnterpriseSso(env);
  const m=await parseIdpMetadata(await metadataFrom(input));
  const providerId=typeof input?.providerId==="string"&&/^[a-z][a-z0-9-]{1,62}$/.test(input.providerId)?input.providerId:null;
  return {idp:{entityID:m.entityID,ssoUrl:m.ssoRedirectUrl,ssoPostUrl:m.ssoPostUrl},
    certificates:m.certificates.map(c=>certificateStatus({...c,role:"active",addedAt:""})),
    warnings:m.warnings,...(providerId?{sp:spValues(env.NATHAN_ISSUER,providerId)}:{})};
}

/**
 * Creates a disabled SAML connection from validated IdP metadata. The plugin
 * receives a canonical metadata document rebuilt by Nathan, Nathan's own
 * per-connection SP entity ID as issuer and audience, and signed assertions
 * required.
 */
export async function createSamlConnection(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string){
  requireEnterpriseSso(env);
  const providerId=providerIdOf(input?.providerId);
  const domain=domainOf(input?.domain);
  const provisioning=input?.provisioning??"invitation-only";
  if(!PROVISIONING.includes(provisioning))throw Error("Invalid provisioning mode");
  const preset=input?.attributePreset??"generic";
  if(!ATTRIBUTE_PRESETS.includes(preset))throw Error("Invalid attribute preset");
  const m=await parseIdpMetadata(await metadataFrom(input));
  const now=new Date().toISOString();
  const certs:Certificate[]=m.certificates.map(c=>({der:c.der,sha256:c.sha256,bits:c.bits,
    signatureAlgorithm:c.signatureAlgorithm,notBefore:c.notBefore,notAfter:c.notAfter,role:"active",addedAt:now}));
  const sp=spValues(env.NATHAN_ISSUER,providerId);
  await audit(env,actor,"saml_connection_create",providerId,"attempted");
  let result:any;
  try{
    result=await auth.api.registerSSOProvider({headers,body:{
      providerId,issuer:sp.entityId,domain,
      samlConfig:{
        entryPoint:m.ssoRedirectUrl,
        audience:sp.entityId,
        callbackUrl:new URL(env.NATHAN_ISSUER).origin+"/",
        idpMetadata:{metadata:buildIdpMetadata({entityID:m.entityID,ssoRedirectUrl:m.ssoRedirectUrl,
          ssoPostUrl:m.ssoPostUrl,certificates:certs.map(c=>c.der)})},
        spMetadata:{entityID:sp.entityId},
        wantAssertionsSigned:true,
        authnRequestsSigned:false,
        mapping:attributeMapping(preset)
      }
    }});
  }catch(e){
    await audit(env,actor,"saml_connection_create",providerId,"failed");
    throw e;
  }
  try{
    await env.DB.prepare(
      "INSERT INTO nathan_saml_connections(provider_id,domain,idp_entity_id,sso_url,sso_post_url,certificates,provisioning,attribute_preset,enabled,created_by) "+
      "VALUES(?,?,?,?,?,?,?,?,0,?)"
    ).bind(providerId,domain,m.entityID,m.ssoRedirectUrl,m.ssoPostUrl,JSON.stringify(certs),provisioning,preset,actor).run();
  }catch(e){
    // Never leave a plugin provider without Nathan's (disabled-by-default) policy row.
    await env.DB.prepare('DELETE FROM "ssoProvider" WHERE "providerId"=?').bind(providerId).run();
    await audit(env,actor,"saml_connection_create",providerId,"failed");
    throw e;
  }
  await audit(env,actor,"saml_connection_create",providerId,"succeeded");
  const token=typeof result?.domainVerificationToken==="string"?result.domainVerificationToken:null;
  return {...present(await loadConnection(env,providerId),env.NATHAN_ISSUER),
    metadataWarnings:m.warnings,
    verification:{txtHost:"_better-auth-token-"+providerId+"."+domain,...(token?{txtValue:token}:{}),
      note:"Publish this TXT record in the enterprise DNS zone, then verify the domain. The connection stays disabled until then."}};
}

export async function setSamlConnectionEnabled(env:AuthEnv,input:any,actor:string){
  requireEnterpriseSso(env);
  const id=providerIdOf(input?.providerId);
  if(typeof input?.enabled!=="boolean"||input.confirm!==(input.enabled?"CONFIRM ENABLE SAML ":"CONFIRM DISABLE SAML ")+id)
    throw Error("Explicit confirmation required");
  const action=input.enabled?"saml_connection_enable":"saml_connection_disable";
  await audit(env,actor,action,id,"attempted");
  try{
    const row=await loadConnection(env,id);
    if(input.enabled){
      if(Number(row.domain_verified)!==1)throw Error("Verify the connection's domain with the DNS TXT challenge before enabling");
      const certs=JSON.parse(row.certificates) as Certificate[];
      if(!certs.some(c=>!certificateStatus(c).expired))throw Error("Add a valid signing certificate before enabling");
    }
    await env.DB.prepare("UPDATE nathan_saml_connections SET enabled=?,updated_at=unixepoch() WHERE provider_id=?")
      .bind(input.enabled?1:0,id).run();
    await audit(env,actor,action,id,"succeeded");
    return present(await loadConnection(env,id),env.NATHAN_ISSUER);
  }catch(e){await audit(env,actor,action,id,"failed");throw e;}
}

export async function setSamlProvisioning(env:AuthEnv,input:any,actor:string){
  requireEnterpriseSso(env);
  const id=providerIdOf(input?.providerId);
  if(!PROVISIONING.includes(input?.provisioning)||input.confirm!=="CONFIRM PROVISIONING "+input.provisioning+" "+id)
    throw Error("Explicit confirmation required");
  await audit(env,actor,"saml_connection_provisioning",id+":"+input.provisioning,"attempted");
  try{
    await loadConnection(env,id);
    await env.DB.prepare("UPDATE nathan_saml_connections SET provisioning=?,updated_at=unixepoch() WHERE provider_id=?")
      .bind(input.provisioning,id).run();
    await audit(env,actor,"saml_connection_provisioning",id+":"+input.provisioning,"succeeded");
    return present(await loadConnection(env,id),env.NATHAN_ISSUER);
  }catch(e){await audit(env,actor,"saml_connection_provisioning",id+":"+input.provisioning,"failed");throw e;}
}

/** Rebuilds the plugin's IdP metadata from Nathan's certificate list, atomically with Nathan's row. */
async function writeCertificates(env:AuthEnv,row:ConnectionRow,certs:Certificate[]){
  const provider=await env.DB.prepare('SELECT "samlConfig" AS config FROM "ssoProvider" WHERE "providerId"=? LIMIT 1')
    .bind(row.provider_id).first<{config:string|null}>();
  if(!provider?.config)throw Error("SAML connection not found");
  const config=JSON.parse(provider.config);
  config.idpMetadata={metadata:buildIdpMetadata({entityID:row.idp_entity_id,ssoRedirectUrl:row.sso_url,
    ssoPostUrl:row.sso_post_url,certificates:certs.map(c=>c.der)})};
  delete config.cert;
  await env.DB.batch([
    env.DB.prepare('UPDATE "ssoProvider" SET "samlConfig"=? WHERE "providerId"=? AND "samlConfig" IS NOT NULL')
      .bind(JSON.stringify(config),row.provider_id),
    env.DB.prepare("UPDATE nathan_saml_connections SET certificates=?,updated_at=unixepoch() WHERE provider_id=?")
      .bind(JSON.stringify(certs),row.provider_id)
  ]);
}

/** Rotation step 1: trust the IdP's next signing certificate alongside the current one. */
export async function addSamlCertificate(env:AuthEnv,input:any,actor:string){
  requireEnterpriseSso(env);
  const id=providerIdOf(input?.providerId);
  await audit(env,actor,"saml_certificate_add",id,"attempted");
  try{
    const row=await loadConnection(env,id);
    const certs=JSON.parse(row.certificates) as Certificate[];
    const c=await certificateFromInput(input?.certificate);
    if(certs.some(x=>x.sha256===c.sha256))throw Error("Certificate is already trusted for this connection");
    if(certs.length>=MAX_CERTIFICATES)throw Error("Retire an old certificate before adding another");
    certs.push({der:c.der,sha256:c.sha256,bits:c.bits,signatureAlgorithm:c.signatureAlgorithm,
      notBefore:c.notBefore,notAfter:c.notAfter,role:"next",addedAt:new Date().toISOString()});
    await writeCertificates(env,row,certs);
    await audit(env,actor,"saml_certificate_add",id+":"+c.sha256,"succeeded");
    return present(await loadConnection(env,id),env.NATHAN_ISSUER);
  }catch(e){await audit(env,actor,"saml_certificate_add",id,"failed");throw e;}
}

/** Rotation step 2: stop trusting an old certificate once the IdP signs with the next one. */
export async function retireSamlCertificate(env:AuthEnv,input:any,actor:string){
  requireEnterpriseSso(env);
  const id=providerIdOf(input?.providerId);
  const sha256=typeof input?.sha256==="string"?input.sha256.toUpperCase():"";
  if(!/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(sha256)||input.confirm!=="CONFIRM RETIRE CERTIFICATE "+id)
    throw Error("Explicit confirmation and certificate fingerprint required");
  await audit(env,actor,"saml_certificate_retire",id+":"+sha256,"attempted");
  try{
    const row=await loadConnection(env,id);
    const certs=JSON.parse(row.certificates) as Certificate[];
    const remaining=certs.filter(c=>c.sha256!==sha256);
    if(remaining.length===certs.length)throw Error("Certificate is not trusted for this connection");
    if(!remaining.length)throw Error("Cannot retire the only signing certificate; add the next one first");
    if(row.enabled===1&&!remaining.some(c=>!certificateStatus(c).expired))
      throw Error("Cannot leave an enabled connection with only expired certificates");
    if(!remaining.some(c=>c.role==="active"))for(const c of remaining)c.role="active";
    await writeCertificates(env,row,remaining);
    await audit(env,actor,"saml_certificate_retire",id+":"+sha256,"succeeded");
    return present(await loadConnection(env,id),env.NATHAN_ISSUER);
  }catch(e){await audit(env,actor,"saml_certificate_retire",id+":"+sha256,"failed");throw e;}
}
