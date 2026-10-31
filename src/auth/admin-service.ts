import type { AuthEnv } from "./env";

export type AdminActor = { id:string; email:string; role:"admin"; emailVerified:true };
export function isAdminUser(user: unknown, env:AuthEnv): user is AdminActor {
  if(!user || typeof user!=="object")return false;
  const u=user as Record<string,unknown>;
  const emails=(env.NATHAN_ADMIN_EMAILS||"").split(",").map(e=>e.trim().toLowerCase()).filter(Boolean);
  return Boolean(u.emailVerified===true && u.role==="admin" && typeof u.id==="string"
    && typeof u.email==="string" && emails.includes(u.email.toLowerCase()));
}
export async function audit(env:AuthEnv,actor:string,action:string,target:string,outcome:string) {
  await env.DB.prepare("INSERT INTO nathan_security_audit (id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
    .bind(crypto.randomUUID(),actor,action,target,outcome).run();
}
export async function listClients(env:AuthEnv) {
  const rows=await env.DB.prepare(
    'SELECT "clientId" AS id, "name" AS name, "redirectUris" AS redirectUris, "disabled" AS disabled, "tokenEndpointAuthMethod" AS authMethod FROM "oauthClient" ORDER BY "createdAt" DESC LIMIT 100'
  ).all<{id:string,name:string,redirectUris:string,disabled:number,authMethod:string}>();
  return rows.results.map(c=>({...c,redirectUris:JSON.parse(c.redirectUris||"[]")}));
}
export async function listApplications(env:AuthEnv) {
  const rows=await env.DB.prepare("SELECT id,hostname,roles,enabled,created_at,updated_at FROM nathan_applications ORDER BY id LIMIT 200")
    .all<{id:string;hostname:string;roles:string;enabled:number;created_at:number;updated_at:number}>();
  return rows.results.map(x=>({...x,roles:JSON.parse(x.roles||"[]")}));
}
export async function listSso(env:AuthEnv) {
  const rows=await env.DB.prepare('SELECT "providerId" AS id, "issuer" AS issuer, "domain" AS domain, "organizationId" AS organizationId, "oidcConfig" IS NOT NULL AS oidc, "samlConfig" IS NOT NULL AS saml, "domainVerified" AS domainVerified FROM "ssoProvider" ORDER BY "providerId" LIMIT 100')
    .all();
  return rows.results;
}
export async function recentAudit(env:AuthEnv) {
  const rows=await env.DB.prepare("SELECT id,actor,action,target,outcome,created_at FROM nathan_security_audit ORDER BY created_at DESC LIMIT 75").all();
  return rows.results;
}
export function validateApplication(input:any){
  if(!input || !/^[a-z][a-z0-9-]{0,62}$/.test(input.id||""))throw new Error("Invalid application id");
  let url:URL;
  try{url=new URL("https://"+input.hostname);}catch{throw new Error("Invalid hostname");}
  if(!/^[a-z0-9.-]+$/.test(input.hostname) || url.hostname!==input.hostname || input.hostname.includes(".."))
    throw new Error("Invalid hostname");
  if(!Array.isArray(input.roles) || input.roles.length>16 || input.roles.some((r:unknown)=>typeof r!=="string" || !/^[a-z][a-z0-9_-]{0,31}$/.test(r)))
    throw new Error("Invalid roles");
  return {id:input.id,hostname:input.hostname,roles:input.roles as string[]};
}
export async function upsertApplication(env:AuthEnv,input:any,actor:string){
  const app=validateApplication(input);
  // New protected applications start disabled, never online by default.
  await env.DB.prepare("INSERT INTO nathan_applications(id,hostname,roles,enabled) VALUES (?,?,?,0) ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname,roles=excluded.roles,updated_at=unixepoch()")
    .bind(app.id,app.hostname,JSON.stringify(app.roles)).run();
  await audit(env,actor,"application_upsert",app.id,"succeeded");
  return {...app,enabled:false,note:"Existing enabled status is retained; new records are disabled"};
}
export async function setApplicationEnabled(env:AuthEnv,id:string,enabled:boolean,actor:string){
  if(!/^[a-z][a-z0-9-]{0,62}$/.test(id))throw Error("Invalid application id");
  const result=await env.DB.prepare("UPDATE nathan_applications SET enabled=?,updated_at=unixepoch() WHERE id=?").bind(enabled?1:0,id).run();
  if(!result.meta?.changes)throw Error("Unknown application");
  await audit(env,actor,enabled?"application_enable":"application_disable",id,"succeeded");
  return {id,enabled};
}
export async function createOAuthClient(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string){
  if(typeof input?.name!=="string" || !input.name.trim() || input.name.length>100)throw Error("Invalid client name");
  if(!["external","worker","gateway","mcp"].includes(input.kind))throw Error("Invalid client kind");
  if(input.publicClient && input.kind==="gateway")throw Error("Gateway must be confidential");
  let redirect:URL;
  try{redirect=new URL(input.redirectUri);}catch{throw Error("Invalid redirect URI");}
  if(redirect.protocol!=="https:" || redirect.username || redirect.password || redirect.hash || redirect.origin==="null")
    throw Error("Clients require an exact HTTPS redirect URL");
  if(input.kind==="gateway" && redirect.pathname!=="/__nathan/callback")throw Error("Gateway callback must use /__nathan/callback");
  const extras=input.kind==="gateway" ? {backchannel_logout_uri:redirect.origin+"/__nathan/backchannel",enable_end_session:true} : {};
  const resource=input.kind==="mcp" ? {resources:[new URL(env.NATHAN_ISSUER).origin+"/mcp"]} : {};
  await audit(env,actor,"client_create",input.kind+":"+redirect.origin,"attempted");
  try {
    const client=await auth.api.adminCreateOAuthClient({
      headers,body:{
        client_name:input.name.trim(),
        redirect_uris:[redirect.href],
        token_endpoint_auth_method:input.publicClient?"none":"client_secret_basic",
        application_type:"web",
        grant_types:["authorization_code","refresh_token"],
        require_pkce:true,
        skip_consent:false,
        ...extras,...resource
      }
    });
    await audit(env,actor,"client_create",input.kind+":"+redirect.origin,"succeeded");
    return client;
  } catch(e) {
    await audit(env,actor,"client_create",input.kind+":"+redirect.origin,"failed");
    throw e;
  }
}
export async function updateOAuthClientStatus(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string){
  if(typeof input?.clientId!=="string" || !/^[A-Za-z0-9._-]{1,200}$/.test(input.clientId) || typeof input.disabled!=="boolean")
    throw Error("Invalid client status update");
  await audit(env,actor,"client_status",input.clientId,"attempted");
  try {
    await auth.api.adminUpdateOAuthClient({headers,body:{client_id:input.clientId,update:{disabled:input.disabled}}});
    await audit(env,actor,"client_status",input.clientId,"succeeded");
    return {clientId:input.clientId,disabled:input.disabled};
  } catch(e) {
    await audit(env,actor,"client_status",input.clientId,"failed");
    throw e;
  }
}
export async function registerEnterpriseOidc(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string){
  if(env.ENTERPRISE_SSO!=="true")throw Error("Enterprise SSO plugin is disabled; redeploy with ENTERPRISE_SSO=true");
  if(!/^[a-z][a-z0-9-]{1,62}$/.test(input?.providerId||""))throw Error("Invalid provider id");
  if(typeof input?.domain!=="string"||!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(input.domain))throw Error("Invalid domain");
  let issuer:URL;
  try{issuer=new URL(input.issuer);}catch{throw Error("Invalid OIDC issuer");}
  if(issuer.protocol!=="https:"||issuer.username||issuer.password||issuer.hash||issuer.search||
     /^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(issuer.hostname))
    throw Error("OIDC issuer must be a public HTTPS URL");
  if(typeof input.clientId!=="string"||input.clientId.length<1||input.clientId.length>512||
     typeof input.clientSecret!=="string"||input.clientSecret.length<8||input.clientSecret.length>4096)
    throw Error("Missing or invalid enterprise OIDC credentials");
  await audit(env,actor,"enterprise_sso_register",input.providerId,"attempted");
  try {
    const result=await auth.api.registerSSOProvider({
      headers,
      body:{providerId:input.providerId,issuer:issuer.href.replace(/\/$/,""),domain:input.domain,
        oidcConfig:{clientId:input.clientId,clientSecret:input.clientSecret,pkce:true}}
    });
    await audit(env,actor,"enterprise_sso_register",input.providerId,"succeeded");
    const token=typeof (result as any)?.domainVerificationToken==="string"
      ?(result as any).domainVerificationToken:null;
    return {registered:true,providerId:input.providerId,
      callback:new URL("/api/auth/sso/callback/"+input.providerId,env.NATHAN_ISSUER).href,
      domainVerified:false,
      verification:{txtHost:"_better-auth-token-"+input.providerId+"."+input.domain,
        ...(token?{txtValue:token}:{}),note:token
          ?"Publish this TXT record under the enterprise-owned DNS zone, then verify."
          :"Request a new domain verification token from Identity Studio."}};
  } catch(e) {
    await audit(env,actor,"enterprise_sso_register",input.providerId,"failed");
    throw e;
  }
}

/** Privileged internal mutation for OAuth-authenticated MCP administrators. */
export async function setOAuthClientDisabledWithMcp(env:AuthEnv,clientId:string,disabled:boolean,actor:string){
  if(!/^[A-Za-z0-9._-]{1,200}$/.test(clientId))throw Error("Invalid client id");
  const result=await env.DB.prepare('UPDATE "oauthClient" SET "disabled"=? WHERE "clientId"=?')
    .bind(disabled?1:0,clientId).run();
  if(!result.meta?.changes)throw Error("Unknown OAuth client");
  await env.DB.prepare("UPDATE nathan_realm_clients SET status=?,updated_at=unixepoch() WHERE oauth_client_id=?")
    .bind(disabled?"disabled":"registered",clientId).run();
  await audit(env,actor,disabled?"oauth_client_disable":"oauth_client_enable",clientId,"succeeded");
  return {clientId,disabled,note:"Existing bearer access tokens may remain valid until expiration; revoke tokens separately if required."};
}

/** Read-only administrative user directory. Never expose credentials or sessions. */
export async function listUsers(env:AuthEnv) {
  const rows=await env.DB.prepare(
    'SELECT "id","name","email","emailVerified","role","banned","createdAt" FROM "user" ORDER BY "createdAt" DESC LIMIT 100'
  ).all();
  return rows.results;
}

function validatedProviderId(value:any):string{
  if(typeof value!=="string" || !/^[a-z][a-z0-9-]{1,62}$/.test(value))
    throw Error("Invalid enterprise provider ID");
  return value;
}
export async function requestEnterpriseVerification(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string){
  const id=validatedProviderId(input?.providerId);
  if(env.ENTERPRISE_SSO!=="true")throw Error("Enterprise SSO disabled");
  await audit(env,actor,"enterprise_sso_token_request",id,"attempted");
  try{
    const record=await env.DB.prepare(
      'SELECT "domain" AS domain FROM "ssoProvider" WHERE "providerId"=? LIMIT 1'
    ).bind(id).first<{domain:string}>();
    if(!record)throw Error("SSO provider not found");
    const result=await auth.api.requestDomainVerification({
      headers,body:{providerId:id}
    }) as any;
    const value=typeof result?.domainVerificationToken==="string"
      ?result.domainVerificationToken:typeof result?.verificationToken==="string"?result.verificationToken:null;
    await audit(env,actor,"enterprise_sso_token_request",id,"succeeded");
    return {
      providerId:id,domain:record.domain,
      txtHost:"_better-auth-token-"+id+"."+record.domain,
      ...(value?{txtValue:value}:{}),
      note:"Add the returned TXT record, allow DNS propagation, and verify. The token is not fabricated by Nathan."
    };
  }catch(e){
    await audit(env,actor,"enterprise_sso_token_request",id,"failed");
    throw e;
  }
}
export async function verifyEnterpriseDomain(auth:any,env:AuthEnv,headers:Headers,input:any,actor:string){
  const id=validatedProviderId(input?.providerId);
  if(env.ENTERPRISE_SSO!=="true")throw Error("Enterprise SSO disabled");
  await audit(env,actor,"enterprise_sso_domain_verify",id,"attempted");
  try{
    await auth.api.verifyDomain({headers,body:{providerId:id}});
    const record=await env.DB.prepare(
      'SELECT "domainVerified" AS verified FROM "ssoProvider" WHERE "providerId"=? LIMIT 1'
    ).bind(id).first<{verified:number}>();
    if(!record || record.verified!==1)throw Error("Better Auth domain verification did not finish");
    await audit(env,actor,"enterprise_sso_domain_verify",id,"succeeded");
    return {providerId:id,verified:true,
      note:"The enterprise domain is verified by Better Auth. Complete a staging login test before production use."};
  }catch(e){
    await audit(env,actor,"enterprise_sso_domain_verify",id,"failed");
    throw e;
  }
}

/**
 * The Cloudflare-bound bootstrap owner is a special root-of-trust. Other admins
 * require a verified account, an admin role and an explicit current D1 grant.
 */
export async function isBootstrapOwner(user:unknown,env:AuthEnv):Promise<boolean>{
  if(!isAdminUser(user,env))return false;
  if(env.NATHAN_BOOTSTRAP_REQUIRED!=="true")return true;
  const u=user as AdminActor;
  const row=await env.DB.prepare(
    "SELECT admin_user_id,admin_email,state FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1"
  ).first<{admin_user_id:string|null;admin_email:string;state:string}>();
  return Boolean(row && row.admin_user_id===u.id &&
    row.admin_email===u.email.trim().toLowerCase() && row.state!=="pending");
}
export async function isAdminPrincipal(user:unknown,env:AuthEnv):Promise<boolean>{
  if(!user||typeof user!=="object")return false;
  const u=user as Record<string,unknown>;
  if(u.emailVerified!==true||u.role!=="admin" ||
     typeof u.id!=="string"||typeof u.email!=="string")return false;
  if(await isBootstrapOwner(u,env)){
    const b=await env.DB.prepare(
      "SELECT state FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1"
    ).first<{state:string}>();
    return env.NATHAN_BOOTSTRAP_REQUIRED!=="true"||b?.state==="complete";
  }
  const grant=await env.DB.prepare(
    "SELECT enabled FROM nathan_admin_grants WHERE user_id=? AND email=? LIMIT 1"
  ).bind(u.id,u.email.trim().toLowerCase()).first<{enabled:number}>();
  return grant?.enabled===1;
}
export async function listAdminGrants(env:AuthEnv){
  const [grants,owner]=await Promise.all([
    env.DB.prepare(
      "SELECT g.user_id AS id,g.email AS email,g.enabled AS enabled,"+
      "g.granted_by AS grantedBy,g.created_at AS createdAt "+
      "FROM nathan_admin_grants g ORDER BY g.created_at DESC LIMIT 100"
    ).all(),
    env.DB.prepare(
      "SELECT admin_user_id AS id,admin_email AS email,state FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1"
    ).first()
  ]);
  return {owner,grants:grants.results.map((r:any)=>({...r,enabled:r.enabled===1}))};
}
export async function grantAdmin(env:AuthEnv,input:any,actor:string){
  const email=String(input?.email||"").trim().toLowerCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)
    throw Error("Select an existing verified user by exact email");
  if(input?.confirm!=="CONFIRM GRANT ADMIN "+email)
    throw Error("Explicit admin grant confirmation required");
  const users=await env.DB.prepare(
    'SELECT "id" AS id,"emailVerified" AS verified,"banned" AS banned FROM "user" WHERE lower("email")=? LIMIT 2'
  ).bind(email).all<{id:string;verified:number;banned:number}>();
  if(users.results.length!==1||users.results[0].verified!==1||users.results[0].banned===1)
    throw Error("User must exist, have a verified email and not be suspended");
  const id=users.results[0].id;
  const original=await env.DB.prepare(
    "SELECT admin_user_id FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1"
  ).first<{admin_user_id:string|null}>();
  if(id===original?.admin_user_id)throw Error("Initial bootstrap owner already has administrator authority");
  await audit(env,actor,"admin_grant",id,"attempted");
  try {
    await env.DB.batch([
      env.DB.prepare('UPDATE "user" SET "role"=? WHERE "id"=? AND "emailVerified"=1')
        .bind("admin",id),
      env.DB.prepare(
        "INSERT INTO nathan_admin_grants(user_id,email,granted_by,enabled) VALUES(?,?,?,1) "+
        "ON CONFLICT(user_id) DO UPDATE SET email=excluded.email,granted_by=excluded.granted_by,"+
        "enabled=1,updated_at=unixepoch()"
      ).bind(id,email,actor)
    ]);
    await audit(env,actor,"admin_grant",id,"succeeded");
    return {id,email,enabled:true,
      note:"Administrator added. Their current session must satisfy enrollment and recent passkey step-up before access."};
  }catch(e){await audit(env,actor,"admin_grant",id,"failed");throw e;}
}
export async function revokeAdminGrant(env:AuthEnv,input:any,actor:string){
  const id=input?.id;
  if(typeof id!=="string"||id.length>256||
     input.confirm!=="CONFIRM REVOKE ADMIN "+id)throw Error("Invalid revocation confirmation");
  const owner=await env.DB.prepare(
    "SELECT admin_user_id FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1"
  ).first<{admin_user_id:string|null}>();
  if(id===owner?.admin_user_id)throw Error("Cannot revoke the bootstrap root through Identity Studio");
  if(id===actor)throw Error("An administrator cannot revoke their own grant through this endpoint");
  const grant=await env.DB.prepare("SELECT enabled FROM nathan_admin_grants WHERE user_id=? LIMIT 1")
    .bind(id).first<{enabled:number}>();
  if(!grant||grant.enabled!==1)throw Error("Active admin grant not found");
  await env.DB.batch([
    env.DB.prepare("UPDATE nathan_admin_grants SET enabled=0,updated_at=unixepoch() WHERE user_id=?")
      .bind(id),
    env.DB.prepare('UPDATE "user" SET "role"=? WHERE "id"=?')
      .bind("user",id),
    env.DB.prepare('DELETE FROM "session" WHERE "userId"=?').bind(id),
    env.DB.prepare('DELETE FROM nathan_admin_assurance WHERE user_id=?').bind(id)
  ]);
  await audit(env,actor,"admin_revoke",id,"succeeded");
  return {id,enabled:false,note:"Better Auth sessions were revoked; existing external JWTs need expiry/online introspection."};
}
