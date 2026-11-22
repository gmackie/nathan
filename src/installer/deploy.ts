import type { InstallerEnv } from "./env";
import type { InstallerTokens } from "./oauth";
import { cloudflareRequest, cloudflareWrite } from "./cloudflare";
import { loadRelease, releaseFile, type NathanRelease, type ReleaseFile } from "./release";
import { validateInstallPlan, validateHostname, EMPTY_DATABASE_SQL, INSTALLER_PROVIDER_STATE_SQL, INSTALLER_PROVIDER_AUDIT_SQL } from "./validation.mjs";
import { realmIssuerHostname } from "../shared/realm.mjs";
import { generateConfigKey,sealProviderCredentials } from "../auth/config-crypto.mjs";
import { PROVIDER_IDS, validateProviderCredentials } from "../shared/providers.mjs";
import { mintAppleClientSecret } from "../auth/apple-secret.mjs";
import {sha256} from "../gateway/crypto";
import { verifyIdentityHostname } from "./verify-idp";
import { findD1Database } from "./d1";

const STAGES=["database","schema","upload","domain","activate","verify","bootstrap","complete"] as const;
type Stage=typeof STAGES[number];
type Identity={id:string;email:string};
type InstallJob={
  id:string;owner_user_id:string;owner_email:string;account_id:string;zone_id:string;
  hostname:string;worker_name:string;admin_email:string;profile:"standard"|"business";
  enterprise_sso:number;realm_apex:string|null;scim_requested:number;scim_connection_id:string|null;scim_domain:string|null;release_id:string;stage:Stage;database_id:string|null;error:string|null;
  lease_token:string|null;database_create_started_at:number|null;
  created_at:number;updated_at:number
};
type ApiSession={digest:string;tokens:InstallerTokens};
type Api=<T>(path:string)=>Promise<T>;
type Write=<T>(method:"POST"|"PUT"|"DELETE",path:string,body:unknown)=>Promise<T>;

function writeApi(env:InstallerEnv,session:ApiSession):Write {
  return (method,path,body)=>cloudflareWrite(env,session.digest,session.tokens,path,method,body);
}
function readApi(env:InstallerEnv,session:ApiSession):Api {
  return path=>cloudflareRequest(env,session.digest,session.tokens,path);
}
function safeMessage(error:unknown):string{
  const message=error instanceof Error?error.message:String(error);
  return message.replace(/(secret|token|authorization|password)\s*[:=]\s*\S+/gi,"$1=[REDACTED]").slice(0,500);
}
function records(value:unknown):any[]{
  if(!Array.isArray(value)||value.some(x=>!x||x.success!==true))throw Error("D1 SQL operation failed");
  return value.flatMap(x=>Array.isArray(x.results)?x.results:[]);
}
function sqlId(value:string){
  if(!/^[a-z0-9_-]+$/.test(value))throw Error("Unexpected internal identifier");
  return value;
}
function next(stage:Stage):Stage {
  const index=STAGES.indexOf(stage);
  if(index<0)throw Error("Invalid installer job stage");
  return STAGES[Math.min(index+1,STAGES.length-1)];
}
function describe(job:InstallJob){
  return {id:job.id,stage:job.stage,status:job.stage==="complete"?"complete":"in_progress",
    worker:job.worker_name,hostname:job.hostname,adminEmail:job.admin_email,release:job.release_id,enterpriseSso:job.enterprise_sso===1,realmApex:job.realm_apex||null,
    scimRequested:job.scim_requested===1,scimConnectionId:job.scim_connection_id||null,
    url:"https://"+job.hostname,error:job.error,
    steps:STAGES.filter(x=>x!=="complete").map((stage,index)=>({
      stage,status:index<STAGES.indexOf(job.stage)?"done":index===STAGES.indexOf(job.stage)?"next":"pending"
    }))};
}
async function identity(api:Api):Promise<Identity> {
  const user=await api<{id:string;email:string}>("/user");
  if(typeof user?.id!=="string"||user.id.length<5||
    typeof user.email!=="string"||!user.email.includes("@"))throw Error("Cloudflare did not return a verified account identity");
  return {id:user.id,email:user.email.trim().toLowerCase()};
}
async function activeAccount(api:Api,accountId:string) {
  const accounts=await api<Array<{id:string;name:string}>>("/accounts?per_page=100");
  if(!Array.isArray(accounts)||!accounts.some(a=>a.id===accountId))
    throw Error("Selected Cloudflare account is not available to this OAuth session");
}
async function resolveZone(api:Api,accountId:string,hostname:string) {
  const zones=await api<Array<{id:string;name:string;status:string}>>("/zones?account.id="+accountId+"&per_page=100");
  if(!Array.isArray(zones))throw Error("Zone inventory unavailable");
  const matching=zones.filter(z=>z.status==="active"&&(hostname===z.name||hostname.endsWith("."+z.name)))
    .sort((a,b)=>b.name.length-a.name.length)[0];
  if(!matching)throw Error("Identity hostname is not in a Cloudflare-managed active zone");
  return matching;
}
async function nameIsFree(api:Api,accountId:string,name:string,dbName:string,hostname:string,zoneId:string){
  const [scripts,existingDb,dns,domains]=await Promise.all([
    api<Array<{id:string}>>("/accounts/"+accountId+"/workers/scripts"),
    findD1Database(api,accountId,dbName),
    api<Array<{id:string;type:string}>>("/zones/"+zoneId+"/dns_records?name="+encodeURIComponent(hostname)),
    api<Array<{hostname:string;service:string}>>("/accounts/"+accountId+"/workers/domains")
  ]);
  if(!Array.isArray(scripts)||!Array.isArray(dns)||!Array.isArray(domains))
    throw Error("Cannot verify Cloudflare resource availability");
  if(scripts.some(s=>s.id===name))throw Error("A Worker with that name already exists. Choose a new name.");
  if(existingDb)throw Error("A D1 database with that name already exists. Choose a new name.");
  if(dns.length)throw Error("The identity hostname has existing DNS records; resolve them before installing");
  if(domains.some(d=>d.hostname===hostname))throw Error("This hostname is already attached to a Worker");
}
function parsePlan(input:any){
  const plan=validateInstallPlan(input);
  if(plan.securityProfile==="high")throw Error("High-assurance deployment needs validated AAL support");
  const adminEmail=String(input.adminEmail||"").trim().toLowerCase();
  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(adminEmail)||adminEmail.length>254)
    throw Error("A verified administrator email is required");
  if(input.enterpriseSSO!==undefined&&typeof input.enterpriseSSO!=="boolean")throw Error("Invalid enterprise SSO setting");
  if(input.mfaPolicy && input.mfaPolicy!=="optional")
    throw Error("Enforced MFA is not yet verified for federated logins; choose optional until AAL enforcement is available");
  return {...plan,adminEmail,enterpriseSSO:Boolean(input.enterpriseSSO)};
}
async function fetchJob(env:InstallerEnv,id:string,owner:string):Promise<InstallJob|null> {
  if(!/^[a-f0-9-]{36}$/.test(id))return null;
  return env.INSTALLER_DB.prepare(
    "SELECT * FROM nathan_install_jobs WHERE id=? AND owner_user_id=? LIMIT 1"
  ).bind(id,owner).first<InstallJob>();
}
export async function createInstall(env:InstallerEnv,session:ApiSession,input:any) {
  const api=readApi(env,session);
  const user=await identity(api);
  const plan=parsePlan(input);
  if(plan.adminEmail!==user.email)throw Error("Initial admin must match the signed-in Cloudflare identity email");
  await activeAccount(api,plan.accountId);
  const zone=await resolveZone(api,plan.accountId,plan.hostname);
  const release=await loadRelease(env);
  const existing=await env.INSTALLER_DB.prepare(
    "SELECT * FROM nathan_install_jobs WHERE account_id=? AND worker_name=? LIMIT 1"
  ).bind(plan.accountId,plan.name).first<InstallJob>();
  if(existing){
    if(existing.owner_user_id!==user.id||existing.hostname!==plan.hostname||
       existing.admin_email!==user.email||existing.realm_apex!==(plan.realmApex||null)||
       existing.scim_connection_id!==(plan.scim?.id||null))throw Error("Installation name is reserved or setup options differ");
    if(existing.release_id!==release.release)throw Error("Installed release differs; resume with original installer version");
    return describe(existing);
  }
  await nameIsFree(api,plan.accountId,plan.name,plan.name+"-db",plan.hostname,zone.id);
  const id=crypto.randomUUID();
  await env.INSTALLER_DB.prepare(
    "INSERT INTO nathan_install_jobs(id,owner_user_id,owner_email,account_id,zone_id,hostname,worker_name,admin_email,profile,enterprise_sso,realm_apex,scim_requested,scim_connection_id,scim_domain,release_id) "+
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
  ).bind(id,user.id,user.email,plan.accountId,zone.id,plan.hostname,plan.name,plan.adminEmail,
    plan.securityProfile,plan.enterpriseSSO?1:0,plan.realmApex||null,plan.scim?1:0,plan.scim?.id||null,plan.scim?.domain||null,release.release).run();
  const created=await fetchJob(env,id,user.id);
  if(!created)throw Error("Installation job was not persisted");
  return describe(created);
}
export async function installStatus(env:InstallerEnv,session:ApiSession,id:string){
  const api=readApi(env,session),user=await identity(api);
  const job=await fetchJob(env,id,user.id);
  if(!job)throw Error("Installation job not found");
  return describe(job);
}
async function query(write:Write,job:InstallJob,sql:string,params:any[]=[]):Promise<any[]>{
  if(!job.database_id||!/^[a-f0-9-]{36}$/.test(job.database_id))throw Error("D1 database not ready");
  const result=await write<any[]>("POST","/accounts/"+job.account_id+"/d1/database/"+job.database_id+"/query",{sql,params});
  return records(result);
}
/**
 * True when a D1 database holds no schema objects of any kind (tables, views, indexes,
 * triggers), ignoring only SQLite's own and Cloudflare's internal `_cf_` objects. Prefixes
 * are compared with substr(): LIKE treats `_` as a wildcard.
 */
async function databaseIsEmpty(write:Write,accountId:string,databaseId:string){
  if(!/^[a-f0-9-]{36}$/.test(databaseId))throw Error("D1 API returned an invalid database UUID");
  const result=await write<any[]>("POST","/accounts/"+accountId+"/d1/database/"+databaseId+"/query",{
    sql:EMPTY_DATABASE_SQL,params:[]});
  const rows=records(result);
  return rows.length===1&&Number(rows[0].n)===0;
}
async function ensureMigrations(env:InstallerEnv,write:Write,release:NathanRelease,job:InstallJob){
  await query(write,job,
    "CREATE TABLE IF NOT EXISTS nathan_release_migrations(name TEXT PRIMARY KEY,sha256 TEXT NOT NULL,applied_at INTEGER NOT NULL DEFAULT (unixepoch()))");
  const migrations=release.files.filter(f=>f.type==="migration").sort((a,b)=>a.name.localeCompare(b.name));
  if(migrations.length<7)throw Error("Release is missing required identity, realm, SCIM and control-plane migrations");
  for(const item of migrations){
    const prev=await query(write,job,"SELECT sha256 FROM nathan_release_migrations WHERE name=?",[item.name]);
    if(prev.length){
      if(prev[0].sha256!==item.sha256)throw Error("Migration checksum drift: "+item.name);
      continue;
    }
    const bytes=await releaseFile(env,item);
    const sql=new TextDecoder().decode(bytes);
    if(sql.length>1_000_000 || !/^[A-Za-z0-9_.-]+\.sql$/.test(item.name))throw Error("Invalid migration");
    // A single D1 SQL batch contains the schema and its checksum marker.
    const statement=sql+"\nINSERT INTO nathan_release_migrations(name,sha256) VALUES ('"+
      item.name+"','"+item.sha256+"');";
    await query(write,job,statement);
  }
}
function b64url(count:number) {
  let raw="";for(const b of crypto.getRandomValues(new Uint8Array(count)))raw+=String.fromCharCode(b);
  return btoa(raw).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"");
}
/** First-admin login provider, validated by the shared registry (NATH-9). Never echoes values. */
async function validateProvider(payload:any) {
  if(!payload||!PROVIDER_IDS.includes(payload.provider))
    throw Error("Select a supported login provider (Google, GitHub, Apple, Discord, Twitch or X) for first administrator login");
  let values:Record<string,string>;
  try{values=validateProviderCredentials(payload.provider,payload) as Record<string,string>}
  catch(e){throw Error((e as {publicMessage?:string}).publicMessage||"Provider credentials are required at initial upload")}
  if(payload.provider==="apple"){
    try{await mintAppleClientSecret(values as {clientId:string;teamId:string;keyId:string;privateKey:string})}
    catch{throw Error("Apple private key is not a valid ES256 (P-256) PKCS#8 .p8 key")}
  }
  return {name:payload.provider as string,values};
}
async function uploadWorker(
  env:InstallerEnv,write:Write,release:NathanRelease,job:InstallJob,active:boolean,
  provider?:Awaited<ReturnType<typeof validateProvider>>, configKey?:string, firstDeploy=false
){
  if(!job.database_id)throw Error("Database ID missing");
  const bindings:any[]=[
    {type:"d1",name:"DB",id:job.database_id},
    {type:"durable_object_namespace",name:"SCIM_DIRECTORY",class_name:"NathanScimDirectory"},
    {type:"plain_text",name:"NATHAN_ISSUER",text:"https://"+job.hostname},
    {type:"plain_text",name:"NATHAN_REALM_APEX",text:job.realm_apex||""},
    {type:"plain_text",name:"NATHAN_ADMIN_EMAILS",text:job.admin_email},
    {type:"plain_text",name:"NATHAN_INSTALL_ACTIVE",text:active?"true":"false"},
    {type:"plain_text",name:"NATHAN_MCP_WRITE_ENABLED",text:"false"},
    {type:"plain_text",name:"ENABLE_PASSWORD",text:"false"},
    {type:"plain_text",name:"NATHAN_SECURITY_PROFILE",text:job.profile},
    {type:"plain_text",name:"NATHAN_BOOTSTRAP_REQUIRED",text:"true"},
    {type:"plain_text",name:"NATHAN_ADMIN_STEPUP_REQUIRED",text:job.profile==="business"?"true":"false"},
    {type:"plain_text",name:"ENTERPRISE_SSO",text:job.enterprise_sso===1?"true":"false"}
  ];
  if(provider){
    if(!configKey)throw Error("Configuration encryption key missing during private Worker upload");
    bindings.push(
      {type:"secret_text",name:"BETTER_AUTH_SECRET",text:b64url(48)},
      {type:"secret_text",name:"NATHAN_CONFIG_KEY",text:configKey}
    );
  }
  const metadata={
    main_module:release.worker.mainModule,
    compatibility_date:release.worker.compatibilityDate,
    compatibility_flags:release.worker.compatibilityFlags,
    observability:release.worker.observability,
    bindings,
    tags:["nathan"],
    ...(firstDeploy?{migrations:{new_tag:"nathan-scim-v1",steps:[{new_sqlite_classes:["NathanScimDirectory"]}]}}:{}),
    ...(provider?{}:{keep_bindings:["secret_text"]}),
    annotations:{"workers/message":"nathan "+release.release+" "+(active?"activate":"private install")}
  };
  const form=new FormData();
  form.set("metadata",new File([JSON.stringify(metadata)],"metadata.json",{type:"application/json"}));
  for(const entry of release.files.filter(f=>f.type==="module")){
    const binary=await releaseFile(env,entry);
    form.set(entry.name,new File([binary],entry.name,{type:entry.contentType}));
  }
  await write("PUT","/accounts/"+job.account_id+"/workers/scripts/"+job.worker_name,form);
}
export async function advanceInstall(env:InstallerEnv,session:ApiSession,id:string,input:any={}){
  const api=readApi(env,session),unguardedWrite=writeApi(env,session);
  const user=await identity(api);
  let job=await fetchJob(env,id,user.id);
  if(!job)throw Error("Installation job not found");
  if(job.stage==="complete")return describe(job);
  const release=await loadRelease(env);
  if(job.release_id!==release.release)throw Error("This installation is pinned to another release. Resume with the original installer.");
  if(job.stage==="upload")await validateProvider(input); // Fail before claiming lock and touching Cloudflare
  // Claim a lease for the stage this request observed. RETURNING * re-reads the job under
  // the lease, so a request that waited behind another one never re-runs a finished stage.
  const lease=crypto.randomUUID();
  const claimed=await env.INSTALLER_DB.prepare(
    "UPDATE nathan_install_jobs SET locked_until=unixepoch()+300,lease_token=? WHERE id=? AND owner_user_id=? "+
    "AND stage=? AND locked_until<unixepoch() RETURNING *"
  ).bind(lease,job.id,user.id,job.stage).first<InstallJob>();
  if(!claimed)throw Error("Another setup step is running or has just finished; refresh the installation status");
  job=claimed;
  const finish=async(sql:string,...params:unknown[])=>{
    const result=await env.INSTALLER_DB.prepare(sql+" AND lease_token=?").bind(...params,lease).run();
    if(!result.meta?.changes)throw Error("Setup lease expired before this step was recorded; refresh and retry");
  };
  // Every Cloudflare mutation (including D1 queries) first proves and extends the lease. A
  // single call times out within 60 s, far inside the 300 s extension, so a request whose
  // lease was taken over can never perform another side effect.
  const write:Write=async(method,path,body)=>{
    await finish("UPDATE nathan_install_jobs SET locked_until=unixepoch()+300 WHERE id=?",job!.id);
    return unguardedWrite(method,path,body);
  };
  let actionRequired:any=null,updatedDbId:string|undefined,oneTimeScim:any=null;
  try{
    // Every step is independently resumable. No secrets are written to installer D1.
    if(job.stage==="database"){
      const dbName=job.worker_name+"-db";
      const found=await findD1Database(api,job.account_id,dbName);
      // Never reuse a database that the job cannot prove it created. A create this job started
      // whose response was lost is adopted only if Cloudflare created that database after the
      // job started the create, and it still holds no schema objects at all.
      if(found && !job.database_id){
        const startedAt=job.database_create_started_at;
        const createdAt=Date.parse(found.created_at||"")/1000;
        if(!startedAt||!Number.isFinite(createdAt)||createdAt<startedAt-5)
          throw Error("D1 database now exists but is not recorded as owned by this installer job; inspect it before retrying");
        if(!await databaseIsEmpty(write,job.account_id,found.uuid))
          throw Error("D1 database from an interrupted setup is not empty; inspect it before retrying");
      }
      let db=found;
      if(!db){
        await finish("UPDATE nathan_install_jobs SET database_create_started_at=unixepoch() WHERE id=?",job.id);
        try{
          db=await write<{uuid:string;name:string}>("POST","/accounts/"+job.account_id+"/d1/database",{name:dbName});
        }catch(error){
          // Only an unknown outcome (timeout, 5xx) may leave a database behind. A definite
          // rejection clears the marker so a database someone else creates later is never adopted.
          if(/\((4\d\d)\)/.test(error instanceof Error?error.message:""))
            await finish("UPDATE nathan_install_jobs SET database_create_started_at=NULL WHERE id=?",job.id);
          throw error;
        }
      }
      if(!/^[a-f0-9-]{36}$/.test(db.uuid))throw Error("D1 API returned an invalid database UUID");
      updatedDbId=db.uuid;job.database_id=db.uuid;
    }else if(job.stage==="schema"){
      await ensureMigrations(env,write,release,job);
      // One immutable bootstrap authority: the Cloudflare-authenticated installer.
      await query(write,job,
        "INSERT OR IGNORE INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')",
        [user.id,job.admin_email]);
      const bootstrapOwner=await query(write,job,
        "SELECT cloudflare_user_id,admin_email FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1");
      if(bootstrapOwner.length!==1 || bootstrapOwner[0].cloudflare_user_id!==user.id ||
         bootstrapOwner[0].admin_email!==job.admin_email)
        throw Error("Existing admin bootstrap belongs to another Cloudflare owner; manual recovery required");
      if(job.realm_apex){
        if(job.hostname!==realmIssuerHostname(job.realm_apex))
          throw Error("Domain-wide SSO issuer does not match verified base domain");
        await query(write,job,
          "INSERT OR IGNORE INTO nathan_domain_realms(apex,issuer_hostname,account_id,zone_id,registered_by) VALUES (?,?,?,?,?)",
          [job.realm_apex,job.hostname,job.account_id,job.zone_id,"cloudflare:"+user.id]);
        const realms=await query(write,job,
          "SELECT issuer_hostname,account_id,zone_id FROM nathan_domain_realms WHERE apex=? LIMIT 1",
          [job.realm_apex]);
        if(realms.length!==1||realms[0].issuer_hostname!==job.hostname||
           realms[0].account_id!==job.account_id||realms[0].zone_id!==job.zone_id)
          throw Error("Existing domain realm does not match approved account, zone and issuer");
      }
    }else if(job.stage==="upload"){
      const initialProvider=await validateProvider(input);
      // Both wizard and ongoing Identity Studio use the same encrypted D1 provider store.
      // This inactive IdP can be retried safely before the public route exists.
      const configKey=generateConfigKey();
      const sealed=await sealProviderCredentials(initialProvider.name,initialProvider.values,configKey);
      const scripts=await api<Array<{id:string;tags?:string[];migration_tag?:string}>>("/accounts/"+job.account_id+"/workers/scripts");
      const workerName=job.worker_name;
      const existing=scripts.find(s=>s.id===workerName);
      if(existing && (!Array.isArray(existing.tags)||!existing.tags.includes("nathan")))
        throw Error("Worker name was claimed by an unrelated deployment after planning; refusing to overwrite it");
      await query(write,job,
        "INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,config,secret_fields,updated_by) "+
        "VALUES (?,?,NULL,?,?,?) ON CONFLICT(id) DO UPDATE SET client_id=excluded.client_id,secret_cipher=NULL,"+
        "config=excluded.config,secret_fields=excluded.secret_fields,"+
        "updated_at=unixepoch(),updated_by=excluded.updated_by",
        [initialProvider.name,sealed.clientId,sealed.config,sealed.secretFields,"installer:"+user.id]);
      // New credentials start untested; a first install enables the provider, a re-run keeps an
      // administrator's disable. Every installer credential write is audited (NATH-9 provider state).
      await query(write,job,INSTALLER_PROVIDER_STATE_SQL,[initialProvider.name,"installer:"+user.id]);
      await query(write,job,INSTALLER_PROVIDER_AUDIT_SQL,[crypto.randomUUID(),"installer:"+user.id,initialProvider.name]);
      await uploadWorker(env,write,release,job,false,initialProvider,configKey,!existing?.migration_tag);
      // An uploaded Worker must never be reachable at workers.dev or preview URLs.
      await write("POST","/accounts/"+job.account_id+"/workers/scripts/"+job.worker_name+"/subdomain",
        {enabled:false,previews_enabled:false});
    }else if(job.stage==="domain"){
      const [dns,domains]=await Promise.all([
        api<Array<{id:string;name:string;type:string}>>("/zones/"+job.zone_id+"/dns_records?name="+encodeURIComponent(job.hostname)),
        api<Array<{hostname:string;service:string}>>("/accounts/"+job.account_id+"/workers/domains")
      ]);
      const targetHostname=job.hostname;
      const attached=domains.find(d=>d.hostname===targetHostname);
      if(attached?.service===job.worker_name){ /* previous step attached, safe to resume */ }
      else {
        if(dns.length||attached)throw Error("Hostname has conflicting DNS or Worker routing; cannot replace it");
        await write("PUT","/accounts/"+job.account_id+"/workers/domains",
          {hostname:job.hostname,zone_id:job.zone_id,service:job.worker_name,environment:"production"});
      }
    }else if(job.stage==="activate"){
      await uploadWorker(env,write,release,job,true);
    }else if(job.stage==="verify"){
      await verifyIdentityHostname(validateHostname(job.hostname));
    }else if(job.stage==="bootstrap"){
      // A verified Better Auth user with exactly the Cloudflare installer identity's
      // approved email is necessary; no unauthenticated bootstrap password.
      const rows=await query(write,job,
        'SELECT "id","email","emailVerified","role" FROM "user" WHERE lower("email")=lower(?) LIMIT 2',
        [job.admin_email]);
      if(rows.length!==1||Number(rows[0].emailVerified)!==1) {
        actionRequired={kind:"sign-in",url:"https://"+job.hostname+"/sign-in",
          instruction:"Sign in at Nathan with the verified Cloudflare account email, then return to the wizard."};
      } else {
        const existing=await query(write,job,
          "SELECT cloudflare_user_id,admin_email,admin_user_id,state FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1");
        if(existing.length!==1 || existing[0].cloudflare_user_id!==user.id ||
           existing[0].admin_email!==job.admin_email ||
           (existing[0].admin_user_id && existing[0].admin_user_id!==rows[0].id))
          throw Error("Initial administrator claim conflicts with the verified Cloudflare installer identity");
        if(rows[0].role!=="admin"){
          await query(write,job,
            'UPDATE "user" SET "role"=? WHERE "id"=? AND "emailVerified"=1',
            ["admin",rows[0].id]);
          await query(write,job,
            "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)",
            [crypto.randomUUID(),"installer:"+user.id,"admin_bootstrap",rows[0].id,"succeeded"]);
        }
        await query(write,job,
          "UPDATE nathan_bootstrap_status SET admin_user_id=?,state=CASE WHEN state='complete' THEN 'complete' "+
          "ELSE 'identity_verified' END,updated_at=unixepoch() WHERE id='primary' AND cloudflare_user_id=?",
          [rows[0].id,user.id]);
        const state=await query(write,job,
          "SELECT state FROM nathan_bootstrap_status WHERE id='primary' AND admin_user_id=? LIMIT 1",
          [rows[0].id]);
        if(state.length!==1 || state[0].state!=="complete") {
          actionRequired={kind:"security-enrollment",url:"https://"+job.hostname+"/security?setup=admin",
            instruction:"Initial admin identity verified. Enroll a passkey and a TOTP authenticator, save backup codes, then click Complete initial setup on Nathan's security page and resume the wizard."};
        }
        else if(job.scim_requested===1 && job.scim_connection_id && job.scim_domain){
          // Optional first connection uses the same D1 credential schema as Identity
          // Studio. Never store a raw bearer token in the installer job.
          const previous=await query(write,job,
            "SELECT id FROM nathan_scim_connections WHERE id=? LIMIT 1",[job.scim_connection_id]);
          if(previous.length===0){
            const token="nathscim_"+b64url(32),digest=await sha256(token);
            await query(write,job,
              "INSERT INTO nathan_scim_connections(id,domain,mode,enabled,created_by) VALUES(?,?,'directory-only',0,?)",
              [job.scim_connection_id,job.scim_domain,"installer:"+user.id]);
            await query(write,job,
              "INSERT INTO nathan_scim_credentials(id,connection_id,token_hash) VALUES(?,?,?)",
              [crypto.randomUUID(),job.scim_connection_id,digest]);
            oneTimeScim={id:job.scim_connection_id,
              baseUrl:"https://"+job.hostname+"/scim/v2/"+job.scim_connection_id,
              bearerToken:token,enabled:false,
              warning:"Copy the one-time SCIM token to a secrets manager. This directory-only connection starts disabled and does not grant users access."};
          }
        }
      }}
    if(actionRequired){
      await finish("UPDATE nathan_install_jobs SET locked_until=0,lease_token=NULL,error=NULL,updated_at=unixepoch() WHERE id=?",job.id);
      return {...describe(job),actionRequired};
    }
    const following=next(job.stage);
    await finish(
      "UPDATE nathan_install_jobs SET stage=?,database_id=COALESCE(?,database_id),locked_until=0,lease_token=NULL,error=NULL,updated_at=unixepoch() WHERE id=? AND stage=?",
      following,updatedDbId||null,job.id,job.stage);
    job=(await fetchJob(env,job.id,user.id))!;
    return {...describe(job),...(oneTimeScim?{oneTimeScim}:{})};
  }catch(error){
    // Only the current lease holder may record an error or release the lock.
    await env.INSTALLER_DB.prepare(
      "UPDATE nathan_install_jobs SET error=?,locked_until=0,lease_token=NULL,updated_at=unixepoch() WHERE id=? AND lease_token=?"
    ).bind(safeMessage(error),job.id,lease).run();
    throw error;
  }
}
