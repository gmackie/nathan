import type { InstallerEnv } from "./env";
import type { InstallerTokens } from "./oauth";
import { cloudflareRequest, cloudflareWrite } from "./cloudflare";
import { loadRelease, releaseFile, type NathanRelease, type ReleaseFile } from "./release";
import { validateInstallPlan, validateHostname } from "./validation.mjs";
import { realmIssuerHostname } from "../shared/realm.mjs";
import { generateConfigKey,encryptProviderSecret } from "../auth/config-crypto.mjs";

const STAGES=["database","schema","upload","domain","activate","verify","bootstrap","complete"] as const;
type Stage=typeof STAGES[number];
type Identity={id:string;email:string};
type InstallJob={
  id:string;owner_user_id:string;owner_email:string;account_id:string;zone_id:string;
  hostname:string;worker_name:string;admin_email:string;profile:"standard"|"business";
  enterprise_sso:number;realm_apex:string|null;release_id:string;stage:Stage;database_id:string|null;error:string|null;
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
  const [scripts,dbs,dns,domains]=await Promise.all([
    api<Array<{id:string}>>("/accounts/"+accountId+"/workers/scripts"),
    api<Array<{name:string}>>("/accounts/"+accountId+"/d1/database"),
    api<Array<{id:string;type:string}>>("/zones/"+zoneId+"/dns_records?name="+encodeURIComponent(hostname)),
    api<Array<{hostname:string;service:string}>>("/accounts/"+accountId+"/workers/domains")
  ]);
  if(!Array.isArray(scripts)||!Array.isArray(dbs)||!Array.isArray(dns)||!Array.isArray(domains))
    throw Error("Cannot verify Cloudflare resource availability");
  if(scripts.some(s=>s.id===name))throw Error("A Worker with that name already exists. Choose a new name.");
  if(dbs.some(d=>d.name===dbName))throw Error("A D1 database with that name already exists. Choose a new name.");
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
       existing.admin_email!==user.email||existing.realm_apex!==(plan.realmApex||null))throw Error("Installation name is reserved or domain realm differs");
    if(existing.release_id!==release.release)throw Error("Installed release differs; resume with original installer version");
    return describe(existing);
  }
  await nameIsFree(api,plan.accountId,plan.name,plan.name+"-db",plan.hostname,zone.id);
  const id=crypto.randomUUID();
  await env.INSTALLER_DB.prepare(
    "INSERT INTO nathan_install_jobs(id,owner_user_id,owner_email,account_id,zone_id,hostname,worker_name,admin_email,profile,enterprise_sso,realm_apex,release_id) "+
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
  ).bind(id,user.id,user.email,plan.accountId,zone.id,plan.hostname,plan.name,plan.adminEmail,
    plan.securityProfile,plan.enterpriseSSO?1:0,plan.realmApex||null,release.release).run();
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
async function ensureMigrations(env:InstallerEnv,write:Write,release:NathanRelease,job:InstallJob){
  await query(write,job,
    "CREATE TABLE IF NOT EXISTS nathan_release_migrations(name TEXT PRIMARY KEY,sha256 TEXT NOT NULL,applied_at INTEGER NOT NULL DEFAULT (unixepoch()))");
  const migrations=release.files.filter(f=>f.type==="migration").sort((a,b)=>a.name.localeCompare(b.name));
  if(migrations.length<6)throw Error("Release is missing identity, realm or control-plane migrations");
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
function validateProvider(payload:any) {
  if(!payload||!["google","github"].includes(payload.provider))throw Error("Select Google or GitHub for first administrator login");
  if(typeof payload.clientId!=="string"||payload.clientId.length<8||payload.clientId.length>512||
     typeof payload.clientSecret!=="string"||payload.clientSecret.length<12||payload.clientSecret.length>4096)
    throw Error("OAuth client ID and secret are required at initial upload");
  return {name:payload.provider,id:payload.clientId,secret:payload.clientSecret};
}
async function uploadWorker(
  env:InstallerEnv,write:Write,release:NathanRelease,job:InstallJob,active:boolean,
  provider?:ReturnType<typeof validateProvider>, configKey?:string
){
  if(!job.database_id)throw Error("Database ID missing");
  const bindings:any[]=[
    {type:"d1",name:"DB",id:job.database_id},
    {type:"plain_text",name:"NATHAN_ISSUER",text:"https://"+job.hostname},
    {type:"plain_text",name:"NATHAN_REALM_APEX",text:job.realm_apex||""},
    {type:"plain_text",name:"NATHAN_ADMIN_EMAILS",text:job.admin_email},
    {type:"plain_text",name:"NATHAN_INSTALL_ACTIVE",text:active?"true":"false"},
    {type:"plain_text",name:"NATHAN_MCP_WRITE_ENABLED",text:"false"},
    {type:"plain_text",name:"ENABLE_PASSWORD",text:"false"},
    {type:"plain_text",name:"NATHAN_SECURITY_PROFILE",text:job.profile},
    {type:"plain_text",name:"NATHAN_BOOTSTRAP_REQUIRED",text:"true"},
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
  const api=readApi(env,session),write=writeApi(env,session);
  const user=await identity(api);
  let job=await fetchJob(env,id,user.id);
  if(!job)throw Error("Installation job not found");
  if(job.stage==="complete")return describe(job);
  const release=await loadRelease(env);
  if(job.release_id!==release.release)throw Error("This installation is pinned to another release. Resume with the original installer.");
  if(job.stage==="upload")validateProvider(input); // Fail before claiming lock and touching Cloudflare
  const claim=await env.INSTALLER_DB.prepare(
    "UPDATE nathan_install_jobs SET locked_until=unixepoch()+300 WHERE id=? AND owner_user_id=? "+
    "AND locked_until<unixepoch() RETURNING id"
  ).bind(job.id,user.id).first<{id:string}>();
  if(!claim)throw Error("A setup operation is already in progress");
  let actionRequired:any=null,updatedDbId:string|undefined;
  try{
    // Every step is independently resumable. No secrets are written to installer D1.
    if(job.stage==="database"){
      const dbName=job.worker_name+"-db";
      const databases=await api<Array<{uuid:string;name:string}>>("/accounts/"+job.account_id+"/d1/database");
      const found=databases.find(d=>d.name===dbName);
      // Never reuse a database that the job cannot prove it created.
      if(found && !job.database_id)
        throw Error("D1 database now exists but is not recorded as owned by this installer job; inspect it before retrying");
      const db=found||await write<{uuid:string}>("POST","/accounts/"+job.account_id+"/d1/database",{name:dbName});
      if(!/^[a-f0-9-]{36}$/.test(db.uuid))throw Error("D1 API returned an invalid database UUID");
      updatedDbId=db.uuid;job.database_id=db.uuid;
    }else if(job.stage==="schema"){
      await ensureMigrations(env,write,release,job);
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
      const initialProvider=validateProvider(input);
      // Both wizard and ongoing Identity Studio use the same encrypted D1 provider store.
      // This inactive IdP can be retried safely before the public route exists.
      const configKey=generateConfigKey();
      const cipher=await encryptProviderSecret(initialProvider.name,initialProvider.secret,configKey);
      const scripts=await api<Array<{id:string;tags?:string[]}>>("/accounts/"+job.account_id+"/workers/scripts");
      const workerName=job.worker_name;
      const existing=scripts.find(s=>s.id===workerName);
      if(existing && (!Array.isArray(existing.tags)||!existing.tags.includes("nathan")))
        throw Error("Worker name was claimed by an unrelated deployment after planning; refusing to overwrite it");
      await query(write,job,
        "INSERT INTO nathan_oauth_providers(id,client_id,secret_cipher,enabled,updated_by) "+
        "VALUES (?,?,?,1,?) ON CONFLICT(id) DO UPDATE SET client_id=excluded.client_id,"+
        "secret_cipher=excluded.secret_cipher,enabled=1,updated_at=unixepoch(),updated_by=excluded.updated_by",
        [initialProvider.name,initialProvider.id,cipher,"installer:"+user.id]);
      await uploadWorker(env,write,release,job,false,initialProvider,configKey);
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
      const base="https://"+validateHostname(job.hostname);
      const [health,discovery,jwks]=await Promise.all([
        fetch(base+"/healthz",{redirect:"error",signal:AbortSignal.timeout(7000)}),
        fetch(base+"/.well-known/openid-configuration",{redirect:"error",signal:AbortSignal.timeout(7000)}),
        fetch(base+"/api/auth/jwks",{redirect:"error",signal:AbortSignal.timeout(7000)})
      ]);
      if(!health.ok||!discovery.ok||!jwks.ok)throw Error("Identity hostname not healthy yet; check route, secrets, and DNS propagation");
      const healthJson=await health.json() as {active?:boolean};
      const metadata=await discovery.json() as {issuer?:string};
      const keys=await jwks.json() as {keys?:unknown[]};
      if(!healthJson.active||metadata.issuer!=="https://"+job.hostname+"/api/auth"||
         !Array.isArray(keys.keys))throw Error("OIDC discovery, JWKS or active flag mismatch");
    }else if(job.stage==="bootstrap"){
      const rows=await query(write,job,'SELECT "id","email","emailVerified","role" FROM "user" WHERE lower("email")=lower(?) LIMIT 2',[job.admin_email]);
      if(rows.length!==1||Number(rows[0].emailVerified)!==1)actionRequired={
        kind:"sign-in",url:"https://"+job.hostname+"/sign-in",
        instruction:"Sign in with the verified Cloudflare email using the configured upstream provider, then retry this step."
      };
      else if(rows[0].role!=="admin"){
        await query(write,job,'UPDATE "user" SET "role"=? WHERE "id"=? AND "emailVerified"=1',["admin",rows[0].id]);
        await query(write,job,
          "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)",
          [crypto.randomUUID(),"installer:"+user.id,"admin_bootstrap",rows[0].id,"succeeded"]);
      }
    }
    if(actionRequired){
      await env.INSTALLER_DB.prepare("UPDATE nathan_install_jobs SET locked_until=0,error=NULL,updated_at=unixepoch() WHERE id=?")
        .bind(job.id).run();
      return {...describe(job),actionRequired};
    }
    const following=next(job.stage);
    await env.INSTALLER_DB.prepare(
      "UPDATE nathan_install_jobs SET stage=?,database_id=COALESCE(?,database_id),locked_until=0,error=NULL,updated_at=unixepoch() WHERE id=?"
    ).bind(following,updatedDbId||null,job.id).run();
    job=(await fetchJob(env,job.id,user.id))!;
    return describe(job);
  }catch(error){
    await env.INSTALLER_DB.prepare("UPDATE nathan_install_jobs SET error=?,locked_until=0,updated_at=unixepoch() WHERE id=?")
      .bind(safeMessage(error),job.id).run();
    throw error;
  }
}
