import { randomId, sha256 } from "../gateway/crypto";
import { parseCookie, makeCookie, constantTimeEqual } from "../shared/security.mjs";
import { validateAccountId, validateHostname, validateInstallPlan, isAllowedOrigin } from "./validation.mjs";
import { oauthAuthorizeUrl, oauthExchange } from "./oauth";
import { beginOAuthState, consumeOAuthState, createInstallerSession, installerSession, deleteInstallerSession, pruneInstallerState } from "./storage";
import { cloudflareRequest } from "./cloudflare";
import { installerPage } from "./ui";
import { validateDomainName,discoverRealmHostCandidates,realmIssuerHostname } from "../shared/realm.mjs";
import { createInstall, installStatus, advanceInstall } from "./deploy";
import type { InstallerEnv } from "./env";

const STATE_COOKIE="__Host-nathan-installer-state";
const SESSION_COOKIE="__Host-nathan-installer";
function error(status:number,error:string){return Response.json({error},{status,headers:{"Cache-Control":"no-store"}})}
function responseSecurity(response:Response){
  response.headers.set("Cache-Control","no-store");
  response.headers.set("Referrer-Policy","no-referrer");
  response.headers.set("X-Content-Type-Options","nosniff");
  response.headers.set("X-Frame-Options","DENY");
  response.headers.set("Strict-Transport-Security","max-age=31536000");
  return response;
}
function expectedOrigin(env:InstallerEnv){
  const u=new URL(env.PUBLIC_ORIGIN);
  if(u.protocol!=="https:"||u.origin!==u.href.replace(/\/$/,"")||u.username||u.password)
    throw Error("PUBLIC_ORIGIN must be an HTTPS bare origin");
  if(!env.INSTALLER_ENCRYPTION_KEY||!env.CF_OAUTH_CLIENT_ID||!env.CF_OAUTH_CLIENT_SECRET)
    throw Error("Installer secrets are not configured");
  return u.origin;
}
function sessionCookie(request:Request){return parseCookie(request.headers.get("Cookie"),SESSION_COOKIE)}
async function connected(request:Request,env:InstallerEnv){
  return installerSession(env,sessionCookie(request));
}
async function dashboard(request:Request,env:InstallerEnv){
  const url=new URL(request.url),path=url.pathname;
  if(path==="/"&&request.method==="GET"){
    const nonce=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    const body=installerPage(nonce);
    return new Response(body,{headers:{
      "Content-Type":"text/html; charset=utf-8",
      "Content-Security-Policy":"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    }});
  }
  if(path==="/api/login"&&request.method==="GET"){
    const verifier=randomId();
    const state=await beginOAuthState(env,verifier);
    const authorize=await oauthAuthorizeUrl(env,state,verifier);
    const r=Response.redirect(authorize,302);
    r.headers.append("Set-Cookie",makeCookie(STATE_COOKIE,state,{maxAge:300}));
    return r;
  }
  if(path==="/api/callback"&&request.method==="GET"){
    const state=url.searchParams.get("state");
    const cookie=parseCookie(request.headers.get("Cookie"),STATE_COOKIE);
    if(!state||!cookie||!constantTimeEqual(state,cookie))return error(400,"Invalid OAuth state");
    const verifier=await consumeOAuthState(env,state);
    if(!verifier)return error(400,"OAuth state expired or already used");
    const code=url.searchParams.get("code");
    if(!code||code.length>4096)return error(400,"Authorization code missing");
    const tokens=await oauthExchange(env,code,verifier);
    const handle=await createInstallerSession(env,tokens);
    const response=Response.redirect(env.PUBLIC_ORIGIN+"/",303);
    response.headers.append("Set-Cookie",makeCookie(SESSION_COOKIE,handle,{maxAge:1800}));
    response.headers.append("Set-Cookie",makeCookie(STATE_COOKIE,"",{deleteCookie:true}));
    return response;
  }
  if(path==="/api/health"&&request.method==="GET")return Response.json({ok:true,service:"nathan-installer"});
  if(path.startsWith("/api/")&&request.method==="POST"){
    const origin=request.headers.get("Origin");
    if(!isAllowedOrigin(origin,env.PUBLIC_ORIGIN))return error(403,"Cross-origin request rejected");
    if(!request.headers.get("Content-Type")?.startsWith("application/json")&&path!=="/api/logout")
      return error(415,"JSON required");
  }
  const session=await connected(request,env);
  if(!session)return error(401,"Connect your Cloudflare account first");
  if(path==="/api/logout"&&request.method==="POST"){
    const handle=sessionCookie(request);
    if(handle)await deleteInstallerSession(env,handle);
    const r=new Response(null,{status:204});r.headers.append("Set-Cookie",makeCookie(SESSION_COOKIE,"",{deleteCookie:true}));
    return r;
  }
  const api=<T>(path:string)=>cloudflareRequest<T>(env,session.digest,session.tokens,path);
  if(path==="/api/session"&&request.method==="GET"){
    const user=await api<{id:string;email:string}>("/user");
    return Response.json({user:{email:user.email},expiresAt:session.expiresAt});
  }
  if(path==="/api/accounts"&&request.method==="GET"){
    const accounts=await api<Array<{id:string;name:string}>>("/accounts?per_page=100");
    return Response.json({accounts:accounts.map(a=>({id:a.id,name:a.name}))});
  }
  if(path==="/api/zones"&&request.method==="GET"){
    const accountId=validateAccountId(url.searchParams.get("account"));
    const zones=await api<Array<{id:string;name:string;status:string}>>("/zones?account.id="+accountId+"&per_page=100");
    return Response.json({zones:zones.filter(z=>z.status==="active").map(z=>({id:z.id,name:z.name,status:z.status}))});
  }
  if(path==="/api/workers"&&request.method==="GET"){
    const accountId=validateAccountId(url.searchParams.get("account"));
    const workers=await api<Array<{id:string}>>("/accounts/"+accountId+"/workers/scripts");
    return Response.json({workers:workers.map(w=>w.id)});
  }
  if(path==="/api/realm/discover"&&request.method==="GET"){
    let accountId:string,apex:string;
    try{
      accountId=validateAccountId(url.searchParams.get("account"));
      apex=validateDomainName(url.searchParams.get("apex"));
    }catch{return error(400,"Valid account and base domain are required");}
    const zones=await api<Array<{id:string;name:string;status:string}>>("/zones?account.id="+accountId+"&per_page=100");
    if(!Array.isArray(zones))return error(503,"Zone inventory unavailable");
    const zone=zones.filter(z=>z.status==="active"&&(apex===z.name||apex.endsWith("."+z.name)))
      .sort((a,b)=>b.name.length-a.name.length)[0];
    if(!zone)return error(403,"The requested domain does not belong to an accessible active Cloudflare zone");
    const records:Array<{name:string;type:string;proxied?:boolean}>=[];
    for(let page=1;page<=100;page++){
      const pageRecords=await api<Array<{name:string;type:string;proxied?:boolean}>>(
        "/zones/"+zone.id+"/dns_records?per_page=100&page="+page);
      if(!Array.isArray(pageRecords))return error(503,"Unable to enumerate DNS records");
      records.push(...pageRecords);
      if(pageRecords.length<100)break;
      if(page===100)return error(413,"Zone inventory exceeds safe discovery limit");
    }
    const workerDomains=await api<Array<{hostname:string;service?:string;zone_id?:string}>>(
      "/accounts/"+accountId+"/workers/domains");
    if(!Array.isArray(workerDomains))return error(503,"Unable to enumerate Worker custom domains");
    const candidates=discoverRealmHostCandidates({
      apex,issuerHostname:realmIssuerHostname(apex),
      dnsRecords:records,workerDomains:workerDomains.filter(d=>!d.zone_id||d.zone_id===zone.id)
    });
    return Response.json({
      apex,issuer:"https://"+realmIssuerHostname(apex)+"/api/auth",zone:zone.name,
      root:apex,subdomains:"*."+apex,candidates,status:"review-only",
      warning:"Candidates are not automatically registered or protected. Approve each exact hostname as an OIDC client in Nathan Studio."
    },{headers:{"Cache-Control":"no-store"}});
  }
  if(path==="/api/plan"&&request.method==="POST"){
    const bodyText=await request.text();
    if(bodyText.length>8192)return error(413,"Request too large");
    let plan;try{plan=validateInstallPlan(JSON.parse(bodyText));}catch(e){return error(400,"Invalid installation plan")}
    const zones=await api<Array<{id:string;name:string;status:string}>>("/zones?account.id="+plan.accountId+"&per_page=100");
    const zone=zones.filter(z=>z.status==="active"&&(plan.hostname===z.name||plan.hostname.endsWith("."+z.name))).sort((a,b)=>b.name.length-a.name.length)[0];
    if(!zone)return error(400,"Identity hostname is not in an accessible active Cloudflare zone");
    const [workers,databases,dns,domains]=await Promise.all([
      api<Array<{id:string}>>("/accounts/"+plan.accountId+"/workers/scripts"),
      api<Array<{uuid:string;name:string}>>("/accounts/"+plan.accountId+"/d1/database"),
      api<Array<{id:string;type:string;name:string}>>("/zones/"+zone.id+"/dns_records?name="+encodeURIComponent(plan.hostname)),
      api<Array<{hostname:string;service:string}>>("/accounts/"+plan.accountId+"/workers/domains")
    ]);
    const worker=workers.find(w=>w.id===plan.name),database=databases.find(d=>d.name===plan.name+"-db");
    const domain=domains.find(d=>d.hostname===plan.hostname);
    const available=!worker&&!database&&!dns.length&&!domain;
    return Response.json({
      status:"preview-only",
      publishAvailable:available,
      accountId:plan.accountId,
      zone:zone.name,hostname:plan.hostname,securityProfile:plan.securityProfile,realmApex:plan.realmApex,
      resources:[
        {kind:"worker",name:plan.name,action:worker?"CONFLICT: Worker already exists":"create"},
        {kind:"d1",name:plan.name+"-db",action:database?"CONFLICT: D1 name in use":"create"},
        {kind:"custom-domain",name:plan.hostname,action:dns.length||domain?"CONFLICT: hostname in use":"create"},
        ...(plan.realmApex?[{kind:"oidc-realm",name:plan.realmApex,issuer:"https://"+plan.hostname+"/api/auth",action:"create",
          coverage:[plan.realmApex,"*."+plan.realmApex],clientRegistration:"approved-only"}]:[])
      ],
      warning:available?"No changes made. Review this plan and select Start deployment to continue.":"No changes made. Resolve all resource conflicts before starting deployment."
    },{headers:{"Cache-Control":"no-store"}});
  }

  if(path==="/api/install/start"&&request.method==="POST"){
    const raw=await request.text();
    if(raw.length>8192)return error(413,"Installation plan too large");
    try{
      const body=JSON.parse(raw);
      const result=await createInstall(env,session,body);
      return Response.json({job:result},{headers:{"Cache-Control":"no-store"}});
    }catch(e){
      return error(400,e instanceof Error?e.message:"Unable to start installation");
    }
  }
  if(path==="/api/install/status"&&request.method==="GET"){
    const id=url.searchParams.get("id")||"";
    try{return Response.json({job:await installStatus(env,session,id)},{headers:{"Cache-Control":"no-store"}})}
    catch{return error(404,"Installation unavailable or not owned by this session")}
  }
  if(path==="/api/install/advance"&&request.method==="POST"){
    const raw=await request.text();
    if(raw.length>8192)return error(413,"Step input too large");
    try{
      const body=JSON.parse(raw);
      if(typeof body?.id!=="string")return error(400,"Installation ID required");
      const job=await advanceInstall(env,session,body.id,body.credentials||{});
      return Response.json({job},{headers:{"Cache-Control":"no-store"}});
    }catch(e){
      // No secrets are included in ordinary errors; the installer stores only a sanitized reason.
      const reason=e instanceof Error?e.message:"Installer step failed";
      return error(409,reason.replace(/(secret|token|password)[=:]\S+/gi,"$1=[REDACTED]").slice(0,500));
    }
  }
  if(path==="/api/apply"&&request.method==="POST")
    return error(410,"Use /api/install/start and /api/install/advance with the current installer release");
  return error(404,"Not found");
}

export default {
  async fetch(request:Request,env:InstallerEnv){
    try {
      const origin=expectedOrigin(env),url=new URL(request.url);
      if(url.origin!==origin)return responseSecurity(error(421,"Misdirected request"));
      return responseSecurity(await dashboard(request,env));
    } catch {
      return responseSecurity(error(503,"Installer operation unavailable; retry or reconnect"));
    }
  },
  async scheduled(_:ScheduledEvent,env:InstallerEnv){await pruneInstallerState(env)}
};
