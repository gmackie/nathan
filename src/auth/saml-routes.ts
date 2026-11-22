/**
 * HTTP routes for inbound enterprise SAML (NATH-10): the protocol gate in
 * front of the plugin's SAML endpoints, "Sign in with SSO" routing, and the
 * Identity Studio admin API. Kept out of worker.ts so it stays a small,
 * additive routing change.
 */
import type { AuthEnv } from "./env";
import { audit, isAdminPrincipal } from "./admin-service";
import { mayAdminister } from "./bootstrap";
import { samlProviderFromPath, samlConnectionUsable, resolveSsoConnection, inspectSamlMessage, formDataMatches } from "./saml-policy.mjs";
import { listSamlConnections, previewSamlMetadata, createSamlConnection, setSamlConnectionEnabled,
  setSamlProvisioning, addSamlCertificate, retireSamlCertificate } from "./saml-admin";

const noStore = { "Cache-Control": "no-store" };
function reject(status:number,reason:string,code?:string){
  return Response.json(code?{error:reason,code}:{error:reason},{status,headers:noStore});
}
/** Admin-readable reason from Nathan's validators; never database internals. */
export function reason(e:unknown,fallback:string){
  const m=e instanceof Error?e.message:"";
  return m&&m.length<=300&&!/D1_|SQLITE|SQL|stack/i.test(m)?m:fallback;
}

/**
 * Security event for a refused SAML message: the connection and the refusal code only,
 * never the message. This runs before Better Auth's rate limiter, so the row id is
 * deterministic per connection, code and minute: a flood of unauthenticated rejections
 * writes at most one row per (connection, code) per minute instead of one per request.
 */
async function auditRejection(env:AuthEnv,connection:string,code:string){
  const minute=Math.floor(Date.now()/60_000);
  await env.DB.prepare("INSERT OR IGNORE INTO nathan_security_audit (id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
    .bind("saml-rejected:"+connection+":"+code+":"+minute,"anonymous","saml_message_rejected",connection+":"+code,"rejected").run();
}

/**
 * Runs before auth.handler for /api/auth/*. SAML ACS/SLO paths only reach the
 * plugin for an enabled connection with a verified domain, and only after
 * Nathan's message guard (inspectSamlMessage) has accepted the exact message
 * the plugin will parse; raw SSO sign-in must name a usable connection explicitly.
 */
export async function samlProtocolGate(request:Request,env:AuthEnv,url:URL):Promise<Response|null>{
  const id=samlProviderFromPath(url.pathname);
  if(id!==null){
    if(!await samlConnectionUsable(env.DB,id))return reject(404,"SAML connection unavailable");
    // better-call parses a body for every method and the ACS accepts GET, so a SAMLResponse in
    // the body of a GET would reach the plugin without inspection. Only POST may carry a body.
    if(request.method!=="POST"&&request.body!==null){
      await auditRejection(env,id,"saml_body_not_allowed");
      return reject(400,"SAML messages in a request body must use POST","saml_body_not_allowed");
    }
    const raw=request.method==="POST"?await request.clone().text():"";
    if(raw.length>400_000)return reject(413,"SAML message too large");
    const endpoint=url.pathname.includes("/sp/acs/")?"acs":url.pathname.includes("/sp/slo/")?"slo":"logout";
    const contentType=request.headers.get("Content-Type")??"";
    let refused=inspectSamlMessage({endpoint,method:request.method,search:url.search,contentType,body:raw});
    if(!refused&&request.method==="POST"&&contentType.split(";")[0].trim().toLowerCase()==="application/x-www-form-urlencoded"){
      // Parse with the exact primitive the plugin uses; any divergence from what was
      // inspected means the plugin could process a message Nathan never checked.
      let entries:Iterable<[string,FormDataEntryValue]>|null=null;
      try{entries=(await request.clone().formData()).entries()}catch{entries=null}
      if(!entries||!formDataMatches(raw,entries))
        refused={status:400,code:"saml_noncanonical_encoding",message:"SAML message rejected: non-canonical form encoding"};
    }
    if(refused){
      await auditRejection(env,id,refused.code);
      return reject(refused.status,refused.message,refused.code);
    }
    // Single logout is not enabled (no enableSingleLogout in the plugin options), and the SLO
    // endpoint reads SAMLRequest/SAMLResponse from the query, which this gate does not decode.
    // Refuse it here so enabling SLO later requires extending the guard first.
    if(endpoint==="slo")return reject(404,"SAML single logout is not enabled");
    return null;
  }
  if(url.pathname==="/api/auth/sign-in/sso"&&request.method==="POST"){
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")return reject(415,"JSON required");
    const raw=await request.clone().text();
    if(raw.length>8192)return reject(413,"Request too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    const providerId=typeof body?.providerId==="string"?body.providerId:"";
    if(!/^[a-z][a-z0-9-]{1,62}$/.test(providerId))
      return reject(400,"Use Sign in with SSO; enterprise sign-in must name an enabled connection");
    const row=await env.DB.prepare('SELECT "samlConfig" IS NOT NULL AS saml,"domainVerified" AS verified FROM "ssoProvider" WHERE "providerId"=? LIMIT 1')
      .bind(providerId).first<{saml:number;verified:number}>();
    if(!row||Number(row.verified)!==1)return reject(404,"Enterprise connection unavailable");
    if(Number(row.saml)===1&&!await samlConnectionUsable(env.DB,providerId))return reject(404,"Enterprise connection unavailable");
  }
  return null;
}

async function adminSession(auth:any,env:AuthEnv,request:Request){
  const session=await auth.api.getSession({headers:request.headers});
  if(!await isAdminPrincipal(session?.user,env)||!await mayAdminister(env,session!.user.id,session!.session.id))return null;
  return session as {user:{id:string};session:{id:string}};
}

const POSTS:Record<string,(auth:any,env:AuthEnv,headers:Headers,body:any,actor:string)=>Promise<unknown>>={
  "/studio/api/saml/preview":(_a,env,_h,body,actor)=>previewSamlMetadata(env,body,actor),
  "/studio/api/saml/connections":(auth,env,headers,body,actor)=>createSamlConnection(auth,env,headers,body,actor),
  "/studio/api/saml/status":(_a,env,_h,body,actor)=>setSamlConnectionEnabled(env,body,actor),
  "/studio/api/saml/provisioning":(_a,env,_h,body,actor)=>setSamlProvisioning(env,body,actor),
  "/studio/api/saml/certificates":(_a,env,_h,body,actor)=>addSamlCertificate(env,body,actor),
  "/studio/api/saml/certificates/retire":(_a,env,_h,body,actor)=>retireSamlCertificate(env,body,actor)
};

/** Safe message for a refused SAML admin change (shared with the Studio API v1). */
export const SAML_ADMIN_REFUSAL="SAML change rejected. Check the metadata, confirmation text and domain verification.";

/** Nathan-owned SAML routes outside /api/auth. Returns null when not matched. */
export async function handleSamlRoutes(request:Request,env:AuthEnv,auth:any,url:URL):Promise<Response|null>{
  const issuer=new URL(env.NATHAN_ISSUER);
  if(url.pathname==="/sign-in/sso/start"&&request.method==="POST"){
    if(env.ENTERPRISE_SSO!=="true")return reject(404,"Enterprise sign-in is not enabled");
    if(request.headers.get("Origin")!==issuer.origin||request.headers.get("Sec-Fetch-Site")==="cross-site")
      return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")return reject(415,"JSON required");
    const raw=await request.text();
    if(raw.length>2048)return reject(413,"Request too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    const target=await resolveSsoConnection(env.DB,typeof body?.email==="string"?body.email.trim():"");
    if(!target)return reject(404,"No enterprise sign-in is configured for this email domain");
    const headers=new Headers({"Content-Type":"application/json",Origin:issuer.origin});
    for(const h of ["Cookie","User-Agent","cf-connecting-ip"]){const v=request.headers.get(h);if(v)headers.set(h,v);}
    return auth.handler(new Request(issuer.origin+"/api/auth/sign-in/sso",{method:"POST",headers,
      body:JSON.stringify({providerId:target.providerId,providerType:target.type,callbackURL:"/"})}));
  }
  if(url.pathname==="/studio/api/saml"&&request.method==="GET"){
    if(!await adminSession(auth,env,request))return reject(403,"Admin enrollment incomplete");
    return Response.json({enterpriseSso:env.ENTERPRISE_SSO==="true",connections:await listSamlConnections(env)},{headers:noStore});
  }
  const op=Object.hasOwn(POSTS,url.pathname)?POSTS[url.pathname]:null;
  if(op&&request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin||request.headers.get("Sec-Fetch-Site")==="cross-site")
      return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")return reject(415,"JSON required");
    const session=await adminSession(auth,env,request);
    if(!session)return reject(403,"Verified administrator with completed enrollment and recent passkey required");
    const raw=await request.text();
    if(raw.length>160_000)return reject(413,"SAML configuration too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      return Response.json(await op(auth,env,request.headers,body,session.user.id),{headers:noStore});
    }catch(e){
      return reject(409,reason(e,SAML_ADMIN_REFUSAL));
    }
  }
  return null;
}
