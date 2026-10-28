import { createLocalJWKSet, jwtVerify } from "jose";
import type { AuthEnv } from "./env";
import {mayAdminister} from "./bootstrap";
import {listScimConnections} from "./scim/admin";
import { isAdminPrincipal, listClients, listApplications, listSso, listUsers, recentAudit,
  setApplicationEnabled, setOAuthClientDisabledWithMcp, audit } from "./admin-service";
import {loadVerifiedRealm,listRealmClients} from "./domain-realm";
import { MCP_VERSION, READ_TOOLS, WRITE_TOOLS, isWriteTool,
  requiredConfirm, decodeMcpRequest, mcpResult, mcpError, textContent } from "../mcp/protocol.mjs";

const RESPONSE_HEADERS={
  "Content-Type":"application/json; charset=utf-8",
  "Cache-Control":"no-store",
  "X-Content-Type-Options":"nosniff",
  "Referrer-Policy":"no-referrer"
};
function issuer(env:AuthEnv){return new URL(env.NATHAN_ISSUER).origin+"/api/auth";}
function resource(env:AuthEnv){return new URL(env.NATHAN_ISSUER).origin+"/mcp";}
function authorizedMetadata(env:AuthEnv) {
  return {
    resource:resource(env),authorization_servers:[issuer(env)],
    scopes_supported:["nathan:read","nathan:admin"],
    bearer_methods_supported:["header"]
  };
}
export function protectedResourceMetadata(env:AuthEnv) {
  return Response.json(authorizedMetadata(env),{headers:RESPONSE_HEADERS});
}
function unauthorized(env:AuthEnv) {
  return new Response(JSON.stringify({error:"authorization_required"}),{
    status:401,headers:{...RESPONSE_HEADERS,
      "WWW-Authenticate":'Bearer resource_metadata="'+new URL(env.NATHAN_ISSUER).origin+'/.well-known/oauth-protected-resource", scope="nathan:read"'}
  });
}
function forbidden(env:AuthEnv) {
  return new Response(JSON.stringify({error:"forbidden"}),{status:403,headers:{
    ...RESPONSE_HEADERS,
    "WWW-Authenticate":'Bearer error="insufficient_scope", scope="nathan:admin", resource_metadata="'+new URL(env.NATHAN_ISSUER).origin+'/.well-known/oauth-protected-resource"'
  }});
}
async function authenticatedPrincipal(request:Request,env:AuthEnv,auth:any) {
  const header=request.headers.get("Authorization");
  if(!header?.startsWith("Bearer "))return null;
  const token=header.slice("Bearer ".length);
  if(token.length<32||token.length>16000||!/^[-._~+/=A-Za-z0-9]+$/.test(token))return null;
  const keys=await auth.api.getJwks();
  if(!keys || !Array.isArray(keys.keys))return null;
  const set=createLocalJWKSet(keys);
  const {payload}=await jwtVerify(token,set,{
    issuer:issuer(env),audience:resource(env),
    algorithms:["RS256","ES256","EdDSA"],clockTolerance:30
  });
  // DPoP-bound tokens cannot be treated as bearer tokens without validating proofs.
  if(payload.cnf)return null;
  if(typeof payload.sub!=="string" || payload.sub.length>256)return null;
  const scopes=typeof payload.scope==="string"?payload.scope.split(/\s+/):[];
  if(!scopes.includes("nathan:read")&&!scopes.includes("nathan:admin"))return null;
  const account=await env.DB.prepare('SELECT "id","email","emailVerified","role","banned" FROM "user" WHERE "id"=? LIMIT 1')
    .bind(payload.sub).first<{id:string,email:string,emailVerified:number,role:string,banned:number}>();
  if(!account || account.banned===1 || !await isAdminPrincipal({
    id:account.id,email:account.email,emailVerified:account.emailVerified===1,role:account.role
  },env) || !await mayAdminister(env,account.id,typeof payload.sid==="string"?payload.sid:undefined))return null;
  return {actor:account.id,scopes,sessionId:typeof payload.sid==="string"?payload.sid:null};
}
async function checkWritePrivilege(env:AuthEnv,principal:{actor:string;scopes:string[];sessionId:string|null}) {
  if(env.NATHAN_MCP_WRITE_ENABLED!=="true"||!principal.scopes.includes("nathan:admin"))return false;
  // Online session check: independently revoked/expired sessions must not authorize writes.
  if(!principal.sessionId)return false;
  const session=await env.DB.prepare('SELECT "id","expiresAt" FROM "session" WHERE "id"=? AND "userId"=? LIMIT 1')
    .bind(principal.sessionId,principal.actor).first<{id:string,expiresAt:number|string}>();
  if(!session)return false;
  const expiry=Number(session.expiresAt);
  return Number.isFinite(expiry) && (expiry > 1e12 ? expiry : expiry*1000)>Date.now();
}
async function limit(env:AuthEnv,actor:string){
  const bucket=Math.floor(Date.now()/60000);
  const key=actor+":"+bucket;
  const row=await env.DB.prepare(
    'INSERT INTO nathan_mcp_limits(id,request_count,expires_at) VALUES (?,1,?) '+
    'ON CONFLICT(id) DO UPDATE SET request_count=request_count+1 RETURNING request_count'
  ).bind(key,(bucket+2)*60).first<{request_count:number}>();
  return Boolean(row && row.request_count<=60);
}
async function executeTool(name:string,args:Record<string,any>,env:AuthEnv,auth:any,principal:{actor:string;scopes:string[];sessionId:string|null}) {
  if(name==="nathan_status")return {
    issuer:issuer(env),resource:resource(env),
    features:{oidc:true,mcp:"2026-07-28",enterpriseSso:env.ENTERPRISE_SSO==="true"},
    mcpWritesEnabled:env.NATHAN_MCP_WRITE_ENABLED==="true"
  };
  if(name==="nathan_clients_list")return {clients:await listClients(env)};
  if(name==="nathan_users_list")return {users:await listUsers(env)};
  if(name==="nathan_realm_status")return {realm:await loadVerifiedRealm(env)};
  if(name==="nathan_realm_clients_list")return await listRealmClients(env);
  if(name==="nathan_apps_list")return {applications:await listApplications(env)};
  if(name==="nathan_sso_list")return {providers:await listSso(env)};
  if(name==="nathan_scim_list")return {connections:await listScimConnections(env)};
  if(name==="nathan_audit_recent")return {events:await recentAudit(env)};
  if(isWriteTool(name)){
    if(!await checkWritePrivilege(env,principal))throw Error("Write tools require explicit server enablement, nathan:admin scope and a live session");
    if(args.confirm!==requiredConfirm(name,args))throw Error("Explicit confirmation string does not match requested change");
    if(name==="nathan_app_set_enabled"){
      if(typeof args.enabled!=="boolean")throw Error("Invalid enabled flag");
      return setApplicationEnabled(env,args.id,args.enabled,principal.actor);
    }
    if(name==="nathan_client_set_disabled"){
      if(typeof args.disabled!=="boolean")throw Error("Invalid disabled flag");
      return setOAuthClientDisabledWithMcp(env,args.clientId,args.disabled,principal.actor);
    }
  }
  throw Error("Tool not supported");
}
export async function handleMcp(request:Request,env:AuthEnv,auth:any) {
  if(request.method!=="POST")return new Response(null,{status:405,headers:{Allow:"POST"}});
  const expected=new URL(env.NATHAN_ISSUER).origin;
  const source=request.headers.get("Origin");
  if(source && source!==expected)return new Response("Cross-origin calls denied",{status:403});
  if(Number(request.headers.get("Content-Length")||"0")>65536)return new Response("Body too large",{status:413});
  let principal;
  try{principal=await authenticatedPrincipal(request,env,auth);}catch{return unauthorized(env);}
  if(!principal)return unauthorized(env);
  if(!await limit(env,principal.actor))return new Response("Rate limit exceeded",{status:429});
  let body:any;
  try{
    const raw=await request.text();
    if(raw.length>65536)throw Error("Body too large");
    body=decodeMcpRequest(request,JSON.parse(raw));
  }catch(e){
    return new Response(JSON.stringify(mcpError(null,-32600,"Invalid MCP request or unsupported protocol version")),
      {status:400,headers:RESPONSE_HEADERS});
  }
  const id=body.id;
  let result:any;
  if(body.method==="server/discover") {
    result={resultType:"complete",protocolVersion:MCP_VERSION,serverInfo:{name:"nathan-admin",version:"0.1.0"},
      capabilities:{tools:{listChanged:false}}};
  }else if(body.method==="tools/list"){
    result={resultType:"complete",tools:[
      ...READ_TOOLS,...(await checkWritePrivilege(env,principal)?WRITE_TOOLS:[])
    ]};
  }else if(body.method==="tools/call"){
    const name=body.params?.name;
    if(![...READ_TOOLS,...WRITE_TOOLS].some(x=>x.name===name)) {
      return Response.json(mcpError(id,-32601,"Unknown tool"),{headers:RESPONSE_HEADERS});
    }
    const args=(body.params?.arguments && typeof body.params.arguments==="object" && !Array.isArray(body.params.arguments))
      ? body.params.arguments : {};
    try{
      const out=await executeTool(name,args,env,auth,principal);
      result=textContent(out);
      if(isWriteTool(name))await audit(env,principal.actor,"mcp_write",name,"succeeded");
    }catch(e){
      if(isWriteTool(name))await audit(env,principal.actor,"mcp_write",String(name),"failed");
      result={resultType:"complete",isError:true,content:[{type:"text",text:"Tool denied or failed: "+(e instanceof Error?e.message:"Unknown error")}]};
    }
  }else {
    return Response.json(mcpError(id,-32601,"Method not supported"),{headers:RESPONSE_HEADERS});
  }
  return Response.json(mcpResult(id,result),{headers:RESPONSE_HEADERS});
}
