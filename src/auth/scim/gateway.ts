import type {AuthEnv} from "../env";
import {sha256} from "../../gateway/crypto";
const DENY={"Cache-Control":"no-store","WWW-Authenticate":'Bearer realm="Nathan SCIM"'};
const ID=/^[a-z][a-z0-9-]{1,62}$/;
export async function handleScim(request:Request,env:AuthEnv):Promise<Response>{
  const url=new URL(request.url),issuer=new URL(env.NATHAN_ISSUER);
  if(url.origin!==issuer.origin)return new Response("Unknown SCIM authority",{status:421});
  const match=/^\/scim\/v2\/([^/]+)(\/.*)?$/.exec(url.pathname);
  if(!match||!ID.test(match[1]))return new Response("SCIM connection not found",{status:404});
  const connId=match[1],relative=match[2]||"/ServiceProviderConfig";
  const authorization=request.headers.get("Authorization");
  if(!authorization?.startsWith("Bearer ")){
    return new Response("SCIM connection token required",{status:401,headers:DENY});
  }
  const token=authorization.slice(7);
  if(!/^nathscim_[A-Za-z0-9_-]{40,100}$/.test(token))
    return new Response("Invalid SCIM token",{status:401,headers:DENY});
  try{
    const digest=await sha256(token);
    const row=await env.DB.prepare(
      "SELECT c.id AS id,c.enabled AS enabled FROM nathan_scim_connections c "+
      "JOIN nathan_scim_credentials t ON c.id=t.connection_id "+
      "WHERE c.id=? AND t.token_hash=? AND t.revoked_at IS NULL "+
      "AND (t.expires_at IS NULL OR t.expires_at>unixepoch()) LIMIT 1"
    ).bind(connId,digest).first<{id:string;enabled:number}>();
    if(!row||row.enabled!==1)return new Response("Invalid SCIM token or disabled connection",{status:401,headers:DENY});
    if(!env.SCIM_DIRECTORY)return new Response("SCIM directory not provisioned",{status:503,headers:{"Cache-Control":"no-store"}});
    if(Number(request.headers.get("Content-Length")||"0")>131072)
      return new Response("SCIM request too large",{status:413,headers:{"Cache-Control":"no-store"}});
    const body=["POST","PUT","PATCH"].includes(request.method)?await request.text():undefined;
    if(body!==undefined&&body.length>131072)
      return new Response("SCIM request too large",{status:413,headers:{"Cache-Control":"no-store"}});
    const h=new Headers();
    if(request.headers.has("Content-Type"))h.set("Content-Type",request.headers.get("Content-Type")!);
    if(request.headers.has("If-Match"))h.set("If-Match",request.headers.get("If-Match")!);
    h.set("X-Nathan-SCIM-Base",issuer.origin+"/scim/v2/"+connId);
    const forwarded=new Request("https://scim.internal"+relative+url.search,{
      method:request.method,headers:h,body,redirect:"error"
    });
    const stub=env.SCIM_DIRECTORY.getByName("connection:"+connId);
    const response=await stub.fetch(forwarded);
    const outgoing=new Response(response.body,response);
    outgoing.headers.set("Cache-Control","no-store");
    outgoing.headers.set("X-Content-Type-Options","nosniff");
    return outgoing;
  }catch{
    return new Response("SCIM directory unavailable",{status:503,headers:{"Cache-Control":"no-store"}});
  }
}
