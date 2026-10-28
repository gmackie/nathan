import type { InstallerTokens } from "./oauth";
import type { InstallerEnv } from "./env";
import { oauthRefresh } from "./oauth";
import { updateInstallerTokens } from "./storage";

export async function cloudflareRequest<T>(
  env:InstallerEnv,
  digest:string,
  tokens:InstallerTokens,
  path:string
):Promise<T>{
  if(!path.startsWith("/")||path.startsWith("//")||path.includes(".."))throw Error("Invalid Cloudflare API path");
  const now=Date.now();
  let current=tokens;
  if(current.expiresAt<now+30000){
    if(!current.refreshToken)throw Error("Cloudflare session expired; sign in again");
    current=await oauthRefresh(env,current.refreshToken);
    await updateInstallerTokens(env,digest,current);
  }
  const response=await fetch("https://api.cloudflare.com/client/v4"+path,{
    headers:{"Authorization":"Bearer "+current.accessToken,"Accept":"application/json"},
    redirect:"error",signal:AbortSignal.timeout(12000)
  });
  const data=await response.json() as {success?:boolean;result?:T;errors?:Array<{message:string}>};
  if(!response.ok||data.success!==true||data.result===undefined)
    throw Error("Cloudflare returned "+response.status+" for this operation");
  return data.result;
}

/** Cloudflare API mutation with the same encrypted OAuth session and refresh behavior. */
export async function cloudflareWrite<T>(
  env:InstallerEnv,digest:string,tokens:InstallerTokens,path:string,
  method:"POST"|"PUT"|"DELETE",body:unknown
):Promise<T>{
  if(!path.startsWith("/")||path.startsWith("//")||path.includes(".."))throw Error("Invalid Cloudflare API path");
  let current=tokens;
  if(current.expiresAt<Date.now()+30000){
    if(!current.refreshToken)throw Error("Cloudflare session expired; sign in again");
    current=await oauthRefresh(env,current.refreshToken);
    await updateInstallerTokens(env,digest,current);
  }
  const response=await fetch("https://api.cloudflare.com/client/v4"+path,{
    method,headers:{
      "Authorization":"Bearer "+current.accessToken,
      ...(body instanceof FormData?{}:{"Content-Type":"application/json"})
    },
    body:body instanceof FormData?body:JSON.stringify(body),
    redirect:"error",signal:AbortSignal.timeout(60000)
  });
  const json=await response.json().catch(()=>null) as {success?:boolean;result?:T;errors?:Array<{message:string}>}|null;
  if(!response.ok||!json?.success){
    throw Error("Cloudflare operation failed ("+response.status+"): "+
      (json?.errors?.map(e=>e.message).join("; ")||"Unknown error"));
  }
  return json.result as T;
}
