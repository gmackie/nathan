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
