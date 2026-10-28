import { randomId, pkceChallenge } from "../gateway/crypto";
import type { InstallerEnv } from "./env";

const AUTH="https://dash.cloudflare.com/oauth2/auth";
const TOKEN="https://dash.cloudflare.com/oauth2/token";

export function oauthCallback(env:InstallerEnv){
  return new URL("/api/callback",env.PUBLIC_ORIGIN).href;
}
export async function oauthAuthorizeUrl(env:InstallerEnv,state:string,verifier:string){
  const url=new URL(AUTH);
  if(!env.CF_OAUTH_CLIENT_ID||!env.CF_OAUTH_SCOPES)throw Error("Cloudflare OAuth client is not configured");
  url.search=new URLSearchParams({
    response_type:"code",
    client_id:env.CF_OAUTH_CLIENT_ID,
    redirect_uri:oauthCallback(env),
    scope:env.CF_OAUTH_SCOPES,
    state,
    code_challenge:await pkceChallenge(verifier),
    code_challenge_method:"S256"
  }).toString();
  return url.href;
}
export interface InstallerTokens { accessToken:string; refreshToken:string|null; expiresAt:number }
export async function oauthExchange(env:InstallerEnv,code:string,verifier:string):Promise<InstallerTokens>{
  if(!env.CF_OAUTH_CLIENT_SECRET||!env.CF_OAUTH_CLIENT_ID)throw Error("Cloudflare OAuth credentials missing");
  const basic=btoa(env.CF_OAUTH_CLIENT_ID+":"+env.CF_OAUTH_CLIENT_SECRET);
  const response=await fetch(TOKEN,{
    method:"POST",redirect:"error",
    headers:{"Authorization":"Basic "+basic,"Content-Type":"application/x-www-form-urlencoded"},
    body:new URLSearchParams({grant_type:"authorization_code",code,code_verifier:verifier,redirect_uri:oauthCallback(env)}),
    signal:AbortSignal.timeout(12000)
  });
  if(!response.ok)throw Error("Cloudflare OAuth code exchange failed");
  const body=await response.json() as {access_token?:string;refresh_token?:string;expires_in?:number};
  if(!body.access_token||body.access_token.length>12000)throw Error("Invalid OAuth token response");
  return {
    accessToken:body.access_token,
    refreshToken:body.refresh_token||null,
    expiresAt:Date.now()+Math.min(3600,Math.max(60,body.expires_in||3600))*1000
  };
}
export async function oauthRefresh(env:InstallerEnv,token:string):Promise<InstallerTokens>{
  const basic=btoa(env.CF_OAUTH_CLIENT_ID+":"+env.CF_OAUTH_CLIENT_SECRET);
  const response=await fetch(TOKEN,{
    method:"POST",redirect:"error",
    headers:{"Authorization":"Basic "+basic,"Content-Type":"application/x-www-form-urlencoded"},
    body:new URLSearchParams({grant_type:"refresh_token",refresh_token:token}),
    signal:AbortSignal.timeout(12000)
  });
  if(!response.ok)throw Error("Cloudflare OAuth refresh rejected: sign in again");
  const body=await response.json() as {access_token?:string;refresh_token?:string;expires_in?:number};
  if(!body.access_token)throw Error("Missing refreshed access token");
  return {accessToken:body.access_token,refreshToken:body.refresh_token||token,expiresAt:Date.now()+Math.min(3600,Math.max(60,body.expires_in||3600))*1000};
}
export { randomId };
