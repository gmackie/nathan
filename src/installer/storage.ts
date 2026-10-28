import { randomId, sha256, seal, unseal } from "../gateway/crypto";
import type { InstallerEnv } from "./env";
import type { InstallerTokens } from "./oauth";
const SESSION_AGE_SECONDS=30*60;
export async function beginOAuthState(env:InstallerEnv,verifier:string){
  const state=randomId();
  const stateHash=await sha256(state);
  const encrypted=await seal(verifier,env.INSTALLER_ENCRYPTION_KEY);
  await env.INSTALLER_DB.prepare("INSERT INTO nathan_installer_state(state_hash,verifier_cipher,expires_at) VALUES (?,?,?)")
    .bind(stateHash,encrypted,Math.floor(Date.now()/1000)+300).run();
  return state;
}
export async function consumeOAuthState(env:InstallerEnv,state:string):Promise<string|null>{
  if(!/^[A-Za-z0-9_-]{32,128}$/.test(state))return null;
  const digest=await sha256(state);
  const row=await env.INSTALLER_DB.prepare(
    "UPDATE nathan_installer_state SET consumed_at=unixepoch() WHERE state_hash=? AND consumed_at IS NULL AND expires_at>unixepoch() RETURNING verifier_cipher"
  ).bind(digest).first<{verifier_cipher:string}>();
  return row?unseal<string>(row.verifier_cipher,env.INSTALLER_ENCRYPTION_KEY):null;
}
export async function createInstallerSession(env:InstallerEnv,tokens:InstallerTokens){
  const handle=randomId();
  const digest=await sha256(handle);
  const encrypted=await seal(tokens,env.INSTALLER_ENCRYPTION_KEY);
  await env.INSTALLER_DB.prepare(
    "INSERT INTO nathan_installer_sessions(session_hash,token_cipher,expires_at) VALUES (?,?,?)"
  ).bind(digest,encrypted,Math.floor(Date.now()/1000)+SESSION_AGE_SECONDS).run();
  return handle;
}
export async function installerSession(env:InstallerEnv,handle:string|null){
  if(!handle||!/^[A-Za-z0-9_-]{32,128}$/.test(handle))return null;
  const digest=await sha256(handle);
  const row=await env.INSTALLER_DB.prepare(
    "SELECT token_cipher,expires_at FROM nathan_installer_sessions WHERE session_hash=? AND expires_at>unixepoch()"
  ).bind(digest).first<{token_cipher:string;expires_at:number}>();
  if(!row)return null;
  const tokens=await unseal<InstallerTokens>(row.token_cipher,env.INSTALLER_ENCRYPTION_KEY);
  if(!tokens)return null;
  return {digest,tokens,expiresAt:row.expires_at};
}
export async function updateInstallerTokens(env:InstallerEnv,digest:string,tokens:InstallerTokens){
  await env.INSTALLER_DB.prepare("UPDATE nathan_installer_sessions SET token_cipher=? WHERE session_hash=?")
    .bind(await seal(tokens,env.INSTALLER_ENCRYPTION_KEY),digest).run();
}
export async function deleteInstallerSession(env:InstallerEnv,handle:string){
  await env.INSTALLER_DB.prepare("DELETE FROM nathan_installer_sessions WHERE session_hash=?")
    .bind(await sha256(handle)).run();
}
export async function pruneInstallerState(env:InstallerEnv){
  await env.INSTALLER_DB.batch([
    env.INSTALLER_DB.prepare("DELETE FROM nathan_installer_state WHERE expires_at<=unixepoch()"),
    env.INSTALLER_DB.prepare("DELETE FROM nathan_installer_sessions WHERE expires_at<=unixepoch()")
  ]);
}
