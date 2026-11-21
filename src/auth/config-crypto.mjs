/**
 * Envelopes for managed identity provider secrets, encrypted at rest under NATHAN_CONFIG_KEY.
 * v1 (google/github client secrets before migration 0012): AAD "nathan:provider:v1:<id>".
 * v2 (every secret field since NATH-9): AAD "nathan:provider:v2:<id>:<field>", so a
 * ciphertext cannot be moved to another provider or another field.
 * No JSON payload containing secrets is ever written to logs or audit tables.
 */
import { PROVIDER_IDS, secretFieldNames, validateProviderCredentials } from "../shared/providers.mjs";
const enc=new TextEncoder(),dec=new TextDecoder();
function base64url(bytes) {
  let raw="";for(const b of bytes)raw+=String.fromCharCode(b);
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function fromBase64Url(value){
  if(typeof value!=="string" || !/^[A-Za-z0-9_-]+$/.test(value))throw Error("Invalid secret encoding");
  const raw=atob(value.replace(/-/g,"+").replace(/_/g,"/"));
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
async function key(value){
  if(typeof value!=="string" || value.length<40)throw Error("NATHAN_CONFIG_KEY not configured");
  const bytes=fromBase64Url(value);
  if(bytes.length!==32)throw Error("NATHAN_CONFIG_KEY must contain 32 random bytes encoded base64url");
  return crypto.subtle.importKey("raw",bytes,{name:"AES-GCM"},false,["encrypt","decrypt"]);
}
export function generateConfigKey(){
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}
export async function encryptProviderSecret(provider,secret,masterKey){
  if(!["google","github"].includes(provider) || typeof secret!=="string"||
     secret.length<8 || secret.length>8192)throw Error("Invalid OAuth provider or secret");
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({
    name:"AES-GCM",iv,additionalData:enc.encode("nathan:provider:v1:"+provider)
  },await key(masterKey),enc.encode(secret));
  return "v1."+base64url(iv)+"."+base64url(new Uint8Array(cipher));
}
export async function decryptProviderSecret(provider,value,masterKey){
  if(!["google","github"].includes(provider)||typeof value!=="string")
    throw Error("Invalid encrypted provider");
  const parts=value.split(".");
  if(parts.length!==3||parts[0]!=="v1")throw Error("Unsupported provider secret format");
  const iv=fromBase64Url(parts[1]),cipher=fromBase64Url(parts[2]);
  if(iv.length!==12||cipher.length<24||cipher.length>10000)
    throw Error("Malformed encrypted provider secret");
  return dec.decode(await crypto.subtle.decrypt({
    name:"AES-GCM",iv,additionalData:enc.encode("nathan:provider:v1:"+provider)
  },await key(masterKey),cipher));
}
/** Registry-backed validation: `{id, fields:{...}}` or the flat legacy `{id, clientId, clientSecret}`. */
export function validateOAuthProviderInput(input){
  if(!input||typeof input!=="object"||Array.isArray(input)||!PROVIDER_IDS.includes(input.id))
    throw Error("Unsupported OAuth provider");
  return {id:input.id,values:validateProviderCredentials(input.id,input)};
}
function fieldAad(provider,field){
  if(!PROVIDER_IDS.includes(provider)||!secretFieldNames(provider).includes(field))
    throw Error("Invalid provider secret field");
  return enc.encode("nathan:provider:v2:"+provider+":"+field);
}
export async function encryptProviderField(provider,field,secret,masterKey){
  const additionalData=fieldAad(provider,field);
  if(typeof secret!=="string"||secret.length<1||secret.length>8192)throw Error("Invalid provider secret");
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData},await key(masterKey),enc.encode(secret));
  return "v2."+base64url(iv)+"."+base64url(new Uint8Array(cipher));
}
export async function decryptProviderField(provider,field,value,masterKey){
  const additionalData=fieldAad(provider,field);
  if(typeof value!=="string")throw Error("Invalid encrypted provider field");
  const parts=value.split(".");
  if(parts.length!==3||parts[0]!=="v2")throw Error("Unsupported provider secret format");
  const iv=fromBase64Url(parts[1]),cipher=fromBase64Url(parts[2]);
  if(iv.length!==12||cipher.length<17||cipher.length>10000)throw Error("Malformed encrypted provider secret");
  return dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv,additionalData},await key(masterKey),cipher));
}
/**
 * Seals validated credentials into the nathan_oauth_providers columns: client_id, the
 * non-secret fields as JSON, and a JSON map of secret field -> v2 ciphertext.
 */
export async function sealProviderCredentials(provider,values,masterKey){
  const secrets=secretFieldNames(provider),config={},sealed={};
  for(const [name,value] of Object.entries(values)){
    if(name==="clientId")continue;
    if(secrets.includes(name))sealed[name]=await encryptProviderField(provider,name,value,masterKey);
    else config[name]=value;
  }
  for(const name of secrets)if(!sealed[name])throw Error("Missing provider secret field");
  return {clientId:values.clientId,config:JSON.stringify(config),secretFields:JSON.stringify(sealed)};
}
