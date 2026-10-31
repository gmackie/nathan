/**
 * v1 envelope for managed identity provider secrets.
 * Encrypts at rest under NATHAN_CONFIG_KEY, with provider-specific AES-GCM AAD.
 * No JSON payload containing secrets is ever written to logs or audit tables.
 */
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
export function validateOAuthProviderInput(input){
  if(!input||typeof input!=="object"||Array.isArray(input)||
     !["google","github"].includes(input.id))throw Error("Unsupported OAuth provider");
  if(typeof input.clientId!=="string"||input.clientId.trim().length<5||input.clientId.length>512)
    throw Error("OAuth client ID is missing or invalid");
  if(typeof input.clientSecret!=="string"||input.clientSecret.length<8||input.clientSecret.length>8192)
    throw Error("OAuth client secret is missing or invalid");
  return {id:input.id,clientId:input.clientId.trim(),clientSecret:input.clientSecret};
}
