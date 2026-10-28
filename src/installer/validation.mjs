const SLUG=/^[a-z][a-z0-9-]{0,62}$/;
const ACCOUNT=/^[a-f0-9]{32}$/;
export function validateAccountId(input){
  if(typeof input!=="string"||!ACCOUNT.test(input))throw Error("Invalid Cloudflare account ID");
  return input;
}
export function validateHostname(input){
  if(typeof input!=="string"||input.length>253||input!==input.toLowerCase())throw Error("Invalid hostname");
  const labels=input.split(".");
  if(labels.length<2||labels.some(x=>x.length<1||x.length>63||!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x)))throw Error("Invalid hostname");
  return input;
}
export function validateWorkerName(input){
  if(typeof input!=="string"||!SLUG.test(input))throw Error("Invalid Worker name");
  return input;
}
export function validateInstallPlan(input){
  if(!input||typeof input!=="object"||Array.isArray(input))throw Error("Invalid plan");
  const accountId=validateAccountId(input.accountId);
  const hostname=validateHostname(input.hostname);
  const name=validateWorkerName(input.name);
  if(input.securityProfile && !["standard","business","high"].includes(input.securityProfile))
    throw Error("Invalid security profile");
  return {accountId,hostname,name,securityProfile:input.securityProfile||"business"};
}
export function isAllowedOrigin(origin,expected){
  if(typeof origin!=="string"||typeof expected!=="string")return false;
  try {return new URL(origin).origin===expected && new URL(origin).href.replace(/\/$/,"")===expected;}
  catch{return false;}
}
