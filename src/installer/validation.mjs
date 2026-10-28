import { realmForLoginHostname,validateDomainName } from "../shared/realm.mjs";
import {validateScimConnection} from "../auth/scim/validation.mjs";
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
  const realmEnabled=input.realmEnabled===true ||
    (input.realmEnabled===undefined && hostname.startsWith("login."));
  if(input.realmEnabled!==undefined && typeof input.realmEnabled!=="boolean")
    throw Error("Invalid realmEnabled flag");
  let realmApex=null;
  if(realmEnabled){
    const derived=realmForLoginHostname(hostname);
    if(input.realmApex!==undefined && validateDomainName(input.realmApex)!==derived.apex)
      throw Error("Realm apex must match login.<domain> issuer");
    realmApex=derived.apex;
  }
  if(input.scimEnabled!==undefined && typeof input.scimEnabled!=="boolean")
    throw Error("scimEnabled must be a boolean");
  let scim=null;
  if(input.scimEnabled===true)
    scim=validateScimConnection({id:input.scimConnectionId,domain:input.scimDomain});
  return {accountId,hostname,name,securityProfile:input.securityProfile||"business",realmApex,scim};
}
export function isAllowedOrigin(origin,expected){
  if(typeof origin!=="string"||typeof expected!=="string")return false;
  try {return new URL(origin).origin===expected && new URL(origin).href.replace(/\/$/,"")===expected;}
  catch{return false;}
}
