export const SCIM_USER="urn:ietf:params:scim:schemas:core:2.0:User";
export const SCIM_GROUP="urn:ietf:params:scim:schemas:core:2.0:Group";
export const SCIM_LIST="urn:ietf:params:scim:api:messages:2.0:ListResponse";
export const SCIM_PATCH="urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SLUG=/^[a-z][a-z0-9-]{1,62}$/;
export function validateScimConnection(input){
  if(!input || typeof input!=="object" || !SLUG.test(input.id||""))
    throw Error("SCIM connection ID must be an exact lowercase slug");
  if(typeof input.domain!=="string"||input.domain.length>253||
     !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(input.domain)||input.domain.includes(".."))
    throw Error("SCIM enterprise domain must be a lowercase DNS name");
  const org=input.organizationId;
  if(org!==undefined && (typeof org!=="string"||org.length>128||
    !/^[A-Za-z0-9_-]+$/.test(org)))throw Error("Invalid SCIM organization ID");
  return {id:input.id,domain:input.domain,organizationId:org||null};
}
export function validateScimUser(body){
  if(!body||typeof body!=="object"||Array.isArray(body)||!Array.isArray(body.schemas)||
    !body.schemas.includes(SCIM_USER))throw Error("Missing SCIM User schema");
  const userName=body.userName,externalId=body.externalId;
  if(typeof userName!=="string"||userName.length<3||userName.length>254||
     !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userName))
    throw Error("SCIM userName must be a valid email");
  if(typeof externalId!=="string"||externalId.length<3||externalId.length>256||
     /[\x00-\x1f\x7f]/.test(externalId))
    throw Error("A stable directory-owned externalId is required for safe identity matching");
  if(body.active!==undefined && typeof body.active!=="boolean")throw Error("active must be a boolean");
  if(body.displayName!==undefined&&(typeof body.displayName!=="string"||body.displayName.length>256))
    throw Error("Invalid displayName");
  const emails=Array.isArray(body.emails)?body.emails:[{value:userName,primary:true}];
  if(emails.length>10||emails.some(e=>!e||typeof e.value!=="string"||
     e.value.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.value)))
    throw Error("Invalid SCIM emails");
  const displayName=(body.displayName||body.name?.formatted||userName).slice(0,256);
  return {userName,externalId,active:body.active!==false,displayName,
    emails:emails.map(e=>({value:e.value.toLowerCase(),type:e.type==="work"?"work":"other",primary:e.primary===true}))};
}
export function validateScimGroup(body){
  if(!body||!Array.isArray(body.schemas)||!body.schemas.includes(SCIM_GROUP))throw Error("Missing SCIM Group schema");
  if(typeof body.displayName!=="string"||body.displayName.length<1||body.displayName.length>256)
    throw Error("SCIM group requires displayName");
  const members=body.members??[];
  if(!Array.isArray(members)||members.length>200||
     members.some(m=>!m||typeof m.value!=="string"||!/^[0-9a-f-]{36}$/i.test(m.value)))
    throw Error("Invalid SCIM group member IDs");
  return {displayName:body.displayName,members:[...new Set(members.map(m=>m.value))]};
}
export function parseFilter(value){
  if(value==null||value==="")return null;
  if(typeof value!=="string"||value.length>256)throw Error("SCIM filter too long");
  const match=/^(userName|externalId|displayName)\s+eq\s+"([^"\x00-\x1f]{1,254})"$/.exec(value);
  if(!match)throw Error("Unsupported SCIM filter; only attribute eq string is implemented");
  return {field:match[1],value:match[2]};
}
export function pagination(params){
  const start=Number(params.get("startIndex")||"1"),count=Number(params.get("count")||"100");
  if(!Number.isInteger(start)||start<1||start>1000000||!Number.isInteger(count)||count<1||count>200)
    throw Error("Invalid SCIM pagination");
  return {start,count};
}
