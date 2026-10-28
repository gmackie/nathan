import { DurableObject } from "cloudflare:workers";
import {DIRECTORY_SCHEMA} from "./schema.mjs";
import {SCIM_USER,SCIM_GROUP,SCIM_LIST,SCIM_PATCH,validateScimUser,validateScimGroup,parseFilter,pagination} from "./validation.mjs";

const SCIM_ERROR="urn:ietf:params:scim:api:messages:2.0:Error";
const ID=/^[0-9a-f-]{36}$/i;
const HEADERS={"Cache-Control":"no-store","Content-Type":"application/scim+json; charset=utf-8","X-Content-Type-Options":"nosniff"};
type UserRow={id:string;external_id:string;user_name:string;display_name:string;emails_json:string;
  active:number;deleted:number;revision:number;created_at:number;updated_at:number};
type GroupRow={id:string;display_name:string;deleted:number;revision:number;created_at:number;updated_at:number};
function fail(status:number,detail:string,scimType="invalidValue") {
  return Response.json({schemas:[SCIM_ERROR],status:String(status),detail,scimType},{status,headers:HEADERS});
}
const json=(obj:unknown,status=200,extra:Record<string,string>={})=>
  Response.json(obj,{status,headers:{...HEADERS,...extra}});
const version=(revision:number)=>'W/"'+revision+'"';
const instant=(value:number)=>new Date(value).toISOString();
function checkedVersion(ifMatch:string|null,revision:number){
  if(ifMatch && ifMatch!==version(revision))throw new Error("SCIM ETag no longer matches the current resource");
}
export class NathanScimDirectory extends DurableObject {
  readonly sql:SqlStorage;
  constructor(ctx:DurableObjectState,env:unknown){
    super(ctx,env);
    this.sql=ctx.storage.sql;
    this.sql.exec("PRAGMA foreign_keys=ON");
    this.sql.exec(DIRECTORY_SCHEMA);
  }
  private query<T>(sql:string,...args:any[]):T[]{
    return this.sql.exec(sql,...args).toArray() as T[];
  }
  private rateLimit(){
    const bucket=Math.floor(Date.now()/60000);
    const r=this.query<{count:number}>(
      "INSERT INTO scim_request_rates(bucket,count) VALUES(?,1) "+
      "ON CONFLICT(bucket) DO UPDATE SET count=count+1 RETURNING count",bucket)[0];
    if(bucket%20===0)this.sql.exec("DELETE FROM scim_request_rates WHERE bucket<?",bucket-3);
    return r?.count<=120;
  }
  private saveEvent(kind:string,id:string,event:string){
    this.sql.exec("INSERT INTO scim_events(id,kind,resource_id,event,created_at) VALUES(?,?,?,?,?)",
      crypto.randomUUID(),kind,id,event,Date.now());
  }
  private user(row:UserRow,base:string){
    return {schemas:[SCIM_USER],id:row.id,externalId:row.external_id,userName:row.user_name,
      displayName:row.display_name,emails:JSON.parse(row.emails_json),active:row.active===1,
      meta:{resourceType:"User",created:instant(row.created_at),lastModified:instant(row.updated_at),
        version:version(row.revision),location:base+"/Users/"+row.id}};
  }
  private group(row:GroupRow,base:string){
    const members=this.query<{user_id:string}>(
      "SELECT user_id FROM scim_group_members WHERE group_id=? ORDER BY user_id",row.id);
    return {schemas:[SCIM_GROUP],id:row.id,displayName:row.display_name,
      members:members.map(x=>({value:x.user_id,type:"User"})),
      meta:{resourceType:"Group",created:instant(row.created_at),lastModified:instant(row.updated_at),
        version:version(row.revision),location:base+"/Groups/"+row.id}};
  }
  private getUser(id:string){return this.query<UserRow>("SELECT * FROM scim_users WHERE id=? AND deleted=0",id)[0]||null}
  private getGroup(id:string){return this.query<GroupRow>("SELECT * FROM scim_groups WHERE id=? AND deleted=0",id)[0]||null}
  private membersExist(ids:string[]){
    for(const id of ids){
      if(!this.getUser(id))throw new Error("Referenced group member is not a live SCIM User");
    }
  }
  private setMembers(groupId:string,ids:string[]){
    this.membersExist(ids);
    this.sql.exec("DELETE FROM scim_group_members WHERE group_id=?",groupId);
    for(const id of ids)this.sql.exec("INSERT INTO scim_group_members(group_id,user_id) VALUES(?,?)",groupId,id);
  }
  private listUsers(url:URL,base:string){
    const filter=parseFilter(url.searchParams.get("filter"));
    const {start,count}=pagination(url.searchParams);
    const col=filter?({userName:"user_name",externalId:"external_id",displayName:"display_name"} as const)[filter.field as "userName"|"externalId"|"displayName"]:null;
    const where=col?" AND "+col+"=?":"";
    const args=filter?[filter.value]:[];
    const total=this.query<{total:number}>("SELECT COUNT(*) AS total FROM scim_users WHERE deleted=0"+where,...args)[0]?.total||0;
    const rows=this.query<UserRow>(
      "SELECT * FROM scim_users WHERE deleted=0"+where+" ORDER BY user_name LIMIT ? OFFSET ?",
      ...args,count,start-1);
    return json({schemas:[SCIM_LIST],totalResults:total,startIndex:start,itemsPerPage:rows.length,
      Resources:rows.map(r=>this.user(r,base))});
  }
  private listGroups(url:URL,base:string){
    const filter=parseFilter(url.searchParams.get("filter"));
    if(filter&&filter.field!=="displayName")return fail(400,"Unsupported Group filter attribute","invalidFilter");
    const {start,count}=pagination(url.searchParams);
    const where=filter?" AND display_name=?":"";
    const args=filter?[filter.value]:[];
    const total=this.query<{total:number}>("SELECT COUNT(*) AS total FROM scim_groups WHERE deleted=0"+where,...args)[0]?.total||0;
    const rows=this.query<GroupRow>(
      "SELECT * FROM scim_groups WHERE deleted=0"+where+" ORDER BY display_name LIMIT ? OFFSET ?",
      ...args,count,start-1);
    return json({schemas:[SCIM_LIST],totalResults:total,startIndex:start,itemsPerPage:rows.length,
      Resources:rows.map(r=>this.group(r,base))});
  }
  private createUser(body:any,base:string){
    const data=validateScimUser(body),id=crypto.randomUUID(),now=Date.now();
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,active,created_at,updated_at) "+
        "VALUES(?,?,?,?,?,?,?,?)",id,data.externalId,data.userName,data.displayName,
        JSON.stringify(data.emails),data.active?1:0,now,now);
      this.saveEvent("User",id,"create");
    });
    return json(this.user(this.getUser(id)!,base),201,{"Location":base+"/Users/"+id,ETag:version(1)});
  }
  private createGroup(body:any,base:string){
    const data=validateScimGroup(body),id=crypto.randomUUID(),now=Date.now();
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("INSERT INTO scim_groups(id,display_name,created_at,updated_at) VALUES (?,?,?,?)",id,data.displayName,now,now);
      this.setMembers(id,data.members);
      this.saveEvent("Group",id,"create");
    });
    return json(this.group(this.getGroup(id)!,base),201,{"Location":base+"/Groups/"+id,ETag:version(1)});
  }
  private replaceUser(id:string,body:any,ifMatch:string|null,base:string){
    const existing=this.getUser(id);if(!existing)return fail(404,"SCIM User not found");
    checkedVersion(ifMatch,existing.revision);
    const value=validateScimUser(body);
    if(value.externalId!==existing.external_id)
      return fail(409,"Immutable directory externalId cannot change without a reviewed migration","mutability");
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("UPDATE scim_users SET user_name=?,display_name=?,emails_json=?,active=?,revision=revision+1,updated_at=? WHERE id=? AND deleted=0",
        value.userName,value.displayName,JSON.stringify(value.emails),value.active?1:0,Date.now(),id);
      this.saveEvent("User",id,"replace");
    });
    const row=this.getUser(id)!;
    return json(this.user(row,base),200,{ETag:version(row.revision)});
  }
  private replaceGroup(id:string,body:any,ifMatch:string|null,base:string){
    const existing=this.getGroup(id);if(!existing)return fail(404,"SCIM Group not found");
    checkedVersion(ifMatch,existing.revision);
    const value=validateScimGroup(body);
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("UPDATE scim_groups SET display_name=?,revision=revision+1,updated_at=? WHERE id=? AND deleted=0",
        value.displayName,Date.now(),id);
      this.setMembers(id,value.members);
      this.saveEvent("Group",id,"replace");
    });
    const row=this.getGroup(id)!;
    return json(this.group(row,base),200,{ETag:version(row.revision)});
  }
  private patchUser(id:string,body:any,ifMatch:string|null,base:string){
    const existing=this.getUser(id);if(!existing)return fail(404,"SCIM User not found");
    checkedVersion(ifMatch,existing.revision);
    if(!body||!Array.isArray(body.schemas)||!body.schemas.includes(SCIM_PATCH)||
       !Array.isArray(body.Operations)||body.Operations.length<1||body.Operations.length>10)
      return fail(400,"Invalid SCIM PatchOp payload");
    let active=existing.active===1;
    for(const op of body.Operations){
      if(!["replace","add"].includes(String(op.op).toLowerCase())||op.path!=="active"||
         typeof op.value!=="boolean")return fail(400,"Only explicit PATCH active replacement is supported","invalidPath");
      active=op.value;
    }
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("UPDATE scim_users SET active=?,revision=revision+1,updated_at=? WHERE id=? AND deleted=0",
        active?1:0,Date.now(),id);
      this.saveEvent("User",id,"patch-active");
    });
    const row=this.getUser(id)!;
    return json(this.user(row,base),200,{ETag:version(row.revision)});
  }
  private remove(id:string,kind:"User"|"Group"){
    const table=kind==="User"?"scim_users":"scim_groups";
    const row=kind==="User"?this.getUser(id):this.getGroup(id);
    if(!row)return fail(404,kind+" not found");
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("UPDATE "+table+" SET deleted=1,revision=revision+1,updated_at=? "+
        (kind==="User"?",active=0 ":"")+"WHERE id=? AND deleted=0",Date.now(),id);
      if(kind==="User")this.sql.exec("DELETE FROM scim_group_members WHERE user_id=?",id);
      this.saveEvent(kind,id,"delete");
    });
    return new Response(null,{status:204,headers:HEADERS});
  }
  async fetch(request:Request):Promise<Response>{
    try{
      if(!this.rateLimit())return fail(429,"SCIM connection rate exceeded","tooMany");
      const url=new URL(request.url);
      if(url.hostname!=="scim.internal")return fail(421,"Unknown SCIM internal authority");
      const base=request.headers.get("X-Nathan-SCIM-Base");
      if(!base||!/^https:\/\/[a-z0-9.-]+\/scim\/v2\/[a-z][a-z0-9-]{1,62}$/.test(base))
        return fail(400,"Invalid private SCIM base URL");
      if(["/ServiceProviderConfig","/ResourceTypes","/Schemas"].includes(url.pathname)){
        if(request.method!=="GET")return fail(405,"GET required");
        if(url.pathname==="/ServiceProviderConfig")return json({
          schemas:["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
          patch:{supported:true},bulk:{supported:false,maxOperations:0,maxPayloadSize:0},
          filter:{supported:true,maxResults:200},changePassword:{supported:false},
          sort:{supported:false},etag:{supported:true},authenticationSchemes:[{type:"oauthbearertoken",name:"Bearer",description:"Connection-bound token",primary:true}]
        });
        if(url.pathname==="/ResourceTypes")return json([{schemas:["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
          id:"User",name:"User",endpoint:"/Users",schema:SCIM_USER},{schemas:["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
          id:"Group",name:"Group",endpoint:"/Groups",schema:SCIM_GROUP}]);
        return json([{id:SCIM_USER},{id:SCIM_GROUP}]);
      }
      const path=/^\/(Users|Groups)(?:\/([0-9a-f-]{36}))?\/?$/i.exec(url.pathname);
      if(!path)return fail(404,"SCIM endpoint unavailable");
      const kind=path[1].toLowerCase()==="users"?"User":"Group",id=path[2]||null;
      if(id&&!ID.test(id))return fail(404,"Invalid SCIM resource ID");
      if(request.method==="GET"){
        if(id){
          const row=kind==="User"?this.getUser(id):this.getGroup(id);
          if(!row)return fail(404,"SCIM resource not found");
          return kind==="User"
            ?json(this.user(row as UserRow,base),200,{ETag:version(row.revision)})
            :json(this.group(row as GroupRow,base),200,{ETag:version(row.revision)});
        }
        return kind==="User"?this.listUsers(url,base):this.listGroups(url,base);
      }
      if(!["POST","PUT","PATCH","DELETE"].includes(request.method))return fail(405,"Unsupported SCIM HTTP method");
      if(request.method==="DELETE" && id)return this.remove(id,kind);
      if(!["POST","PUT","PATCH"].includes(request.method))return fail(405,"SCIM method requires resource ID");
      const raw=await request.text();
      if(raw.length>131072)return fail(413,"SCIM body too large");
      if(!request.headers.get("Content-Type")?.match(/^(application\/scim\+json|application\/json)(;|$)/i))
        return fail(415,"SCIM JSON content type required");
      let body:any;
      try{body=JSON.parse(raw)}catch{return fail(400,"Invalid JSON")}
      if(request.method==="POST"&&!id)return kind==="User"?this.createUser(body,base):this.createGroup(body,base);
      if(!id)return fail(405,"Resource ID required");
      if(request.method==="PUT")return kind==="User"
        ?this.replaceUser(id,body,request.headers.get("If-Match"),base)
        :this.replaceGroup(id,body,request.headers.get("If-Match"),base);
      if(kind==="User"&&request.method==="PATCH")return this.patchUser(id,body,request.headers.get("If-Match"),base);
      return fail(400,"Group PATCH is not in this initial directory-only profile","invalidPath");
    }catch(error){
      const message=error instanceof Error?error.message:"SCIM operation rejected";
      if(/UNIQUE|constraint/i.test(message))return fail(409,"Resource conflicts with existing immutable directory identity","uniqueness");
      if(/ETag/.test(message))return fail(412,"SCIM resource version mismatch");
      if(/Invalid|Unsupported|Missing|required|too long|cannot change/i.test(message))
        return fail(400,message);
      return fail(503,"SCIM directory unavailable; no changes accepted");
    }
  }
}
