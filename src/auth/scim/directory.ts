import { DurableObject } from "cloudflare:workers";
import type {AuthEnv} from "../env";
import {DIRECTORY_SCHEMA,DIRECTORY_LIFECYCLE_SCHEMA,DIRECTORY_TOMBSTONE_SCHEMA,DIRECTORY_TOMBSTONE_MIGRATION} from "./schema.mjs";
import {SCIM_USER,SCIM_GROUP,SCIM_LIST,validateScimUser,validateScimGroup,parseFilter,pagination} from "./validation.mjs";
import {applyUserPatch,applyGroupPatch,sameUser,sameGroup,ScimError} from "./patch.mjs";
import {loadPolicy,applyUser,applyGroup,markSynced,recordError,Budget,RECONCILE_LIMITS,type UserSnapshot,type GroupSnapshot,type ConnectionPolicy} from "./lifecycle";
import {deliverLogouts} from "../logout-queue";

const SCIM_ERROR="urn:ietf:params:scim:api:messages:2.0:Error";
const ID=/^[0-9a-f-]{36}$/i;
const BASE=/^https:\/\/[a-z0-9.-]+\/scim\/v2\/([a-z][a-z0-9-]{1,62})$/;
const HEADERS={"Cache-Control":"no-store","Content-Type":"application/scim+json; charset=utf-8","X-Content-Type-Options":"nosniff"};
/** Requests per minute per connection; directory full syncs (Entra, Okta) are bursty. NATHAN_SCIM_RATE_LIMIT overrides it. */
const RATE_LIMIT=600;
/** Internal administrator operations: only src/auth/scim/lifecycle-admin.ts and reviews.ts call them,
 * with X-Nathan-SCIM-Admin naming the operation; the public SCIM route never forwards /__ paths. */
const ADMIN_OPS:Record<string,string>={"/__nathan/resync":"POST","/__nathan/requeue":"POST","/__nathan/outbox":"GET","/__nathan/skip":"POST"};
type UserRow={id:string;external_id:string;user_name:string;display_name:string;emails_json:string;
  active:number;deleted:number;revision:number;created_at:number;updated_at:number};
type GroupRow={id:string;display_name:string;external_id:string|null;deleted:number;revision:number;created_at:number;updated_at:number};
type Outcome={applied:number;deprovisioned:boolean;more:boolean;removalsPending:boolean};
type Staged=ReturnType<typeof validateScimUser>;
function fail(status:number,detail:string,scimType="invalidValue",extra:Record<string,string>={}) {
  return Response.json({schemas:[SCIM_ERROR],status:String(status),detail,...(scimType?{scimType}:{})},{status,headers:{...HEADERS,...extra}});
}
const json=(obj:unknown,status=200,extra:Record<string,string>={})=>
  Response.json(obj,{status,headers:{...HEADERS,...extra}});
const version=(revision:number)=>'W/"'+revision+'"';
const instant=(value:number)=>new Date(value).toISOString();
function checkedVersion(ifMatch:string|null,revision:number){
  if(ifMatch && ifMatch!=="*" && ifMatch!==version(revision))throw new Error("SCIM ETag no longer matches the current resource");
}
/** Reconciliation could not apply a staged change to D1; the request must fail so the directory retries. */
class ReconcileError extends Error {}

/**
 * Per-connection SCIM directory (NATH-11). Users and Groups are staged here transactionally; every
 * change that alters a resource bumps its revision and appends to scim_outbox in the same
 * transaction. Reconciliation (./lifecycle.ts) applies the outbox to D1 in order, serialized per
 * connection, and removes an entry only after D1 committed it:
 * - before staging a new change, earlier pending changes must apply, or the request gets 503;
 * - after staging, the change must apply before the request reports success, or it gets 503;
 * - a failed entry stays queued and an alarm retries it even if the directory does not;
 * - each invocation spends at most RECONCILE_LIMITS.statementsPerInvocation D1 statements; the
 *   alarm continues a larger backlog (a resync, a large group) in further invocations, and requests
 *   get 503 until earlier changes are applied;
 * - an administrator can review the outbox head and skip a permanently failing entry (Studio).
 * A PATCH or PUT that changes nothing keeps the revision and queues nothing (replay-safe).
 * Deleted resources move to tombstone tables, so uniqueness covers live resources only (rehires).
 */
export class NathanScimDirectory extends DurableObject<AuthEnv> {
  readonly sql:SqlStorage;
  private chain:Promise<unknown>=Promise.resolve();
  /** The first resource a mutation staged (its own change), for deciding whether it was applied. */
  private primary:{kind:"User"|"Group";id:string}|null=null;
  constructor(ctx:DurableObjectState,env:AuthEnv){
    super(ctx,env);
    this.sql=ctx.storage.sql;
    this.sql.exec("PRAGMA foreign_keys=ON");
    this.sql.exec(DIRECTORY_SCHEMA);
    // Directories created before NATH-11 lack scim_groups.external_id.
    if(!this.query<{name:string}>("PRAGMA table_info(scim_groups)").some(c=>c.name==="external_id"))
      this.sql.exec("ALTER TABLE scim_groups ADD COLUMN external_id TEXT");
    this.sql.exec(DIRECTORY_LIFECYCLE_SCHEMA);
    this.sql.exec(DIRECTORY_TOMBSTONE_SCHEMA);
    if(!this.query<{value:string}>("SELECT value FROM scim_meta WHERE key='tombstones'").length)
      ctx.storage.transactionSync(()=>this.sql.exec(DIRECTORY_TOMBSTONE_MIGRATION));
  }
  private query<T>(sql:string,...args:any[]):T[]{
    return this.sql.exec(sql,...args).toArray() as T[];
  }
  /** Runs mutations, reconciliation and alarms one at a time (D1 awaits would otherwise interleave). */
  private exclusive<T>(fn:()=>Promise<T>):Promise<T>{
    const run=this.chain.then(fn,fn);
    this.chain=run.catch(()=>{});
    return run;
  }
  private rateLimit(){
    const bucket=Math.floor(Date.now()/60000);
    const r=this.query<{count:number}>(
      "INSERT INTO scim_request_rates(bucket,count) VALUES(?,1) "+
      "ON CONFLICT(bucket) DO UPDATE SET count=count+1 RETURNING count",bucket)[0];
    if(bucket%20===0)this.sql.exec("DELETE FROM scim_request_rates WHERE bucket<?",bucket-3);
    const configured=Number(this.env.NATHAN_SCIM_RATE_LIMIT);
    const limit=Number.isInteger(configured)&&configured>0&&configured<=100000?configured:RATE_LIMIT;
    return r?.count<=limit;
  }
  private connection():string|null{
    return this.query<{value:string}>("SELECT value FROM scim_meta WHERE key='connection'")[0]?.value??null;
  }
  /** Binds this object to its connection on first use; a different connection is refused. */
  private bind(connectionId:string){
    const known=this.connection();
    if(known===null)this.sql.exec("INSERT INTO scim_meta(key,value) VALUES('connection',?)",connectionId);
    else if(known!==connectionId)throw new ReconcileError("Directory object is bound to another connection");
  }
  private saveEvent(kind:"User"|"Group",id:string,event:string,revision:number,force=false){
    if(!this.primary)this.primary={kind,id};
    this.sql.exec("INSERT INTO scim_events(id,kind,resource_id,event,created_at) VALUES(?,?,?,?,?)",
      crypto.randomUUID(),kind,id,event,Date.now());
    this.sql.exec("INSERT INTO scim_outbox(kind,resource_id,revision,force,created_at) VALUES(?,?,?,?,?)",
      kind,id,revision,force?1:0,Date.now());
  }
  private user(row:UserRow,base:string){
    return {schemas:[SCIM_USER],id:row.id,externalId:row.external_id,userName:row.user_name,
      displayName:row.display_name,emails:JSON.parse(row.emails_json),active:row.active===1,
      meta:{resourceType:"User",created:instant(row.created_at),lastModified:instant(row.updated_at),
        version:version(row.revision),location:base+"/Users/"+row.id}};
  }
  private memberIds(groupId:string){
    return this.query<{user_id:string}>("SELECT user_id FROM scim_group_members WHERE group_id=? ORDER BY user_id",groupId).map(x=>x.user_id);
  }
  private group(row:GroupRow,base:string,withMembers=true){
    return {schemas:[SCIM_GROUP],id:row.id,...(row.external_id?{externalId:row.external_id}:{}),displayName:row.display_name,
      ...(withMembers?{members:this.memberIds(row.id).map(value=>({value,type:"User"}))}:{}),
      meta:{resourceType:"Group",created:instant(row.created_at),lastModified:instant(row.updated_at),
        version:version(row.revision),location:base+"/Groups/"+row.id}};
  }
  private getUser(id:string){return this.query<UserRow>("SELECT * FROM scim_users WHERE id=? AND deleted=0",id)[0]||null}
  private getGroup(id:string){return this.query<GroupRow>("SELECT * FROM scim_groups WHERE id=? AND deleted=0",id)[0]||null}
  private staged(row:UserRow):Staged{
    return {userName:row.user_name,externalId:row.external_id,displayName:row.display_name,
      emails:JSON.parse(row.emails_json),active:row.active===1};
  }
  private membersExist(ids:string[]){
    for(const id of ids){
      if(!this.getUser(id))throw new ScimError(400,"invalidValue","Referenced group member is not a live SCIM User");
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
    if(filter&&!col)return fail(400,"Unsupported User filter attribute","invalidFilter");
    // userName is case-insensitive (RFC 7643 §4.1.1); Entra and Okta rely on that when matching.
    const where=col?" AND "+col+"=?"+(col==="user_name"?" COLLATE NOCASE":""):"";
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
    const col=filter?({displayName:"display_name",externalId:"external_id",id:"id"} as Record<string,string>)[filter.field]:null;
    if(filter&&!col)return fail(400,"Unsupported Group filter attribute","invalidFilter");
    const {start,count}=pagination(url.searchParams);
    const where=col?" AND "+col+"=?":"";
    const args=filter?[filter.value]:[];
    const withMembers=!/(^|,)\s*members\s*(,|$)/i.test(url.searchParams.get("excludedAttributes")||"");
    const total=this.query<{total:number}>("SELECT COUNT(*) AS total FROM scim_groups WHERE deleted=0"+where,...args)[0]?.total||0;
    const rows=this.query<GroupRow>(
      "SELECT * FROM scim_groups WHERE deleted=0"+where+" ORDER BY display_name LIMIT ? OFFSET ?",
      ...args,count,start-1);
    return json({schemas:[SCIM_LIST],totalResults:total,startIndex:start,itemsPerPage:rows.length,
      Resources:rows.map(r=>this.group(r,base,withMembers))});
  }
  private createUser(body:any,base:string){
    const data=validateScimUser(body),id=crypto.randomUUID(),now=Date.now();
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("INSERT INTO scim_users(id,external_id,user_name,display_name,emails_json,active,created_at,updated_at) "+
        "VALUES(?,?,?,?,?,?,?,?)",id,data.externalId,data.userName,data.displayName,
        JSON.stringify(data.emails),data.active?1:0,now,now);
      this.saveEvent("User",id,"create",1);
    });
    return json(this.user(this.getUser(id)!,base),201,{"Location":base+"/Users/"+id,ETag:version(1)});
  }
  private createGroup(body:any,base:string){
    const data=validateScimGroup(body),id=crypto.randomUUID(),now=Date.now();
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("INSERT INTO scim_groups(id,display_name,external_id,created_at,updated_at) VALUES (?,?,?,?,?)",
        id,data.displayName,data.externalId,now,now);
      this.setMembers(id,data.members);
      this.saveEvent("Group",id,"create",1);
    });
    return json(this.group(this.getGroup(id)!,base),201,{"Location":base+"/Groups/"+id,ETag:version(1)});
  }
  /** Writes a User's next state if it differs from the current one (one transaction). */
  private writeUser(existing:UserRow,next:Staged,event:string,base:string){
    if(next.externalId!==existing.external_id)
      throw new ScimError(409,"mutability","Immutable directory externalId cannot change without a reviewed migration");
    if(!sameUser(next,this.staged(existing))){
      this.ctx.storage.transactionSync(()=>{
        this.sql.exec("UPDATE scim_users SET user_name=?,display_name=?,emails_json=?,active=?,revision=revision+1,updated_at=? WHERE id=? AND deleted=0",
          next.userName,next.displayName,JSON.stringify(next.emails),next.active?1:0,Date.now(),existing.id);
        this.saveEvent("User",existing.id,event,existing.revision+1);
      });
    }
    const row=this.getUser(existing.id)!;
    return json(this.user(row,base),200,{ETag:version(row.revision)});
  }
  private writeGroup(existing:GroupRow,next:{displayName:string;externalId:string|null;members:string[]},event:string,base:string){
    const current={displayName:existing.display_name,externalId:existing.external_id,members:this.memberIds(existing.id)};
    if(current.externalId!==null&&next.externalId!==current.externalId)
      throw new ScimError(409,"mutability","A group's externalId cannot change once set; group mappings depend on it");
    if(!sameGroup(next,current)){
      this.ctx.storage.transactionSync(()=>{
        this.sql.exec("UPDATE scim_groups SET display_name=?,external_id=?,revision=revision+1,updated_at=? WHERE id=? AND deleted=0",
          next.displayName,next.externalId,Date.now(),existing.id);
        this.setMembers(existing.id,next.members);
        this.saveEvent("Group",existing.id,event,existing.revision+1);
      });
    }
    const row=this.getGroup(existing.id)!;
    return json(this.group(row,base),200,{ETag:version(row.revision)});
  }
  private replaceUser(id:string,body:any,ifMatch:string|null,base:string){
    const existing=this.getUser(id);if(!existing)return fail(404,"SCIM User not found");
    checkedVersion(ifMatch,existing.revision);
    // Okta's PUT is a full replace; a PUT that omits externalId keeps the stored one.
    const value=validateScimUser(body&&typeof body==="object"&&body.externalId===undefined?{...body,externalId:existing.external_id}:body);
    return this.writeUser(existing,value,"replace",base);
  }
  private replaceGroup(id:string,body:any,ifMatch:string|null,base:string){
    const existing=this.getGroup(id);if(!existing)return fail(404,"SCIM Group not found");
    checkedVersion(ifMatch,existing.revision);
    const value=validateScimGroup(body);
    return this.writeGroup(existing,{...value,externalId:value.externalId??existing.external_id},"replace",base);
  }
  private patchUser(id:string,body:any,ifMatch:string|null,base:string){
    const existing=this.getUser(id);if(!existing)return fail(404,"SCIM User not found");
    checkedVersion(ifMatch,existing.revision);
    return this.writeUser(existing,applyUserPatch(this.staged(existing),body),"patch",base);
  }
  private patchGroup(id:string,body:any,ifMatch:string|null,base:string){
    const existing=this.getGroup(id);if(!existing)return fail(404,"SCIM Group not found");
    checkedVersion(ifMatch,existing.revision);
    const next=applyGroupPatch({displayName:existing.display_name,externalId:existing.external_id,members:this.memberIds(id)},body);
    return this.writeGroup(existing,next,"patch",base);
  }
  /** DELETE: the resource moves to its tombstone table, releasing its unique names for a rehire. */
  private remove(id:string,kind:"User"|"Group"){
    const row=kind==="User"?this.getUser(id):this.getGroup(id);
    if(!row)return fail(404,kind+" not found");
    this.ctx.storage.transactionSync(()=>{
      const groups=kind==="User"?this.query<{group_id:string}>("SELECT group_id FROM scim_group_members WHERE user_id=?",id):[];
      if(kind==="User"){
        this.sql.exec("DELETE FROM scim_group_members WHERE user_id=?",id);
        this.sql.exec("INSERT INTO scim_user_tombstones(id,external_id,user_name,display_name,emails_json,revision,created_at,updated_at) "+
          "SELECT id,external_id,user_name,display_name,emails_json,revision+1,created_at,? FROM scim_users WHERE id=?",Date.now(),id);
        this.sql.exec("DELETE FROM scim_users WHERE id=?",id);
      }else{
        this.sql.exec("DELETE FROM scim_group_members WHERE group_id=?",id);
        this.sql.exec("INSERT INTO scim_group_tombstones(id,display_name,external_id,revision,created_at,updated_at) "+
          "SELECT id,display_name,external_id,revision+1,created_at,? FROM scim_groups WHERE id=?",Date.now(),id);
        this.sql.exec("DELETE FROM scim_groups WHERE id=?",id);
      }
      this.saveEvent(kind,id,"delete",row.revision+1);
      // Keep the applied member counts of the user's former groups current.
      for(const g of groups){
        const group=this.query<{revision:number}>("SELECT revision FROM scim_groups WHERE id=?",g.group_id)[0];
        this.sql.exec("UPDATE scim_groups SET revision=revision+1 WHERE id=?",g.group_id);
        this.saveEvent("Group",g.group_id,"member-deleted",group.revision+1);
      }
    });
    return new Response(null,{status:204,headers:HEADERS});
  }

  // ---- reconciliation ------------------------------------------------------------------------

  private userSnapshot(id:string):UserSnapshot|null{
    const row=this.query<UserRow>("SELECT * FROM scim_users WHERE id=?",id)[0]
      ??this.query<UserRow>("SELECT *,0 AS active,1 AS deleted FROM scim_user_tombstones WHERE id=?",id)[0];
    if(!row)return null;
    const groups=this.query<{id:string;external_id:string|null}>(
      "SELECT g.id AS id,g.external_id AS external_id FROM scim_group_members m JOIN scim_groups g ON g.id=m.group_id WHERE m.user_id=? AND g.deleted=0",id);
    return {id:row.id,externalId:row.external_id,userName:row.user_name,displayName:row.display_name,
      emails:JSON.parse(row.emails_json),active:row.active===1,deleted:row.deleted===1,revision:row.revision,
      groups:groups.map(g=>({id:g.id,externalId:g.external_id}))};
  }
  private groupSnapshot(id:string):GroupSnapshot|null{
    const row=this.query<GroupRow>("SELECT * FROM scim_groups WHERE id=?",id)[0]
      ??this.query<GroupRow>("SELECT *,1 AS deleted FROM scim_group_tombstones WHERE id=?",id)[0];
    if(!row)return null;
    return {id:row.id,externalId:row.external_id,displayName:row.display_name,deleted:row.deleted===1,
      revision:row.revision,members:row.deleted===1?[]:this.memberIds(id)};
  }
  private async scheduleRetry(attempts:number){
    const delay=Math.min(600_000,1_000*2**Math.min(attempts,10));
    const current=await this.ctx.storage.getAlarm();
    if(current===null||current>Date.now()+delay)await this.ctx.storage.setAlarm(Date.now()+delay);
  }
  /** Continues a backlog in a fresh invocation (alarms get their own D1 query budget). */
  private async continueSoon(){
    const at=Date.now()+50,current=await this.ctx.storage.getAlarm();
    if(current===null||current>at)await this.ctx.storage.setAlarm(at);
  }
  /**
   * Applies pending outbox entries to D1 in order, within one invocation's budget. Throws
   * ReconcileError on the first failure. `more`: the budget ran out first (an alarm continues);
   * `removalsPending`: a partly applied group still has membership removals to apply.
   */
  private async reconcile(budget=new Budget()):Promise<Outcome>{
    const outcome:Outcome={applied:0,deprovisioned:false,more:false,removalsPending:false};
    const connectionId=this.connection();
    const env=budget.wrap(this.env);
    let policy:ConnectionPolicy|null|undefined;
    work:for(;;){
      const pending=this.query<{kind:"User"|"Group";resource_id:string;seq:number;force:number;attempts:number}>(
        "SELECT kind,resource_id,MAX(seq) AS seq,MAX(force) AS force,MAX(attempts) AS attempts FROM scim_outbox "+
        "GROUP BY kind,resource_id ORDER BY MIN(seq) LIMIT 50");
      if(!pending.length)break;
      if(!connectionId)throw new ReconcileError("Directory object is not bound to a connection");
      if(policy===undefined){
        try{policy=await loadPolicy(env,connectionId)}
        catch{await this.scheduleRetry(pending[0].attempts);throw new ReconcileError("Connection policy unavailable")}
      }
      if(!policy)throw new ReconcileError("SCIM connection no longer exists");
      for(const item of pending){
        if(budget.remaining<RECONCILE_LIMITS.userReserve){outcome.more=true;break work}
        try{
          const options={force:item.force===1,budget};
          const result=item.kind==="User"
            ?await (async()=>{const s=this.userSnapshot(item.resource_id);return s?applyUser(env,policy,s,options):null})()
            :await (async()=>{const s=this.groupSnapshot(item.resource_id);return s?applyGroup(env,policy,s,options):null})();
          if(result?.partial){
            // Keep the entry; the next invocation recomputes the remaining work from D1.
            outcome.more=true;outcome.removalsPending=Boolean(result.removalsPending);
            break work;
          }
          if(result?.deprovisioned)outcome.deprovisioned=true;
          this.sql.exec("DELETE FROM scim_outbox WHERE kind=? AND resource_id=? AND seq<=?",item.kind,item.resource_id,item.seq);
          outcome.applied++;
        }catch(error){
          const message=error instanceof Error?error.message:"Reconciliation failed";
          this.sql.exec("UPDATE scim_outbox SET attempts=attempts+1,last_error=? WHERE kind=? AND resource_id=?",
            message.slice(0,300),item.kind,item.resource_id);
          await recordError(this.env,connectionId,item.kind,item.resource_id,
            (item.kind==="User"?"Could not apply directory user to Nathan (nothing reported success): ":"Could not apply directory group: ")+message).catch(()=>{});
          await this.scheduleRetry(item.attempts+1);
          throw new ReconcileError("Directory change could not be applied");
        }
      }
    }
    if(outcome.more)await this.continueSoon();
    if(outcome.applied&&connectionId)await markSynced(this.env,connectionId).catch(()=>{});
    return outcome;
  }
  /** Sends this connection's due back-channel logouts; schedules an alarm for the remaining ones. */
  private async deliver(){
    const connectionId=this.connection();
    if(!connectionId)return;
    try{
      const {nextDue}=await deliverLogouts(this.env,{connectionId});
      if(nextDue!==null){
        const at=Math.max(Date.now()+1000,nextDue*1000),current=await this.ctx.storage.getAlarm();
        if(current===null||current>at)await this.ctx.storage.setAlarm(at);
      }
    }catch{await this.scheduleRetry(1)}
  }
  async alarm(){
    await this.exclusive(async()=>{
      try{await this.reconcile()}catch{return}
      await this.deliver();
    });
  }
  private pendingCount(){
    return this.query<{n:number}>("SELECT COUNT(DISTINCT kind||':'||resource_id) AS n FROM scim_outbox")[0]?.n??0;
  }
  /** Administrator-requested full re-application (after linking or mapping changes). A large
   * directory is applied over several invocations; `pending` says how many resources remain. */
  private async resync(){
    this.ctx.storage.transactionSync(()=>{
      const now=Date.now();
      for(const [kind,table] of [["User","scim_users"],["User","scim_user_tombstones"],["Group","scim_groups"],["Group","scim_group_tombstones"]])
        this.sql.exec("INSERT INTO scim_outbox(kind,resource_id,revision,force,created_at) SELECT ?,id,revision,1,? FROM "+table,kind,now);
    });
    try{
      const result=await this.reconcile();
      if(result.deprovisioned)await this.deliver();
      return json({applied:result.applied,pending:this.pendingCount()});
    }catch{
      return json({applied:false,pending:this.pendingCount()},503,{"Retry-After":"10"});
    }
  }
  /** Re-applies one resource now (after an administrator approved a review for it). */
  private async requeue(body:any){
    const kind=body?.kind==="Group"?"Group":body?.kind==="User"?"User":null,id=String(body?.id??"");
    if(!kind||!ID.test(id))return fail(400,"Invalid requeue target");
    const snapshot=kind==="User"?this.userSnapshot(id):this.groupSnapshot(id);
    if(!snapshot)return fail(404,"SCIM resource not found");
    this.sql.exec("INSERT INTO scim_outbox(kind,resource_id,revision,force,created_at) VALUES(?,?,?,1,?)",kind,id,snapshot.revision,Date.now());
    try{
      const result=await this.reconcile();
      if(result.deprovisioned)await this.deliver();
      const own=this.query<{n:number}>("SELECT COUNT(*) AS n FROM scim_outbox WHERE kind=? AND resource_id=?",kind,id)[0]?.n??0;
      return json({applied:own===0,pending:this.pendingCount()});
    }catch{
      return json({applied:false,pending:this.pendingCount()},503,{"Retry-After":"10"});
    }
  }
  /** What a resource in the outbox is, for an administrator deciding whether to skip it. */
  private summary(kind:"User"|"Group",id:string){
    if(kind==="User"){
      const s=this.userSnapshot(id);
      return s?{userName:s.userName,externalId:s.externalId,active:s.active,deleted:s.deleted,revision:s.revision}:null;
    }
    const g=this.groupSnapshot(id);
    return g?{displayName:g.displayName,externalId:g.externalId,deleted:g.deleted,members:g.members.length,revision:g.revision}:null;
  }
  private outboxHead(limit=10){
    return this.query<{kind:"User"|"Group";resource_id:string;seq:number;attempts:number;last_error:string|null;created_at:number;entries:number}>(
      "SELECT kind,resource_id,MAX(seq) AS seq,MAX(attempts) AS attempts,MAX(last_error) AS last_error,MIN(created_at) AS created_at,COUNT(*) AS entries "+
      "FROM scim_outbox GROUP BY kind,resource_id ORDER BY MIN(seq) LIMIT ?",limit)
      .map(r=>({kind:r.kind,resourceId:r.resource_id,seq:r.seq,attempts:r.attempts,lastError:r.last_error,
        queuedAt:instant(r.created_at),entries:r.entries,resource:this.summary(r.kind,r.resource_id)}));
  }
  /**
   * Drops the head entry after an administrator reviewed it. Only the current head, at the exact
   * sequence the administrator saw, and only after it failed at least once: a healthy queue is never
   * skipped. Nathan's state for that resource stays as it was until the resource changes again or a
   * resync applies it.
   */
  private skip(body:any){
    const head=this.outboxHead(1)[0];
    if(!head||head.kind!==body?.kind||head.resourceId!==body?.id||head.seq!==body?.seq)
      return fail(409,"Only the reviewed head of the outbox can be skipped; reload it","");
    if(head.attempts<1)return fail(409,"The head entry has not failed; nothing to skip","");
    this.ctx.storage.transactionSync(()=>{
      this.sql.exec("DELETE FROM scim_outbox WHERE kind=? AND resource_id=? AND seq<=?",head.kind,head.resourceId,head.seq);
      this.sql.exec("INSERT INTO scim_events(id,kind,resource_id,event,created_at) VALUES(?,?,?,?,?)",
        crypto.randomUUID(),head.kind,head.resourceId,"skipped",Date.now());
    });
    return json({skipped:head,pending:this.pendingCount()});
  }
  private async mutate(request:Request,kind:"User"|"Group",id:string|null,base:string):Promise<Response>{
    const budget=new Budget();
    // Earlier staged changes must reach D1 before anything new is accepted.
    if((await this.reconcile(budget)).more)throw new ReconcileError("Earlier directory changes are still being applied");
    this.primary=null;
    let response:Response;
    if(request.method==="DELETE"){
      if(!id)return fail(405,"SCIM method requires resource ID");
      response=this.remove(id,kind);
    }else{
      const raw=await request.text();
      if(raw.length>131072)return fail(413,"SCIM body too large");
      if(!request.headers.get("Content-Type")?.match(/^(application\/scim\+json|application\/json)(;|$)/i))
        return fail(415,"SCIM JSON content type required");
      let body:any;
      try{body=JSON.parse(raw)}catch{return fail(400,"Invalid JSON")}
      if(request.method==="POST"&&!id)response=kind==="User"?this.createUser(body,base):this.createGroup(body,base);
      else if(!id)return fail(405,"Resource ID required");
      else if(request.method==="PUT")response=kind==="User"
        ?this.replaceUser(id,body,request.headers.get("If-Match"),base)
        :this.replaceGroup(id,body,request.headers.get("If-Match"),base);
      else if(request.method==="PATCH")response=kind==="User"
        ?this.patchUser(id,body,request.headers.get("If-Match"),base)
        :this.patchGroup(id,body,request.headers.get("If-Match"),base);
      else return fail(405,"Unsupported SCIM HTTP method");
    }
    // Success is reported only after D1 committed the change (fail closed for deprovisioning). A
    // group whose remaining work is only additions may finish in the background (alarm).
    const result=await this.reconcile(budget);
    if(result.deprovisioned)await this.deliver();
    // saveEvent() set this during staging (TypeScript cannot see that through the method call).
    const primary=this.primary as {kind:"User"|"Group";id:string}|null;
    const own=primary&&this.query<{n:number}>("SELECT COUNT(*) AS n FROM scim_outbox WHERE kind=? AND resource_id=?",primary.kind,primary.id)[0]?.n;
    if(result.more&&((own&&primary?.kind==="User")||result.removalsPending))
      throw new ReconcileError("Directory change not yet applied");
    return response;
  }
  async fetch(request:Request):Promise<Response>{
    try{
      if(!this.rateLimit())return fail(429,"SCIM connection rate exceeded","tooMany");
      const url=new URL(request.url);
      if(url.hostname!=="scim.internal")return fail(421,"Unknown SCIM internal authority");
      const base=request.headers.get("X-Nathan-SCIM-Base");
      const bound=base?BASE.exec(base):null;
      if(!base||!bound)return fail(400,"Invalid private SCIM base URL");
      this.bind(bound[1]);
      if(url.pathname.startsWith("/__nathan/")){
        const op=url.pathname.slice("/__nathan/".length);
        if(ADMIN_OPS[url.pathname]!==request.method||request.headers.get("X-Nathan-SCIM-Admin")!==op)return fail(404,"SCIM endpoint unavailable");
        if(op==="outbox")return json({pending:this.pendingCount(),head:this.outboxHead()});
        if(op==="resync")return await this.exclusive(()=>this.resync());
        let body:any;try{body=JSON.parse(await request.text())}catch{return fail(400,"Invalid JSON")}
        if(op==="requeue")return await this.exclusive(()=>this.requeue(body));
        return await this.exclusive(async()=>{const r=this.skip(body);if(r.ok)await this.continueSoon();return r});
      }
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
      const kind=path[1].toLowerCase()==="users"?"User":"Group",id=path[2]?.toLowerCase()||null;
      if(id&&!ID.test(id))return fail(404,"Invalid SCIM resource ID");
      if(request.method==="GET"){
        if(id){
          const row=kind==="User"?this.getUser(id):this.getGroup(id);
          if(!row)return fail(404,"SCIM resource not found");
          const withMembers=!/(^|,)\s*members\s*(,|$)/i.test(url.searchParams.get("excludedAttributes")||"");
          return kind==="User"
            ?json(this.user(row as UserRow,base),200,{ETag:version(row.revision)})
            :json(this.group(row as GroupRow,base,withMembers),200,{ETag:version(row.revision)});
        }
        return kind==="User"?this.listUsers(url,base):this.listGroups(url,base);
      }
      if(!["POST","PUT","PATCH","DELETE"].includes(request.method))return fail(405,"Unsupported SCIM HTTP method");
      return await this.exclusive(()=>this.mutate(request,kind,id,base).catch(error=>this.failure(error)));
    }catch(error){
      return this.failure(error);
    }
  }
  private failure(error:unknown):Response{
    if(error instanceof ReconcileError)
      return fail(503,"Directory change not yet applied to Nathan; retry","",{"Retry-After":"10"});
    if(error instanceof ScimError)return fail(error.status,error.message,error.scimType);
    const message=error instanceof Error?error.message:"SCIM operation rejected";
    if(/UNIQUE|constraint/i.test(message))return fail(409,"Resource conflicts with existing immutable directory identity","uniqueness");
    if(/ETag/.test(message))return fail(412,"SCIM resource version mismatch");
    if(/Invalid|Unsupported|Missing|required|too long|cannot change|must be/i.test(message))
      return fail(400,message);
    return fail(503,"SCIM directory unavailable; no changes accepted");
  }
}
