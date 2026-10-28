import type {AuthEnv} from "./env";
import {audit} from "./admin-service";

export type EffectiveAdminPolicy={
  profile:string;requireBothAuthenticators:boolean;requireRecentPasskey:boolean;
  source:{deployment:string;runtimeTightened:boolean};
};
export async function effectiveAdminPolicy(env:AuthEnv):Promise<EffectiveAdminPolicy>{
  const row=await env.DB.prepare(
    "SELECT require_both_admin_authenticators AS both,require_recent_admin_passkey AS recent "+
    "FROM nathan_security_overrides WHERE id='primary' LIMIT 1"
  ).first<{both:number;recent:number}>();
  return {
    profile:env.NATHAN_SECURITY_PROFILE||"business",
    requireBothAuthenticators:env.NATHAN_SECURITY_PROFILE!=="standard"||row?.both===1,
    requireRecentPasskey:env.NATHAN_ADMIN_STEPUP_REQUIRED==="true"||row?.recent===1,
    source:{deployment:env.NATHAN_SECURITY_PROFILE||"business",runtimeTightened:row?.both===1||row?.recent===1}
  };
}
/** Only raises the effective requirement. Reducing it demands reviewed
 * Cloudflare-controlled configuration, not a web toggle. */
export async function tightenAdminPolicy(env:AuthEnv,input:any,actor:string,sessionId:string){
  const name=input?.setting;
  if(!["both-authenticators","recent-passkey"].includes(name))
    throw Error("Unknown security policy setting");
  if(input.confirm!=="CONFIRM REQUIRE "+name)
    throw Error("Exact security policy confirmation required");
  if(!sessionId)throw Error("Authenticated session required");
  const [passkey,totp,recent]=await Promise.all([
    env.DB.prepare('SELECT COUNT(*) AS n FROM "passkey" WHERE "userId"=?').bind(actor).first<{n:number}>(),
    env.DB.prepare('SELECT COUNT(*) AS n FROM "twoFactor" WHERE "userId"=? AND "verified"=1')
      .bind(actor).first<{n:number}>(),
    env.DB.prepare(
      "SELECT session_id FROM nathan_admin_assurance WHERE user_id=? AND session_id=? "+
      "AND verified_at>=unixepoch()-900 LIMIT 1"
    ).bind(actor,sessionId).first()
  ]);
  if(name==="both-authenticators" && (!passkey?.n||!totp?.n))
    throw Error("Enroll both passkey and verified TOTP before tightening the policy");
  if(name==="recent-passkey" && (!passkey?.n||!recent))
    throw Error("Perform a recent passkey sign-in before enabling privileged-action step-up");
  const both=name==="both-authenticators"?1:0;
  const stepup=name==="recent-passkey"?1:0;
  await env.DB.prepare(
    "INSERT INTO nathan_security_overrides(id,require_both_admin_authenticators,require_recent_admin_passkey,modified_by) "+
    "VALUES('primary',?,?,?) ON CONFLICT(id) DO UPDATE SET "+
    "require_both_admin_authenticators=MAX(require_both_admin_authenticators,excluded.require_both_admin_authenticators),"+
    "require_recent_admin_passkey=MAX(require_recent_admin_passkey,excluded.require_recent_admin_passkey),"+
    "modified_by=excluded.modified_by,updated_at=unixepoch()"
  ).bind(both,stepup,actor).run();
  await audit(env,actor,"security_policy_tighten",name,"succeeded");
  return {policy:await effectiveAdminPolicy(env),note:"Security requirement increased. Web UI cannot weaken its deployment baseline."};
}
