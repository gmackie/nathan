import type { AuthEnv } from "./env";
import { audit } from "./admin-service";
import {effectiveAdminPolicy} from "./security-policy";

type BootstrapRow={
  cloudflare_user_id:string;admin_email:string;admin_user_id:string|null;
  state:"pending"|"identity_verified"|"authenticators_enrolled"|"complete";
  completed_at:number|null;
};
export type AdminEnrollment={
  configured:boolean;state:string;isInitialAdmin:boolean;
  passkeys:number;totpVerified:boolean;ready:boolean;
  requirements:{passkey:boolean;totp:boolean};
  warning:string;
};
async function row(env:AuthEnv):Promise<BootstrapRow|null>{
  return env.DB.prepare("SELECT cloudflare_user_id,admin_email,admin_user_id,state,completed_at FROM nathan_bootstrap_status WHERE id='primary' LIMIT 1")
    .first<BootstrapRow>();
}
async function enrollment(env:AuthEnv,userId:string) {
  const [p,t]=await Promise.all([
    env.DB.prepare('SELECT COUNT(*) AS count FROM "passkey" WHERE "userId"=?').bind(userId).first<{count:number}>(),
    env.DB.prepare('SELECT COUNT(*) AS count FROM "twoFactor" WHERE "userId"=? AND "verified"=1').bind(userId).first<{count:number}>()
  ]);
  return {passkeys:p?.count||0,totpVerified:(t?.count||0)>0};
}
export async function bootstrapStatus(env:AuthEnv,userId:string):Promise<AdminEnrollment>{
  const b=await row(env);
  if(!b)return {configured:false,state:"missing",isInitialAdmin:false,
    passkeys:0,totpVerified:false,ready:false,
    requirements:{passkey:true,totp:true},
    warning:"Admin bootstrap has not been initialized; use the Cloudflare-authorized wizard or recovery CLI."};
  const methods=await enrollment(env,userId);
  const policy=await effectiveAdminPolicy(env);
  const business=policy.requireBothAuthenticators;
  const ready=business?(methods.passkeys>0 && methods.totpVerified)
    :(methods.passkeys>0 || methods.totpVerified);
  return {configured:true,state:b.state,isInitialAdmin:b.admin_user_id===userId,
    ...methods,ready,
    requirements:{passkey:business,totp:business},
    warning:"Authenticator enrollment is a setup prerequisite, not proof that the current federated login satisfied a NIST AAL or step-up challenge."};
}
export async function completeBootstrap(env:AuthEnv,userId:string) {
  if(env.NATHAN_BOOTSTRAP_REQUIRED!=="true")throw Error("Bootstrap completion is not configured for this installation");
  const b=await row(env);
  if(!b||b.admin_user_id!==userId||b.state==="pending")
    throw Error("Only the verified installer-approved initial administrator may complete setup");
  const status=await bootstrapStatus(env,userId);
  if(!status.ready)throw Error("Enroll the required passkey and authenticator before completing initial setup");
  const changed=await env.DB.prepare(
    "UPDATE nathan_bootstrap_status SET state='complete',completed_at=unixepoch(),updated_at=unixepoch() "+
    "WHERE id='primary' AND admin_user_id=? AND state IN ('identity_verified','authenticators_enrolled','complete')"
  ).bind(userId).run();
  if(!changed.meta?.changes)throw Error("Bootstrap state changed; sign in and try again");
  await audit(env,userId,"initial_admin_bootstrap","primary","succeeded");
  return {complete:true,identityVerified:true,authenticatorsEnrolled:true,
    note:"Initial admin setup is complete. These enrollment checks alone do not establish current-session MFA."};
}
/** For any administrator, enrollment is required before privileged UI and MCP. */
export async function mayAdminister(env:AuthEnv,userId:string,sessionId?:string) {
  if(env.NATHAN_BOOTSTRAP_REQUIRED!=="true")return true; // Legacy manual installations
  const b=await row(env);
  if(!b||b.state!=="complete")return false;
  const auth=await enrollment(env,userId);
  const policy=await effectiveAdminPolicy(env);
  const enrolled=policy.requireBothAuthenticators
    ?(auth.passkeys>0&&auth.totpVerified):(auth.passkeys>0||auth.totpVerified);
  if(!enrolled)return false;
  if(!policy.requireRecentPasskey)return true;
  if(!sessionId || sessionId.length>256)return false;
  const stepup=await env.DB.prepare(
    "SELECT session_id FROM nathan_admin_assurance WHERE session_id=? AND user_id=? "+
    "AND method='passkey' AND verified_at>=unixepoch()-900 LIMIT 1"
  ).bind(sessionId,userId).first();
  return Boolean(stepup);
}
