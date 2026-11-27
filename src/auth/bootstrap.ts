import { liveAdminSession } from "./email-sign-in-policy";
import type { AuthEnv } from "./env";
import { audit } from "./admin-service";
import {effectiveAdminPolicy, managementAllowsTotp, type EffectiveAdminPolicy} from "./security-policy";

type BootstrapRow={
  cloudflare_user_id:string;admin_email:string;admin_user_id:string|null;
  state:"pending"|"identity_verified"|"authenticators_enrolled"|"complete";
  completed_at:number|null;
};
export type AdminEnrollment={
  configured:boolean;state:string;isInitialAdmin:boolean;
  passkeys:number;totpVerified:boolean;ready:boolean;
  requirements:{passkey:boolean;totp:boolean;stepUp:EffectiveAdminPolicy["stepUp"]};
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
    requirements:{passkey:true,totp:true,stepUp:"passkey"},
    warning:"Admin bootstrap has not been initialized; use the Cloudflare-authorized wizard or recovery CLI."};
  const methods=await enrollment(env,userId);
  const policy=await effectiveAdminPolicy(env);
  const business=policy.requireBothAuthenticators;
  const needsKey = business || policy.requireRecentPasskey;
  const ready = (methods.passkeys > 0 || methods.totpVerified) &&
    (!needsKey || methods.passkeys > 0) && (!business || methods.totpVerified);
  return {configured:true,state:b.state,isInitialAdmin:b.admin_user_id===userId,
    ...methods,ready,
    requirements:{passkey:needsKey,totp:business,stepUp:policy.stepUp},
    warning:"Authenticator enrollment is a setup prerequisite, not proof that the current federated login satisfied a NIST AAL or step-up challenge."};
}
export async function completeBootstrap(env:AuthEnv,userId:string) {
  if(env.NATHAN_BOOTSTRAP_REQUIRED!=="true")throw Error("Bootstrap completion is not configured for this installation");
  const b=await row(env);
  if(!b||b.admin_user_id!==userId||b.state==="pending")
    throw Error("Only the verified installer-approved initial administrator may complete setup");
  const status=await bootstrapStatus(env,userId);
  if(!status.ready)throw Error("Enroll the required authentication method before completing setup");
  const changed=await env.DB.prepare(
    "UPDATE nathan_bootstrap_status SET state='complete',completed_at=unixepoch(),updated_at=unixepoch() "+
    "WHERE id='primary' AND admin_user_id=? AND state IN ('identity_verified','authenticators_enrolled','complete')"
  ).bind(userId).run();
  if(!changed.meta?.changes)throw Error("Bootstrap state changed; sign in and try again");
  await audit(env,userId,"initial_admin_bootstrap","primary","succeeded");
  return {complete:true,identityVerified:true,authenticatorsEnrolled:true,
    note:"Initial admin setup is complete. These enrollment checks alone do not establish current-session MFA."};
}
async function recentPasskey(env:AuthEnv,userId:string,sessionId?:string) {
  if(!sessionId || sessionId.length>256)return false;
  const stepup=await env.DB.prepare(
    "SELECT session_id FROM nathan_admin_assurance WHERE session_id=? AND user_id=? "+
    "AND method='passkey' AND verified_at>=unixepoch()-900 LIMIT 1"
  ).bind(sessionId,userId).first();
  return Boolean(stepup);
}

async function recentAuthenticator(env:AuthEnv, userId:string, sessionId:string | undefined, method:EffectiveAdminPolicy["stepUp"]) {
  if (await recentPasskey(env, userId, sessionId)) return true;
  if (!sessionId || method !== "passkey-or-totp") return false;
  return Boolean(await env.DB.prepare(
    'SELECT 1 FROM nathan_management_totp t JOIN "twoFactor" f ON f.id=t.factor_id ' +
    'JOIN "session" s ON s.id=t.session_id AND s.userId=f.userId JOIN "user" u ON u.id=f.userId AND u.twoFactorEnabled=1 ' +
    'WHERE t.session_id=? AND f.userId=? AND f.verified=1 AND t.verified_at BETWEEN unixepoch()-900 AND unixepoch()'
  ).bind(sessionId, userId).first());
}

/** Once a management factor exists, prove it before adding another method. */
export async function mayEnrollManagementFactor(env: AuthEnv, userId: string, sessionId: string, path: string) {
  const registerKey = path === "/passkey/generate-register-options" || path === "/passkey/verify-registration";
  if (!registerKey && path !== "/two-factor/enable") return true;
  const existing = await enrollment(env, userId);
  if (managementAllowsTotp(env) && (existing.totpVerified || existing.passkeys > 0)) {
    const policy = await effectiveAdminPolicy(env);
    // A TOTP-only operator can add their first key before a stricter policy takes effect.
    // A required passkey that is already enrolled must be proved with the key.
    const method = policy.requireRecentPasskey && existing.passkeys > 0 ? "passkey" : "passkey-or-totp";
    return recentAuthenticator(env, userId, sessionId, method);
  }
  const alreadyEnrolled = registerKey ? existing.passkeys > 0 : existing.totpVerified;
  return !alreadyEnrolled || await recentPasskey(env, userId, sessionId);
}

/** For any administrator, enrollment is required before privileged UI and MCP. */
export async function mayAdminister(env:AuthEnv,userId:string,sessionId?:string) {
  if (!await liveAdminSession(env.DB, userId, sessionId)) return false;
  if(env.NATHAN_BOOTSTRAP_REQUIRED!=="true")return true; // Legacy manual installations
  const b=await row(env);
  if(!b||b.state!=="complete")return false;
  const auth=await enrollment(env,userId);
  const policy=await effectiveAdminPolicy(env);
  const enrolled=policy.requireBothAuthenticators
    ?(auth.passkeys>0&&auth.totpVerified):(auth.passkeys>0||auth.totpVerified);
  if(!enrolled)return false;
  if(policy.stepUp==="none")return true;
  return recentAuthenticator(env,userId,sessionId,policy.stepUp);
}
