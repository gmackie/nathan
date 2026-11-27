import { Button } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import { Link } from "@cloudflare/kumo/components/link";
import { sha256 } from "../gateway/crypto";
import { isAllowedUnsafeRequest } from "../shared/security.mjs";
import { AuthLayout } from "../ui/layouts/AuthLayout";
import { renderPage } from "../ui/render";
import { readBoundedText } from "./bounded-body.mjs";
import { openConfigSecret, sealConfigSecret } from "./config-crypto.mjs";
import { sendAuthEmail } from "./email";
import { managementEmail, type AuthEnv } from "./env";
import type { createAuth } from "./instance";
import { managementAllowsTotp } from "./security-policy";
import { activeManagementUser, epochSeconds } from "./management-storage";

export const managementPasswordPath = "/security/management-password";
type PasswordGrant = {id:string;email:string;generation:number};
const currentPasswordGrant = `FROM nathan_admin_grants g JOIN user u ON u.id=g.user_id
  JOIN nathan_bootstrap_status b ON b.id='primary' AND b.state='complete' AND b.admin_user_id<>u.id
  WHERE g.enabled=1 AND g.email=?1 AND lower(u.email)=g.email AND ${activeManagementUser}`;

// ClassCheck users may have signed in exclusively by email before being granted Studio access.
// Only a live, explicit additional administrator on their own Access host can use this flow.
export async function passwordGrant(env: AuthEnv) {
  if (!managementAllowsTotp(env) || env.ENABLE_PASSWORD !== "true") return null;
  return env.DB.prepare(`SELECT u.id,u.email,g.grant_generation AS generation ${currentPasswordGrant}`)
    .bind(env[managementEmail]).first<PasswordGrant>();
}

async function purpose(env: AuthEnv, grant: {id: string; generation: number}) {
  return "management-password:v1:" + await sha256(JSON.stringify([env.NATHAN_ISSUER, env[managementEmail], grant.id, grant.generation]));
}

async function savePassword(env: AuthEnv, auth: ReturnType<typeof createAuth>, grant: PasswordGrant, token: string, password: string) {
  const identifier = "reset-password:" + token;
  const context = await auth.$context;
  const verification = await context.internalAdapter.findVerificationValue(identifier);
  if (verification?.value !== grant.id || verification.expiresAt.getTime() <= Date.now()) return false;
  const hash = await context.password.hash(password);
  const db = env.DB, receipt = crypto.randomUUID(), now = new Date().toISOString();
  const committed = "EXISTS(SELECT 1 FROM nathan_security_audit WHERE id=?)";
  const credential = "userId=? AND accountId=? AND providerId='credential'";
  // The receipt is created only while this exact grant and unspent token are live.
  // D1 rolls back the receipt along with the token, sessions, and credential on failure.
  const [saved] = await db.batch([
    db.prepare(`INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
      SELECT ?2,u.id,'management_password_set',u.id,'succeeded' ${currentPasswordGrant}
        AND u.id=?3 AND g.grant_generation=?4 AND EXISTS(SELECT 1 FROM verification v
          WHERE v.id=?5 AND v.identifier=?6 AND v.value=u.id AND ${epochSeconds("v.expiresAt")}>unixepoch())`)
      .bind(grant.email, receipt, grant.id, grant.generation, verification.id, identifier),
    db.prepare(`DELETE FROM verification WHERE identifier=? AND value=? AND ${committed}`).bind(identifier, grant.id, receipt),
    db.prepare(`DELETE FROM session WHERE userId=? AND ${committed}`).bind(grant.id, receipt),
    db.prepare(`DELETE FROM nathan_admin_assurance WHERE user_id=? AND ${committed}`).bind(grant.id, receipt),
    db.prepare(`UPDATE account SET password=?,updatedAt=? WHERE ${credential} AND ${committed}`)
      .bind(hash, now, grant.id, grant.id, receipt),
    db.prepare(`INSERT INTO account(id,accountId,providerId,userId,password,createdAt,updatedAt)
      SELECT ?,?,'credential',?,?,?,? WHERE ${committed} AND NOT EXISTS(SELECT 1 FROM account WHERE ${credential})`)
      .bind(crypto.randomUUID(), grant.id, grant.id, hash, now, now, receipt, grant.id, grant.id)
  ]);
  return saved.meta.changes === 1;
}

/** Better Auth issues the token and owns password hashing. Bind its
 * mailed token to this grant holder; the URL fragment stays out of HTTP requests. */
export async function mailManagementPassword(env: AuthEnv, user: {id:string;email:string}, token: string) {
  const grant = await passwordGrant(env);
  if (!grant || grant.id !== user.id || user.email.toLowerCase() !== env[managementEmail]) throw Error("Administrator grant required");
  const link = new URL(managementPasswordPath, env.NATHAN_ISSUER);
  link.hash = await sealConfigSecret(await purpose(env,grant), token, env.NATHAN_CONFIG_KEY);
  await sendAuthEmail(env,user.email,"Set your Studio password",link.href);
}

function page(email: string, message?: string, status = 200) {
  return renderPage(<AuthLayout title="Set your Studio password">
    {message && <p role="status">{message}</p>}
    <form method="post" action={managementPasswordPath} data-request-link="" className="nathan-form">
      <p>Send a one-time password setup link to {email}.</p>
      <Button name="action" value="request" type="submit" variant="primary">Email me a link</Button>
    </form>
    <form method="post" action={managementPasswordPath} data-save-password="" className="nathan-form" hidden>
      <input type="hidden" name="action" value="save" /><input type="hidden" name="proof" />
      <Input label="New management password" name="password" type="password" minLength={8} maxLength={128} autoComplete="new-password" required />
      <Button type="submit" variant="primary">Save password</Button>
    </form>
    <noscript>Enable JavaScript to open the emailed setup link.</noscript>
    <Link href="/sign-in">Return to sign-in</Link>
  </AuthLayout>,{title:"Set your Studio password",status,islands:["management-password"]});
}

export async function managementPassword(request: Request, env: AuthEnv, auth: ReturnType<typeof createAuth>) {
  const grant = await passwordGrant(env);
  if (!grant) return new Response("Setup unavailable",{status:404});
  if (request.method === "GET") return page(grant.email);
  if (request.method !== "POST") return new Response("Method not allowed",{status:405,headers:{Allow:"GET, POST"}});
  if (!isAllowedUnsafeRequest("POST",request.headers.get("Origin"),env.NATHAN_ISSUER,request.headers.get("Sec-Fetch-Site")))
    return new Response("Cross-origin request denied",{status:403});
  if (request.headers.get("Content-Type")?.split(";")[0] !== "application/x-www-form-urlencoded")
    return new Response("Form required",{status:415});
  const data = await readBoundedText(request,4096);
  if (data === null) return new Response("Request too large",{status:413});
  const form = new URLSearchParams(data);
  const headers = new Headers({Origin:env.NATHAN_ISSUER,"Content-Type":"application/json"});
  const ip = request.headers.get("cf-connecting-ip");
  if (ip) headers.set("cf-connecting-ip",ip);
  const provider = (path:string,body:object) => auth.handler(new Request(new URL("/api/auth/"+path,env.NATHAN_ISSUER),{
    method:"POST", headers, body:JSON.stringify(body)
  }));
  if (form.get("action") === "request") {
    const sent = await provider("request-password-reset",{email:grant.email});
    return sent.ok ? page(grant.email,"Check your inbox for the setup link.") :
      page(grant.email,"The link could not be sent. Try again later.",sent.status);
  }
  const password = form.get("password");
  if (form.get("action") !== "save" || !password || password.length<8 || password.length>128)
    return page(grant.email,"Use a password between 8 and 128 characters.",400);
  let token: string;
  try { token = await openConfigSecret(await purpose(env,grant),form.get("proof"),env.NATHAN_CONFIG_KEY); }
  catch { return page(grant.email,"Request a new setup link for this account.",400); }
  try {
    if (!await savePassword(env,auth,grant,token,password))
      return page(grant.email,"Request a fresh setup link and try again.",400);
  } catch {
    return page(grant.email,"Could not save your password. Try again.",500);
  }
  return Response.redirect(env.NATHAN_ISSUER+"/sign-in",303);
}
