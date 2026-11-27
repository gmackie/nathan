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

export const managementPasswordPath = "/security/management-password";

// ClassCheck users may have signed in exclusively by email before being granted Studio access.
// Only a live, explicit additional administrator on their own Access host can use this flow.
export async function passwordGrant(env: AuthEnv) {
  if (!managementAllowsTotp(env) || env.ENABLE_PASSWORD !== "true") return null;
  return env.DB.prepare(`SELECT u.id,u.email,g.grant_generation AS generation FROM nathan_admin_grants g JOIN "user" u ON u.id=g.user_id
    JOIN nathan_bootstrap_status b ON b.id='primary' AND b.state='complete' AND b.admin_user_id<>u.id
    WHERE g.enabled=1 AND g.email=? AND lower(u.email)=g.email AND u.role='admin' AND u.emailVerified=1`)
    .bind(env[managementEmail]).first<{id:string;email:string;generation:number}>();
}

async function purpose(env: AuthEnv, grant: {id: string; generation: number}) {
  return "management-password:v1:" + await sha256(JSON.stringify([env.NATHAN_ISSUER, env[managementEmail], grant.id, grant.generation]));
}

/** Better Auth owns token generation, expiry, consumption and password hashing. Bind its
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
  const saved = await provider("reset-password",{token,newPassword:password});
  if (!saved.ok) return page(grant.email,"Request a fresh setup link and try again.",saved.status);
  return Response.redirect(env.NATHAN_ISSUER+"/sign-in",303);
}
