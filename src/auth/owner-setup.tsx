import { Button } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import { Label } from "@cloudflare/kumo/components/label";
import { Link } from "@cloudflare/kumo/components/link";
import { AuthLayout } from "../ui/layouts/AuthLayout";
import { renderPage } from "../ui/render";
import { isAllowedUnsafeRequest } from "../shared/security.mjs";
import { userBanned } from "../shared/token-claims.mjs";
import { normalizeEmail } from "./admission-policy.mjs";
import { readBoundedText } from "./bounded-body.mjs";
import { managementEmail, ownerInvitation, type AuthEnv } from "./env";
import { createAuth } from "./instance";
import { liveAdminSession } from "./email-sign-in-policy";

const path = "/security/setup-owner";
type Owner = { id: string | null; verified: number | null; invitation: string | null;
  installerClaim: number; banned: number | null; banExpires: string | number | null };
function form(email: string, owner: Owner, error?: string, status = 200, signedIn = false) {
  const title = owner.verified ? "Management email verified" : owner.id ? "Verify your management email" : "Set up your administrator account";
  return renderPage(<AuthLayout title={title}>
    {owner.verified ? <>
      <p>Your email is verified. {owner.installerClaim
        ? signedIn ? "Continue to choose how you will verify access to Studio." : "Sign in with your management password to continue setup."
        : "Ask the deployment operator to bind this account using Nathan’s admin promote command."}</p>
      {owner.installerClaim && signedIn ? <form method="post" action={path}>
        <Button type="submit" name="action" value="claim" variant="primary">Continue to account security</Button>
      </form> : <Link href="/sign-in">Continue to sign-in</Link>}
    </> : <form method="post" action={path} className="nathan-stack">
      <p>{owner.id
        ? <>Open the verification link sent to {email}. To send it again, enter the password you chose.</>
        : <>Choose a management password for {email}. Next, open the verification link sent to this address.</>}</p>
      <Label htmlFor="owner-password"><span id="owner-password-label">Management password</span></Label>
      <Input id="owner-password" aria-labelledby="owner-password-label" name="password" type="password" minLength={8} maxLength={128}
        required autoComplete={owner.id ? "current-password" : "new-password"} />
      {error && <p role="alert">{error}</p>}
      <Button type="submit" variant="primary">{owner.id ? "Resend verification email" : "Create account"}</Button>
    </form>}
  </AuthLayout>, { title, status });
}

// The original installer must have invited this exact subject. A matching address alone
// does not transfer ownership to a pre-existing user or to a newly reissued invitation.
const installerClaim = `EXISTS(SELECT 1 FROM nathan_invitations used WHERE used.id=b.owner_invitation_id AND used.created_by=b.cloudflare_user_id
  AND used.email=b.admin_email AND used.used_by_user=u.id AND used.uses=1 AND used.used_method='password'
  AND used.revoked_at IS NULL)`;

async function claimOwner(env: AuthEnv, email: string, owner: Owner, sessionId: string) {
  // Recheck the live session, account and approved invitation inside the same write as the binding.
  // A losing concurrent request cannot repeat the grant or its audit.
  const results = await env.DB.batch([
    env.DB.prepare(`UPDATE nathan_bootstrap_status AS b SET admin_user_id=?1,state='identity_verified',updated_at=unixepoch()
      WHERE b.id='primary' AND b.state='pending' AND b.admin_user_id IS NULL AND b.admin_email=?2
      AND EXISTS(SELECT 1 FROM "user" u JOIN "session" s ON s.userId=u.id
        WHERE s.id=?3 AND unixepoch(s.expiresAt)>unixepoch() AND u.id=?1 AND u.email=?2 AND u.emailVerified=1
        AND u.banned IS ?4 AND u.banExpires IS ?5 AND ${installerClaim}
        AND (SELECT count(*) FROM "user" WHERE lower(email)=?2)=1
        AND NOT EXISTS(SELECT 1 FROM nathan_email_otp_sessions WHERE session_id=s.id)
        AND NOT EXISTS(SELECT 1 FROM nathan_scim_users WHERE user_id=u.id AND link_state='deprovisioned' AND override_cause IS NULL))`)
      .bind(owner.id,email,sessionId,owner.banned,owner.banExpires),
    env.DB.prepare('UPDATE "user" SET role=\'admin\' WHERE id=? AND changes()=1').bind(owner.id),
    env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) SELECT ?,?,'admin_bootstrap',?,'succeeded' WHERE changes()=1")
      .bind(crypto.randomUUID(),owner.id,owner.id)
  ]);
  return results[2].meta.changes === 1;
}

/** The Access identity, verified mailbox and management session must all match the installed owner. */
export async function ownerSetup(request: Request, env: AuthEnv): Promise<Response | null> {
  const url = new URL(request.url);
  const onSetup = url.pathname === path;
  const entry = request.method === "GET" && ["/", "/sign-in", "/studio", "/studio/users"].includes(url.pathname);
  if (!onSetup && !entry) return null;
  const email = env[managementEmail];
  const allowed = env.ENABLE_PASSWORD === "true" && env.NATHAN_INSTALL_ACTIVE !== "false" && email &&
    env.NATHAN_ADMIN_EMAILS?.split(",").map(normalizeEmail).includes(email);
  const owner = allowed && await env.DB.prepare(
    'SELECT u.id,u.emailVerified AS verified,u.banned,u.banExpires,i.id AS invitation,' + installerClaim + ' AS installerClaim FROM nathan_bootstrap_status b LEFT JOIN "user" u ON lower(u.email)=b.admin_email ' +
    "LEFT JOIN nathan_invitations i ON i.email=b.admin_email AND i.uses=0 AND i.revoked_at IS NULL AND i.expires_at>unixepoch() " +
    "WHERE b.id='primary' AND b.state='pending' AND b.admin_user_id IS NULL AND b.admin_email=? " +
    "AND (u.emailVerified=1 OR i.id IS NOT NULL)"
  ).bind(email).first<Owner>();
  if (!email || !owner || userBanned(owner)) {
    if (onSetup && allowed && await env.DB.prepare("SELECT 1 FROM nathan_bootstrap_status WHERE id='primary' AND admin_email=? AND admin_user_id IS NOT NULL")
        .bind(email).first()) return Response.redirect(url.origin + "/security?setup=admin", 303);
    return onSetup ? new Response("Setup unavailable", { status: 404 }) : null;
  }
  if (entry) return owner.verified && url.pathname === "/sign-in" ? null : Response.redirect(url.origin + path, 302);
  if (request.method !== "POST" && request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  if (request.method === "POST" && !isAllowedUnsafeRequest("POST", request.headers.get("Origin"), url.origin, request.headers.get("Sec-Fetch-Site")))
    return new Response("Cross-origin request denied", { status: 403 });
  const session = owner.verified && owner.installerClaim ? await createAuth(env).api.getSession({headers:request.headers}) : null;
  const signedIn = Boolean(session && session.user.id===owner.id && session.user.email===email && session.user.emailVerified &&
    await liveAdminSession(env.DB, session.user.id, session.session.id));
  if (request.method === "GET") return form(email, owner, undefined, 200, signedIn);
  if (request.headers.get("Content-Type")?.split(";")[0] !== "application/x-www-form-urlencoded") return new Response("Form required", { status: 415 });
  const data = await readBoundedText(request, 4096);
  if (data === null) return new Response("Request too large", { status: 413 });
  const fields = new URLSearchParams(data);
  if (owner.verified) {
    if (fields.get("action") !== "claim" || !signedIn || !session) return new Response("Sign in to continue owner setup", {status:403});
    if (!await claimOwner(env,email,owner,session.session.id)) return Response.redirect(url.origin + path,303);
    return Response.redirect(url.origin + "/security?setup=admin",303);
  }
  const [password, ...other] = fields.getAll("password");
  if (!password || password.length < 8 || password.length > 128 || other.length) return form(email, owner, "Use a password between 8 and 128 characters.", 400);
  const headers = new Headers({ "Content-Type": "application/json", Origin: url.origin });
  const ip = request.headers.get("cf-connecting-ip");
  if (ip) headers.set("cf-connecting-ip", ip);
  const endpoint = owner.id ? "/api/auth/sign-in/email" : "/api/auth/sign-up/email";
  const response = await createAuth({ ...env, [ownerInvitation]: owner.invitation! }).handler(new Request(url.origin + endpoint, {
    method: "POST", headers, body: JSON.stringify({ name: email, email, password, callbackURL: url.origin + path })
  }));
  if (response.ok || (owner.id && response.status === 403 && (await response.json() as { code?: string }).code === "EMAIL_NOT_VERIFIED")) {
    const headers = new Headers({ Location: url.origin + path });
    for (const cookie of response.headers.getSetCookie()) headers.append("Set-Cookie", cookie);
    return new Response(null, { status: 303, headers });
  }
  return form(email, owner, "The request could not be completed. Check your password and try again.", response.status);
}
