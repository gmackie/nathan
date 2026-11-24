import { Button } from "@cloudflare/kumo/components/button";
import { Input } from "@cloudflare/kumo/components/input";
import { Label } from "@cloudflare/kumo/components/label";
import { Link } from "@cloudflare/kumo/components/link";
import { AuthLayout } from "../ui/layouts/AuthLayout";
import { renderPage } from "../ui/render";
import { isAllowedUnsafeRequest } from "../shared/security.mjs";
import { normalizeEmail } from "./admission-policy.mjs";
import { readBoundedText } from "./bounded-body.mjs";
import { managementEmail, type AuthEnv } from "./env";
import { createAuth } from "./instance";

const path = "/security/setup-owner";
type Owner = { id: string | null; verified: number | null };
function form(email: string, owner: Owner, error?: string, status = 200) {
  const title = owner.verified ? "Management email verified" : owner.id ? "Verify your management email" : "Set up your administrator account";
  return renderPage(<AuthLayout title={title}>
    {owner.verified ? <>
      <p>Your email is verified. Complete the installer's administrator promotion for {email}, then sign in to enroll your passkey and authenticator app.</p>
      <Link href="/sign-in">Continue to sign-in</Link>
    </> : <form method="post" action={path} className="nathan-stack">
      <p>{owner.id
        ? <>Open the verification link sent to {email}. To send it again, enter the password you chose.</>
        : <>Choose a password for {email}. You will verify your mailbox before enrolling a passkey and authenticator app.</>}</p>
      <Label htmlFor="owner-password"><span id="owner-password-label">Management password</span></Label>
      <Input id="owner-password" aria-labelledby="owner-password-label" name="password" type="password" minLength={8} maxLength={128}
        required autoComplete={owner.id ? "current-password" : "new-password"} />
      {error && <p role="alert">{error}</p>}
      <Button type="submit" variant="primary">{owner.id ? "Resend verification email" : "Create account"}</Button>
    </form>}
  </AuthLayout>, { title, status });
}

/** A CLI/installer-approved owner signs up through Better Auth's existing admission and
 * verification flow. Only the installer can promote the verified account; enrollment and
 * recent passkey evidence remain mandatory for privileged access. */
export async function ownerSetup(request: Request, env: AuthEnv): Promise<Response | null> {
  const url = new URL(request.url);
  const onSetup = url.pathname === path;
  const entry = request.method === "GET" && (url.pathname === "/" || url.pathname === "/sign-in" || url.pathname === "/studio");
  if (!onSetup && !entry) return null;
  const email = env[managementEmail];
  const allowed = env.ENABLE_PASSWORD === "true" && env.NATHAN_INSTALL_ACTIVE !== "false" && email &&
    env.NATHAN_ADMIN_EMAILS?.split(",").map(normalizeEmail).includes(email);
  const owner = allowed && await env.DB.prepare(
    'SELECT u.id,u.emailVerified AS verified FROM nathan_bootstrap_status b LEFT JOIN "user" u ON lower(u.email)=b.admin_email ' +
    "WHERE b.id='primary' AND b.state='pending' AND b.admin_user_id IS NULL AND b.admin_email=? AND COALESCE(u.banned,0)=0 " +
    "AND (u.emailVerified=1 OR EXISTS (SELECT 1 FROM nathan_invitations i WHERE i.email=b.admin_email AND i.uses=0 AND i.revoked_at IS NULL AND i.expires_at>unixepoch()))"
  ).bind(email).first<Owner>();
  if (!email || !owner) return onSetup ? new Response("Setup unavailable", { status: 404 }) : null;
  if (entry) return owner.verified && url.pathname === "/sign-in" ? null : Response.redirect(url.origin + path, 302);
  if (request.method === "GET") return form(email, owner);
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  if (!isAllowedUnsafeRequest("POST", request.headers.get("Origin"), url.origin, request.headers.get("Sec-Fetch-Site")))
    return new Response("Cross-origin request denied", { status: 403 });
  if (owner.verified) return Response.redirect(url.origin + path, 303);
  if (request.headers.get("Content-Type")?.split(";")[0] !== "application/x-www-form-urlencoded") return new Response("Form required", { status: 415 });
  const data = await readBoundedText(request, 4096);
  if (data === null) return new Response("Request too large", { status: 413 });
  const [password, ...other] = new URLSearchParams(data).getAll("password");
  if (!password || password.length < 8 || password.length > 128 || other.length) return form(email, owner, "Use a password between 8 and 128 characters.", 400);
  const headers = new Headers({ "Content-Type": "application/json", Origin: url.origin });
  const ip = request.headers.get("cf-connecting-ip");
  if (ip) headers.set("cf-connecting-ip", ip);
  const endpoint = owner.id ? "/api/auth/sign-in/email" : "/api/auth/sign-up/email";
  const response = await createAuth(env).handler(new Request(url.origin + endpoint, {
    method: "POST", headers, body: JSON.stringify({ name: email, email, password, callbackURL: url.origin + path })
  }));
  if (response.ok || (owner.id && response.status === 403 && (await response.json() as { code?: string }).code === "EMAIL_NOT_VERIFIED")) {
    const headers = new Headers({ Location: url.origin + path });
    for (const cookie of response.headers.getSetCookie()) headers.append("Set-Cookie", cookie);
    return new Response(null, { status: 303, headers });
  }
  return form(email, owner, "The request could not be completed. Check your password and try again.", response.status);
}
