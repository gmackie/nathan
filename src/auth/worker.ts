import { WorkerEntrypoint } from "cloudflare:workers";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createAuth } from "./instance";
import { signInPage, consentPage, studioPage } from "./ui";
import type { AuthEnv } from "./env";

function reject(status: number, reason: string) {
  return Response.json({ error: reason }, { status, headers: { "Cache-Control": "no-store" } });
}
function isAdmin(session: any, env: AuthEnv): boolean {
  const allow = env.NATHAN_ADMIN_EMAILS.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  return Boolean(session?.user?.emailVerified && session.user.role === "admin"
    && allow.includes(session.user.email?.toLowerCase()));
}
async function handle(request: Request, env: AuthEnv): Promise<Response> {
  const issuer = new URL(env.NATHAN_ISSUER);
  const url = new URL(request.url);
  if (url.hostname !== issuer.hostname || url.protocol !== "https:") return reject(421, "Misdirected request");
  if (url.pathname === "/healthz") return Response.json({ ok: true, system: "nathan" });
  const auth = createAuth(env);
  if (url.pathname.startsWith("/api/auth/") || url.pathname.startsWith("/.well-known/")) {
    return auth.handler(request);
  }
  if (url.pathname === "/") return Response.redirect(issuer.origin + "/sign-in", 302);
  if (url.pathname === "/sign-in" && request.method === "GET") {
    const providers = [];
    if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) providers.push("google");
    if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) providers.push("github");
    return signInPage(providers, env.ENABLE_PASSWORD === "true");
  }
  if (url.pathname === "/consent" && request.method === "GET") {
    const { secret } = await auth.$context;
    const verified = await verifyOAuthQueryParams(url.search.slice(1), secret);
    return consentPage(Boolean(verified), url.searchParams.get("client_id") ?? "Application", url.searchParams.get("scope") ?? "");
  }
  if (url.pathname === "/studio" && request.method === "GET") {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!isAdmin(session, env)) return reject(403, "Admin session required");
    return studioPage(session!.user.email);
  }
  if ((url.pathname === "/studio/api/clients" || url.pathname === "/studio/api/status") && request.method === "GET") {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!isAdmin(session, env)) return reject(403, "Admin session required");
    if (url.pathname === "/studio/api/status") {
      return Response.json({
        issuer: issuer.origin + "/api/auth",
        providers: {google: Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET), github: Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET)},
        features: {oidcProvider: true, passkeys: true, totp: true, enterpriseSso: env.ENTERPRISE_SSO === "true", password: env.ENABLE_PASSWORD === "true"},
        note: "Authentication assurance level enforcement and guided plugin installation are not yet available"
      }, {headers: {"Cache-Control":"no-store"}});
    }
    const clients = await env.DB.prepare('SELECT "clientId" AS id, "name" AS name, "redirectUris" AS redirectUris, "disabled" AS disabled, "tokenEndpointAuthMethod" AS authMethod FROM "oauthClient" ORDER BY "createdAt" DESC LIMIT 100')
      .all<{id:string,name:string,redirectUris:string,disabled:number,authMethod:string}>();
    return Response.json({clients:clients.results.map(c => ({...c,redirectUris:JSON.parse(c.redirectUris || "[]")}))},{headers:{"Cache-Control":"no-store"}});
  }
  if (url.pathname === "/studio/api/clients" && request.method === "POST") {
    if (request.headers.get("Origin") !== issuer.origin) return reject(403, "Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json") return reject(415, "JSON required");
    if (Number(request.headers.get("Content-Length") || "0") > 8192) return reject(413, "Request too large");
    const session = await auth.api.getSession({ headers: request.headers });
    if (!isAdmin(session, env)) return reject(403, "Admin session required");
    let body: any;
    try { body = await request.json(); } catch { return reject(400, "Invalid JSON"); }
    if (typeof body?.name !== "string" || body.name.length < 1 || body.name.length > 100) return reject(400, "Invalid client name");
    let redirect: URL;
    try { redirect = new URL(body.redirectUri); } catch { return reject(400, "Invalid redirect URI"); }
    if (redirect.protocol !== "https:" || redirect.username || redirect.password || redirect.hash)
      return reject(400, "Client redirect must be HTTPS without credentials or fragment");
    if (!["external","worker","gateway"].includes(body.kind)) return reject(400, "Invalid client type");
    if (body.publicClient && body.kind === "gateway") return reject(400, "A gateway must be a confidential client");
    const client = await auth.api.adminCreateOAuthClient({
      headers: request.headers,
      body: {
        client_name: body.name,
        redirect_uris: [redirect.href],
        token_endpoint_auth_method: body.publicClient ? "none" : "client_secret_basic",
        application_type: "web",
        ...(body.kind === "gateway" ? {backchannel_logout_uri: redirect.origin + "/__nathan/backchannel"} : {}),
        grant_types: ["authorization_code", "refresh_token"],
        require_pkce: true,
        skip_consent: false
      }
    });
    return Response.json(client, { headers: { "Cache-Control": "no-store" } });
  }
  return reject(404, "Not found");
}

export default {
  fetch: (request: Request, env: AuthEnv) => handle(request, env)
};

export class NathanVerifier extends WorkerEntrypoint<AuthEnv> {
  async getPrincipal(cookie: string): Promise<{ sub: string; email: string; role: string } | null> {
    if (typeof cookie !== "string" || cookie.length > 8192) return null;
    const auth = createAuth(this.env);
    const session = await auth.api.getSession({ headers: new Headers({ Cookie: cookie }) });
    if (!session?.user?.id) return null;
    return { sub: session.user.id, email: session.user.email, role: (session.user as any).role ?? "user" };
  }
  async authorize(input: { applicationId: string; cookie: string }): Promise<boolean> {
    if (!input || !/^[a-z][a-z0-9-]{0,62}$/.test(input.applicationId ?? "")) return false;
    const principal = await this.getPrincipal(input.cookie);
    if (!principal) return false;
    const row = await this.env.DB.prepare("SELECT roles, enabled FROM nathan_applications WHERE id = ?")
      .bind(input.applicationId).first<{ roles: string; enabled: number }>();
    if (!row || row.enabled !== 1) return false;
    const required: unknown = JSON.parse(row.roles);
    return Array.isArray(required) && required.every(r => typeof r === "string") && (required.length === 0 || required.includes(principal.role));
  }
}
