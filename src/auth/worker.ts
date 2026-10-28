import { WorkerEntrypoint } from "cloudflare:workers";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createAuth } from "./instance";
import { loadSocialCredentials, providerStatus, upsertSocialProvider, setSocialProviderEnabled } from "./provider-store";
import {bootstrapStatus,completeBootstrap,mayAdminister} from "./bootstrap";
import { signInPage, consentPage, studioPage } from "./ui";
import { securityPage } from "./security-ui";
import { loadVerifiedRealm, listRealmClients,registerRealmClient,registerRealmClientsBatch,updateRealmClientStatus } from "./domain-realm";
import type { AuthEnv } from "./env";
import pluginCatalog from "../../plugins/catalog.json";
import { handleMcp, protectedResourceMetadata } from "./mcp";
import { isAdminUser, listApplications, listSso, upsertApplication,
  setApplicationEnabled, registerEnterpriseOidc, createOAuthClient, listUsers } from "./admin-service";

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
  if (url.origin !== issuer.origin || url.protocol !== "https:") return reject(421, "Misdirected request");
  if (url.pathname === "/healthz") return Response.json({ ok: true, system: "nathan", active: env.NATHAN_INSTALL_ACTIVE !== "false" });
  // The hosted installer uploads inactive code before it creates a public route.
  if (env.NATHAN_INSTALL_ACTIVE === "false") return reject(503, "Installation not active");
  if (url.pathname === "/.well-known/oauth-protected-resource" ||
      url.pathname === "/.well-known/oauth-protected-resource/mcp") {
    return protectedResourceMetadata(env);
  }
  const socialProviders=await loadSocialCredentials(env);
  const auth = createAuth(env,socialProviders);
  if (url.pathname === "/mcp") return handleMcp(request,env,auth);
  if (url.pathname.startsWith("/api/auth/") || url.pathname.startsWith("/.well-known/")) {
    return auth.handler(request);
  }
  if (url.pathname === "/") return Response.redirect(issuer.origin + "/sign-in", 302);
  if (url.pathname === "/sign-in" && request.method === "GET") {
    const providers = [];
    if (socialProviders.google) providers.push("google");
    if (socialProviders.github) providers.push("github");
    return signInPage(providers, env.ENABLE_PASSWORD === "true", env.ENTERPRISE_SSO === "true");
  }
  if (url.pathname === "/consent" && request.method === "GET") {
    const { secret } = await auth.$context;
    const verified = await verifyOAuthQueryParams(url.search.slice(1), secret);
    return consentPage(Boolean(verified), url.searchParams.get("client_id") ?? "Application", url.searchParams.get("scope") ?? "");
  }
  if (url.pathname === "/security" && request.method === "GET") {
    const session=await auth.api.getSession({headers:request.headers});
    if(!session?.user?.id)return Response.redirect(issuer.origin+"/sign-in",302);
    return securityPage(session.user.email);
  }

  if(url.pathname==="/security/api/bootstrap" && request.method==="GET"){
    const session=await auth.api.getSession({headers:request.headers});
    if(!session?.user?.id)return reject(401,"Authenticated session required");
    return Response.json(await bootstrapStatus(env,session.user.id),{headers:{"Cache-Control":"no-store"}});
  }
  if(url.pathname==="/security/api/bootstrap/complete" && request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin || request.headers.get("Sec-Fetch-Site")==="cross-site")
      return reject(403,"Cross-origin request denied");
    const session=await auth.api.getSession({headers:request.headers});
    if(!isAdminUser(session?.user,env))return reject(403,"Verified initial admin account required");
    try{
      return Response.json(await completeBootstrap(env,session!.user.id),{headers:{"Cache-Control":"no-store"}});
    }catch{return reject(409,"Complete verified passkey and TOTP enrollment first");}
  }

  if (url.pathname === "/studio" && request.method === "GET") {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!isAdmin(session, env)) return reject(403, "Admin session required");
    if (!await mayAdminister(env,session!.user.id)) return Response.redirect(issuer.origin+"/security?setup=admin",302);
    return studioPage(session!.user.email);
  }
  if (["/studio/api/clients", "/studio/api/status", "/studio/api/plugins", "/studio/api/audit", "/studio/api/apps", "/studio/api/sso", "/studio/api/users", "/studio/api/realm", "/studio/api/realm/clients", "/studio/api/providers"].includes(url.pathname) && request.method === "GET") {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!isAdmin(session, env) || !await mayAdminister(env,session!.user.id)) return reject(403, "Admin enrollment incomplete");
    if (url.pathname === "/studio/api/status") {
      return Response.json({
        issuer: issuer.origin + "/api/auth",
        providers: Object.fromEntries((await providerStatus(env)).map(p=>[p.id,p.enabled])),
        features: {oidcProvider: true, passkeys: true, totp: true, enterpriseSso: env.ENTERPRISE_SSO === "true", password: env.ENABLE_PASSWORD === "true"},
        note: "Authentication assurance level enforcement and guided plugin installation are not yet available"
      }, {headers: {"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/providers") {
      return Response.json({providers:await providerStatus(env)}, {headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/realm") {
      try{return Response.json({realm:await loadVerifiedRealm(env)},{headers:{"Cache-Control":"no-store"}})}
      catch{return reject(503,"Domain realm configuration is incomplete or unverified")}
    }
    if (url.pathname === "/studio/api/realm/clients") {
      try{return Response.json(await listRealmClients(env),{headers:{"Cache-Control":"no-store"}})}
      catch{return reject(503,"Cannot load domain realm clients")}
    }
    if (url.pathname === "/studio/api/users") {
      return Response.json({users:await listUsers(env)},{headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/apps") {
      return Response.json({applications:await listApplications(env)},{headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/sso") {
      return Response.json({providers:await listSso(env)},{headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/plugins") {
      return Response.json(pluginCatalog,{headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/audit") {
      const audit = await env.DB.prepare("SELECT id,actor,action,target,outcome,created_at FROM nathan_security_audit ORDER BY created_at DESC LIMIT 75")
        .all<{id:string,actor:string,action:string,target:string,outcome:string,created_at:number}>();
      return Response.json({events:audit.results},{headers:{"Cache-Control":"no-store"}});
    }
    const clients = await env.DB.prepare('SELECT "clientId" AS id, "name" AS name, "redirectUris" AS redirectUris, "disabled" AS disabled, "tokenEndpointAuthMethod" AS authMethod FROM "oauthClient" ORDER BY "createdAt" DESC LIMIT 100')
      .all<{id:string,name:string,redirectUris:string,disabled:number,authMethod:string}>();
    return Response.json({clients:clients.results.map(c => ({...c,redirectUris:JSON.parse(c.redirectUris || "[]")}))},{headers:{"Cache-Control":"no-store"}});
  }

  if (["/studio/api/apps","/studio/api/apps/status","/studio/api/sso/oidc"].includes(url.pathname) && request.method === "POST") {
    if (request.headers.get("Origin") !== issuer.origin ||
        request.headers.get("Sec-Fetch-Site") === "cross-site") return reject(403,"Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json")
      return reject(415,"JSON required");
    const session = await auth.api.getSession({headers:request.headers});
    if (!isAdminUser(session?.user,env) || !await mayAdminister(env,session!.user.id)) return reject(403,"Admin enrollment incomplete");
    const raw=await request.text();
    if(raw.length>16384)return reject(413,"Request too large");
    let body:any;
    try{body=JSON.parse(raw);}catch{return reject(400,"Invalid JSON");}
    try {
      if(url.pathname==="/studio/api/apps") {
        return Response.json(await upsertApplication(env,body,session!.user.id),{headers:{"Cache-Control":"no-store"}});
      }
      if(url.pathname==="/studio/api/apps/status") {
        if(typeof body.enabled!=="boolean"||body.confirm!==("CONFIRM "+(body.enabled?"ENABLE ":"DISABLE ")+body.id))
          return reject(400,"Explicit confirmation required");
        return Response.json(await setApplicationEnabled(env,body.id,body.enabled,session!.user.id),{headers:{"Cache-Control":"no-store"}});
      }
      const value=await registerEnterpriseOidc(auth,env,request.headers,body,session!.user.id);
      return Response.json(value,{headers:{"Cache-Control":"no-store"}});
    }catch {
      return reject(400,"Operation denied or rejected by identity provider");
    }
  }


  if(["/studio/api/realm/clients","/studio/api/realm/clients/batch"].includes(url.pathname) && request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!isAdminUser(session?.user,env) || !await mayAdminister(env,session!.user.id))return reject(403,"Admin enrollment incomplete");
    const raw=await request.text();
    if(raw.length>8192)return reject(413,"Registration too large");
    let input:any;
    try{input=JSON.parse(raw)}catch{return reject(400,"Invalid JSON");}
    try{
      const client=url.pathname.endsWith("/batch")
        ? await registerRealmClientsBatch(auth,env,request.headers,input,session!.user.id)
        : await registerRealmClient(auth,env,request.headers,input,session!.user.id);
      return Response.json(client,{headers:{"Cache-Control":"no-store"}});
    }catch{
      return reject(409,"Registration denied or incomplete. Check the exact hostname, existing realm clients and security audit before retrying.");
    }
  }


  if(["/studio/api/providers","/studio/api/providers/status"].includes(url.pathname) && request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!isAdminUser(session?.user,env) || !await mayAdminister(env,session!.user.id))return reject(403,"Admin enrollment incomplete");
    const raw=await request.text();
    if(raw.length>16384)return reject(413,"Provider input too large");
    let input:any;try{input=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const updated=url.pathname.endsWith("/status")
        ? await setSocialProviderEnabled(env,input,session!.user.id)
        : await upsertSocialProvider(env,input,session!.user.id);
      return Response.json(updated,{headers:{"Cache-Control":"no-store"}});
    }catch{
      return reject(409,"Provider update denied. Check configuration encryption key and remaining login/recovery methods.");
    }
  }

  if (url.pathname === "/studio/api/clients/status" && request.method === "POST") {
    if (request.headers.get("Origin") !== issuer.origin) return reject(403, "Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json") return reject(415, "JSON required");
    const session = await auth.api.getSession({ headers: request.headers });
    if (!isAdmin(session, env) || !await mayAdminister(env,session!.user.id)) return reject(403, "Admin enrollment incomplete");
    const raw = await request.text();
    if (raw.length > 4096) return reject(413, "Request too large");
    let body: any;
    try { body = JSON.parse(raw); } catch { return reject(400, "Invalid JSON"); }
    if (typeof body.clientId !== "string" || !/^[A-Za-z0-9._-]{1,200}$/.test(body.clientId) || typeof body.disabled !== "boolean")
      return reject(400, "Invalid client status update");
    const auditId = crypto.randomUUID();
    const action = body.disabled ? "oauth_client_disable" : "oauth_client_enable";
    await env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
      .bind(auditId,session!.user.id,action,body.clientId,"attempted").run();
    try {
      await auth.api.adminUpdateOAuthClient({
        headers: request.headers,
        body: { client_id: body.clientId, update: { disabled: body.disabled } }
      });
      await updateRealmClientStatus(env,body.clientId,body.disabled);
      await env.DB.prepare("UPDATE nathan_security_audit SET outcome=? WHERE id=?")
        .bind("succeeded",auditId).run();
      return Response.json({updated:true,clientId:body.clientId,disabled:body.disabled},{headers:{"Cache-Control":"no-store"}});
    } catch (error) {
      await env.DB.prepare("UPDATE nathan_security_audit SET outcome=? WHERE id=?")
        .bind("failed",auditId).run();
      return reject(400,"Client update failed or not authorized");
    }
  }
  if (url.pathname === "/studio/api/clients" && request.method === "POST") {
    if (request.headers.get("Origin") !== issuer.origin ||
        request.headers.get("Sec-Fetch-Site") === "cross-site") return reject(403,"Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json") return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if (!isAdminUser(session?.user,env) || !await mayAdminister(env,session!.user.id)) return reject(403,"Admin enrollment incomplete");
    const raw=await request.text();
    if(raw.length>8192)return reject(413,"Request too large");
    try{
      const client=await createOAuthClient(auth,env,request.headers,JSON.parse(raw),session!.user.id);
      return Response.json(client,{headers:{"Cache-Control":"no-store"}});
    }catch{
      return reject(400,"Client creation rejected; verify exact redirect URI, permitted scopes and provider configuration");
    }
  }

  return reject(404, "Not found");
}

export default {
  fetch: (request: Request, env: AuthEnv) => handle(request, env),
  scheduled: async (_: ScheduledEvent,env:AuthEnv) => {
    await env.DB.prepare("DELETE FROM nathan_mcp_limits WHERE expires_at < unixepoch()").run();
  }
};

export class NathanVerifier extends WorkerEntrypoint<AuthEnv> {
  async getPrincipal(cookie: string): Promise<{ sub: string; email: string; role: string } | null> {
    if (typeof cookie !== "string" || cookie.length > 8192) return null;
    const auth = createAuth(this.env, await loadSocialCredentials(this.env));
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
