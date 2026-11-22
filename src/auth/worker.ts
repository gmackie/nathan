import { WorkerEntrypoint } from "cloudflare:workers";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { createAuth } from "./instance";
import {isRawManagementEndpoint} from "./management-boundary.mjs";
import { loadSocialCredentials, providerStatus, upsertSocialProvider, setSocialProviderEnabled } from "./provider-store";
import { enabledProviderIds, beginProviderTest, completeProviderTest } from "./provider-store";
import { providerTestResultPage } from "./provider-ui.mjs";
import {bootstrapStatus,completeBootstrap,mayAdminister} from "./bootstrap";
import { totpQrResponse } from "./totp-qr";
import {effectiveAdminPolicy,tightenAdminPolicy} from "./security-policy";
import {handleScim} from "./scim/gateway";
import {listScimConnections,createScimConnection,setScimConnectionEnabled,rotateScimToken} from "./scim/admin";
import {samlProtocolGate,handleSamlRoutes} from "./saml-routes";
export {NathanScimDirectory} from "./scim/directory";
import { signInPage, consentPage, studioPage } from "./ui";
import { securityPage } from "./security-ui";
import { loadVerifiedRealm, listRealmClients,registerRealmClient,registerRealmClientsBatch,updateRealmClientStatus } from "./domain-realm";
import type { AuthEnv } from "./env";
import { scopedApplication, outOfScope, type BindingProps } from "./app-binding";
import pluginCatalog from "../../plugins/catalog.json";
import { handleMcp, protectedResourceMetadata } from "./mcp";
import { isAdminUser, listApplications, listSso, upsertApplication,
  setApplicationEnabled, registerEnterpriseOidc, requestEnterpriseVerification, verifyEnterpriseDomain,
  createOAuthClient, listUsers, isAdminPrincipal, isBootstrapOwner, listAdminGrants, grantAdmin, revokeAdminGrant } from "./admin-service";
import { resolveAccess, directoryPrincipal, directoryChanges, pruneRbacChanges, rbacOverview, listGroups, groupMembers, applyRbacOperation } from "./rbac";
import { handleDirectory, createDirectoryClient } from "./directory";
import { tokenOverview, applyTokenOperation } from "./tokens";
import { isMcpOAuthPath, handleMcpOAuth, mcpReturnRedirect, mcpGrantStatus, mcpOverview, applyMcpOperation, pruneMcp } from "./mcp-oauth";
import { updateScimSettings, changeScimMapping, scimConnectionView, SCIM_ADMIN_ERRORS } from "./scim/lifecycle-admin";
import { deliverLogouts } from "./logout-queue";
import { scimUserOperation, scimOutboxView, skipScimOutbox, SCIM_REVIEW_ERRORS } from "./scim/reviews";
import { admissionOverview, applyAdmissionOperation, ADMISSION_ERRORS } from "./admission";
import { healthResponse } from "./health";
import { handleSamlIdp, samlIdpReturnRedirect, pruneSamlIdp } from "./saml-idp";

function reject(status: number, reason: string) {
  return Response.json({ error: reason }, { status, headers: { "Cache-Control": "no-store" } });
}
async function isAdmin(session:any,env:AuthEnv):Promise<boolean>{
  return Boolean(session?.user && await isAdminPrincipal(session.user,env));
}

async function handle(request: Request, env: AuthEnv): Promise<Response> {
  const issuer = new URL(env.NATHAN_ISSUER);
  const url = new URL(request.url);
  if (url.origin !== issuer.origin || url.protocol !== "https:") return reject(421, "Misdirected request");
  // NATH-17: also reports unusable social providers (id and reason only); see ./health.ts.
  if (url.pathname === "/healthz") return healthResponse(env);
  // The hosted installer uploads inactive code before it creates a public route.
  if (env.NATHAN_INSTALL_ACTIVE === "false") return reject(503, "Installation not active");
  if (url.pathname === "/.well-known/oauth-protected-resource" ||
      url.pathname === "/.well-known/oauth-protected-resource/mcp") {
    return protectedResourceMetadata(env);
  }
  if(url.pathname.startsWith("/scim/v2/"))return handleScim(request,env);
  const socialProviders=await loadSocialCredentials(env);
  const auth = createAuth(env,socialProviders);
  // NATH-14: authorization server for remote MCP servers, consent and MCP connections (src/auth/mcp-oauth.ts).
  if (isMcpOAuthPath(url.pathname)) return handleMcpOAuth(request, env, auth);
  if (url.pathname === "/mcp") return handleMcp(request,env,auth);
  if (url.pathname.startsWith("/directory/")) return handleDirectory(request,env,auth);
  // NATH-12: Nathan as a SAML IdP for downstream service providers (src/auth/saml-idp.ts).
  const samlIdp = await handleSamlIdp(request, env, auth, url);
  if (samlIdp) return samlIdp;
  if (url.pathname.startsWith("/api/auth/") || url.pathname.startsWith("/.well-known/")) {
    if(isRawManagementEndpoint(url.pathname))return reject(404,"Management route unavailable; use the protected Identity Studio");
    const samlGate=await samlProtocolGate(request,env,url);
    if(samlGate)return samlGate;
    return auth.handler(request);
  }
  if (url.pathname === "/") {
    const pending = (await mcpReturnRedirect(request, env, auth)) ?? (await samlIdpReturnRedirect(request, env));
    if (pending) return pending;
    // A signed-in browser with nothing to resume lands on its account page; sending it to
    // /sign-in looped every successful sign-in back to the sign-in page.
    const session = await auth.api.getSession({ headers: request.headers });
    return Response.redirect(issuer.origin + (session?.user?.id ? "/security" : "/sign-in"), 302);
  }
  if (url.pathname === "/sign-in" && request.method === "GET") {
    // With a session and no signed authorization to resume (an app's /oauth2/authorize adds `sig`),
    // there is nothing to sign in to; a prompt=login authorization keeps its signed query and the page.
    if (!url.searchParams.has("sig")) {
      const session = await auth.api.getSession({ headers: request.headers });
      if (session?.user?.id) return Response.redirect(issuer.origin + "/security", 302);
    }
    const providers = enabledProviderIds(socialProviders);
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

  if(url.pathname==="/security/api/totp-qr" && request.method==="POST"){
    const session=await auth.api.getSession({headers:request.headers});
    return totpQrResponse(request,issuer.origin,Boolean(session?.user?.id));
  }
  if(url.pathname==="/security/api/bootstrap" && request.method==="GET"){
    const session=await auth.api.getSession({headers:request.headers});
    if(!session?.user?.id)return reject(401,"Authenticated session required");
    return Response.json({...await bootstrapStatus(env,session.user.id),
      sessionReady:await mayAdminister(env,session.user.id,session.session.id)},
      {headers:{"Cache-Control":"no-store"}});
  }
  if(url.pathname==="/security/api/bootstrap/complete" && request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin || request.headers.get("Sec-Fetch-Site")==="cross-site")
      return reject(403,"Cross-origin request denied");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isBootstrapOwner(session?.user,env))return reject(403,"Verified initial admin account required");
    try{
      return Response.json(await completeBootstrap(env,session!.user.id),{headers:{"Cache-Control":"no-store"}});
    }catch{return reject(409,"Complete verified passkey and TOTP enrollment first");}
  }

  if (url.pathname === "/studio" && request.method === "GET") {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!await isAdmin(session, env)) return reject(403, "Admin session required");
    if (!await mayAdminister(env,session!.user.id,session!.session.id)) return Response.redirect(issuer.origin+"/security?setup=admin",302);
    return studioPage(session!.user.email);
  }
  if (["/studio/api/clients", "/studio/api/status", "/studio/api/plugins", "/studio/api/audit", "/studio/api/apps", "/studio/api/sso", "/studio/api/users", "/studio/api/realm", "/studio/api/realm/clients", "/studio/api/providers", "/studio/api/scim/connections", "/studio/api/admins", "/studio/api/security-policy"].includes(url.pathname) && request.method === "GET") {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!await isAdmin(session, env) || !await mayAdminister(env,session!.user.id,session!.session.id)) return reject(403, "Admin enrollment incomplete");
    if (url.pathname === "/studio/api/status") {
      return Response.json({
        issuer: issuer.origin + "/api/auth",
        providers: Object.fromEntries((await providerStatus(env)).map(p=>[p.id,p.enabled])),
        features: {oidcProvider: true, passkeys: true, totp: true, enterpriseSso: env.ENTERPRISE_SSO === "true", password: env.ENABLE_PASSWORD === "true", scimDirectory: Boolean(env.SCIM_DIRECTORY)},
        note: "Authentication assurance level enforcement and guided plugin installation are not yet available"
      }, {headers: {"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/security-policy") {
      return Response.json(await effectiveAdminPolicy(env),{headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/admins") {
      return Response.json(await listAdminGrants(env),{headers:{"Cache-Control":"no-store"}});
    }
    if (url.pathname === "/studio/api/scim/connections") {
      return Response.json({connections:await listScimConnections(env)},{headers:{"Cache-Control":"no-store"}});
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

  if (["/studio/api/apps","/studio/api/apps/status","/studio/api/sso/oidc","/studio/api/sso/token","/studio/api/sso/verify"].includes(url.pathname) && request.method === "POST") {
    if (request.headers.get("Origin") !== issuer.origin ||
        request.headers.get("Sec-Fetch-Site") === "cross-site") return reject(403,"Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json")
      return reject(415,"JSON required");
    const session = await auth.api.getSession({headers:request.headers});
    if (!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id)) return reject(403,"Admin enrollment incomplete");
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
      const value=url.pathname==="/studio/api/sso/token"
        ?await requestEnterpriseVerification(auth,env,request.headers,body,session!.user.id)
        :url.pathname==="/studio/api/sso/verify"
          ?await verifyEnterpriseDomain(auth,env,request.headers,body,session!.user.id)
          :await registerEnterpriseOidc(auth,env,request.headers,body,session!.user.id);
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
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))return reject(403,"Admin enrollment incomplete");
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


  // NATH-9: a Studio test sign-in lands here after the provider callback. The session may
  // belong to the test account, so authority comes from the admin-issued single-use ticket.
  if(url.pathname==="/studio/providers/test-complete" && request.method==="GET"){
    const session=await auth.api.getSession({headers:request.headers});
    try{
      const result=await completeProviderTest(env,url.searchParams.get("ticket"),
        session?.session?.id&&session.user?.id?{sessionId:session.session.id,userId:session.user.id}:null);
      return providerTestResultPage(true,result.id,session?.user?.email??"",result.adminVerified);
    }catch{
      return providerTestResultPage(false,null,session?.user?.email??"");
    }
  }

  if(["/studio/api/providers","/studio/api/providers/status","/studio/api/providers/test"].includes(url.pathname) && request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))return reject(403,"Admin enrollment incomplete");
    const raw=await request.text();
    if(raw.length>16384)return reject(413,"Provider input too large");
    let input:any;try{input=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const updated=url.pathname.endsWith("/status")
        ? await setSocialProviderEnabled(env,input,session!.user.id)
        : url.pathname.endsWith("/test")
          ? await beginProviderTest(env,input,session!.user.id)
          : await upsertSocialProvider(env,input,session!.user.id);
      return Response.json(updated,{headers:{"Cache-Control":"no-store"}});
    }catch(e){
      // Only registry/rule errors carry a publicMessage; they never contain submitted values.
      const safe=(e as {publicMessage?:unknown})?.publicMessage;
      return reject(409,typeof safe==="string"?safe:"Provider update denied. Check configuration encryption key and remaining login/recovery methods.");
    }
  }


  if(["/studio/api/scim/connections","/studio/api/scim/status","/studio/api/scim/rotate"].includes(url.pathname)&&request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Verified administrator with completed enrollment required");
    const raw=await request.text();
    if(raw.length>16384)return reject(413,"SCIM configuration too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const result=url.pathname.endsWith("/status")
        ?await setScimConnectionEnabled(env,body,session!.user.id)
        :url.pathname.endsWith("/rotate")
          ?await rotateScimToken(env,body,session!.user.id)
          :await createScimConnection(env,body,session!.user.id);
      return Response.json(result,{headers:{"Cache-Control":"no-store"}});
    }catch{
      return reject(409,"SCIM change rejected. Verify connection name, server binding and explicit confirmation.");
    }
  }



  if(url.pathname==="/studio/api/security-policy/tighten"&&request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) ||
       !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment and privileged session required");
    const raw=await request.text();
    if(raw.length>2048)return reject(413,"Policy input too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const result=await tightenAdminPolicy(env,body,session!.user.id,session!.session.id);
      return Response.json(result,{headers:{"Cache-Control":"no-store"}});
    }catch{return reject(409,"Cannot tighten policy until the required authenticators and recent verification are available");}
  }

  if(["/studio/api/admins/grant","/studio/api/admins/revoke"].includes(url.pathname)&&request.method==="POST"){
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env)||
       !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Completed admin enrollment and recent passkey authentication required");
    const raw=await request.text();
    if(raw.length>4096)return reject(413,"Admin operation too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const value=url.pathname.endsWith("/grant")
        ?await grantAdmin(env,body,session!.user.id)
        :await revokeAdminGrant(env,body,session!.user.id);
      return Response.json(value,{headers:{"Cache-Control":"no-store"}});
    }catch{return reject(409,"Admin grant/revocation denied; check verified identity, confirmation and recovery policy");}
  }

  if (url.pathname === "/studio/api/clients/status" && request.method === "POST") {
    if (request.headers.get("Origin") !== issuer.origin) return reject(403, "Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json") return reject(415, "JSON required");
    const session = await auth.api.getSession({ headers: request.headers });
    if (!await isAdmin(session, env) || !await mayAdminister(env,session!.user.id,session!.session.id)) return reject(403, "Admin enrollment incomplete");
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
    if (!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id)) return reject(403,"Admin enrollment incomplete");
    const raw=await request.text();
    if(raw.length>8192)return reject(413,"Request too large");
    try{
      const client=await createOAuthClient(auth,env,request.headers,JSON.parse(raw),session!.user.id);
      return Response.json(client,{headers:{"Cache-Control":"no-store"}});
    }catch{
      return reject(400,"Client creation rejected; verify exact redirect URI, permitted scopes and provider configuration");
    }
  }

  // NATH-11: SCIM lifecycle (linking/JIT toggles, group mappings, status). Admin-only, stepped up, audited.
  if (url.pathname === "/studio/api/scim/connection" && request.method === "GET") {
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment incomplete");
    try{return Response.json(await scimConnectionView(env,url.searchParams.get("id"),
      {reviewState:url.searchParams.get("reviewState"),reviewOffset:url.searchParams.get("reviewOffset")}),{headers:{"Cache-Control":"no-store"}})}
    catch(error){
      if(error instanceof Error&&error.message==="Invalid review filter")return reject(400,"Invalid review filter");
      return reject(404,"Unknown SCIM connection");
    }
  }
  if (["/studio/api/scim/settings","/studio/api/scim/mappings"].includes(url.pathname) && request.method === "POST") {
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Verified administrator with completed enrollment required");
    const raw=await request.text();
    if(raw.length>4096)return reject(413,"SCIM configuration too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const value=url.pathname.endsWith("/settings")
        ?await updateScimSettings(env,body,session!.user.id)
        :await changeScimMapping(env,body,session!.user.id);
      return Response.json(value,{headers:{"Cache-Control":"no-store"}});
    }catch(error){
      return reject(409,error instanceof Error&&SCIM_ADMIN_ERRORS.test(error.message)?error.message:"SCIM lifecycle change rejected");
    }
  }

  // NATH-11 review fixes: administrator reviews, keep active / unlink, outbox head and skip.
  // Admin-only with fresh step-up (mayAdminister), same-origin JSON writes, exact confirmation, audited.
  if (url.pathname === "/studio/api/scim/outbox" && request.method === "GET") {
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment incomplete");
    try{return Response.json(await scimOutboxView(env,url.searchParams.get("id")),{headers:{"Cache-Control":"no-store"}})}
    catch(error){return reject(409,error instanceof Error&&SCIM_REVIEW_ERRORS.test(error.message)?error.message:"SCIM outbox unavailable");}
  }
  if (["/studio/api/scim/users","/studio/api/scim/outbox"].includes(url.pathname) && request.method === "POST") {
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Verified administrator with completed enrollment required");
    const raw=await request.text();
    if(raw.length>4096)return reject(413,"SCIM operation too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const value=url.pathname.endsWith("/users")
        ?await scimUserOperation(env,body,session!.user.id)
        :await skipScimOutbox(env,body,session!.user.id);
      return Response.json(value,{headers:{"Cache-Control":"no-store"}});
    }catch(error){
      return reject(409,error instanceof Error&&SCIM_REVIEW_ERRORS.test(error.message)?error.message:"SCIM operation rejected");
    }
  }

  // NATH-13: roles and minimal RBAC (reads and writes need an enrolled, stepped-up administrator).
  if (["/studio/api/rbac","/studio/api/rbac/groups","/studio/api/rbac/group"].includes(url.pathname) && request.method === "GET") {
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment incomplete");
    try{
      const value=url.pathname==="/studio/api/rbac/groups"?await listGroups(env)
        :url.pathname==="/studio/api/rbac/group"?await groupMembers(env,url.searchParams.get("id"))
        :await rbacOverview(env,url.searchParams.get("app"));
      return Response.json(value,{headers:{"Cache-Control":"no-store"}});
    }catch{return reject(404,"Unknown application or group");}
  }
  if (["/studio/api/rbac","/studio/api/directory/clients"].includes(url.pathname) && request.method === "POST") {
    if(request.headers.get("Origin")!==issuer.origin ||
       request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
    if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
      return reject(415,"JSON required");
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment incomplete");
    const raw=await request.text();
    if(raw.length>65536)return reject(413,"Request too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      const value=url.pathname==="/studio/api/directory/clients"
        ?await createDirectoryClient(auth,env,request.headers,body,session!.user.id)
        :await applyRbacOperation(env,body,session!.user.id);
      return Response.json(value,{headers:{"Cache-Control":"no-store"}});
    }catch(error){
      const message=error instanceof Error && /^(Invalid|Unknown|Explicit|Select|User not found|Declare|Too many|Permission keys|Role keys|Group ids|Grant a role|Membership|Description|Application is not registered)/.test(error.message)
        ?error.message:"RBAC change rejected";
      return reject(409,message);
    }
  }

  // NATH-15: Gatekeeper-ready access tokens: audiences, client principal kinds, machine clients.
  if (url.pathname === "/studio/api/tokens" && (request.method === "GET" || request.method === "POST")) {
    if(request.method==="POST"){
      if(request.headers.get("Origin")!==issuer.origin ||
         request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
      if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
        return reject(415,"JSON required");
    }
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment incomplete");
    if(request.method==="GET")return Response.json(await tokenOverview(env),{headers:{"Cache-Control":"no-store"}});
    const raw=await request.text();
    if(raw.length>8192)return reject(413,"Request too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      return Response.json(await applyTokenOperation(auth,env,request.headers,body,session!.user.id),{headers:{"Cache-Control":"no-store"}});
    }catch(error){
      const message=error instanceof Error && /^(Invalid|Unknown|Explicit)/.test(error.message)?error.message:"Token change rejected";
      return reject(409,message);
    }
  }

  // NATH-14: remote MCP servers and their connections (admin + step-up; writes same-origin and audited).
  if (url.pathname === "/studio/api/mcp" && (request.method === "GET" || request.method === "POST")) {
    if(request.method==="POST"){
      if(request.headers.get("Origin")!==issuer.origin ||
         request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
      if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
        return reject(415,"JSON required");
    }
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment incomplete");
    if(request.method==="GET")return Response.json(await mcpOverview(env),{headers:{"Cache-Control":"no-store"}});
    const raw=await request.text();
    if(raw.length>65536)return reject(413,"Request too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      return Response.json(await applyMcpOperation(env,body,session!.user.id),{headers:{"Cache-Control":"no-store"}});
    }catch(error){
      const message=error instanceof Error && /^(Invalid|Unknown|Explicit|Give)/.test(error.message)?error.message:"MCP change rejected";
      return reject(409,message);
    }
  }
  // NATH-16: account admission mode and invitations (admin + step-up; writes same-origin, confirmed and audited).
  if (url.pathname === "/studio/api/admission" && (request.method === "GET" || request.method === "POST")) {
    if(request.method==="POST"){
      if(request.headers.get("Origin")!==issuer.origin ||
         request.headers.get("Sec-Fetch-Site")==="cross-site")return reject(403,"Cross-origin request denied");
      if(request.headers.get("Content-Type")?.split(";")[0]!=="application/json")
        return reject(415,"JSON required");
    }
    const session=await auth.api.getSession({headers:request.headers});
    if(!await isAdminPrincipal(session?.user,env) || !await mayAdminister(env,session!.user.id,session!.session.id))
      return reject(403,"Admin enrollment incomplete");
    if(request.method==="GET")return Response.json(await admissionOverview(env),{headers:{"Cache-Control":"no-store"}});
    const raw=await request.text();
    if(raw.length>4096)return reject(413,"Request too large");
    let body:any;try{body=JSON.parse(raw)}catch{return reject(400,"Invalid JSON")}
    try{
      return Response.json(await applyAdmissionOperation(env,body,session!.user.id),{headers:{"Cache-Control":"no-store"}});
    }catch(error){
      return reject(409,error instanceof Error&&ADMISSION_ERRORS.test(error.message)?error.message:"Admission change rejected");
    }
  }
  const saml=await handleSamlRoutes(request,env,auth,url);
  if(saml)return saml;

  return reject(404, "Not found");
}

export default {
  fetch: (request: Request, env: AuthEnv) => handle(request, env),
  scheduled: async (_: ScheduledEvent,env:AuthEnv) => {
    await env.DB.prepare("DELETE FROM nathan_mcp_limits WHERE expires_at < unixepoch()").run();
    await pruneRbacChanges(env);
    await pruneMcp(env);
    await pruneSamlIdp(env);
    // NATH-11: retry due back-channel logouts (connection Durable Objects also retry their own).
    await deliverLogouts(env,{limit:100}).catch(()=>{});
  }
};

/**
 * App-scoped service binding for gateways and API Workers (see ./app-binding.ts). Each binding pins
 * its application in props ({ applicationId }); every method answers only for that application.
 * Directory reads are not offered here: use the authenticated GET /directory/v1/* API.
 */
/**
 * The user behind a Nathan session cookie. Deliberately a module function, not a NathanVerifier
 * method: every method of a WorkerEntrypoint (TypeScript `private` included) is callable over RPC,
 * and this answer must never reach an app Worker without the per-app access decision.
 */
async function cookieSubject(env: AuthEnv, cookie: unknown): Promise<string | null> {
  if (typeof cookie !== "string" || cookie.length > 8192) return null;
  const auth = createAuth(env, await loadSocialCredentials(env));
  const session = await auth.api.getSession({ headers: new Headers({ Cookie: cookie }) });
  return typeof session?.user?.id === "string" ? session.user.id : null;
}

export class NathanVerifier extends WorkerEntrypoint<AuthEnv, BindingProps> {
  /**
   * NATH-18: the signed-in user behind a Nathan session cookie, for the binding's pinned application
   * only. Returns null unless the evaluator allows that user for that application, so an app Worker
   * holding a cookie learns nothing about people who may not use it. The global Better Auth role is
   * never returned: use `roles`/`permissions`, which are the app's own.
   */
  async getPrincipal(cookie: string): Promise<{ sub: string; email: string | null; applicationId: string; roles: string[]; permissions: string[] } | null> {
    const scope = scopedApplication(this.ctx.props, undefined);
    if (!scope.ok) return null;
    const sub = await cookieSubject(this.env, cookie);
    if (!sub) return null;
    const decision = await resolveAccess(this.env, scope.app, sub);
    if (!decision.allowed) return null;
    return { sub, email: decision.email, applicationId: scope.app, roles: decision.roles, permissions: decision.permissions };
  }
  /** Cookie-based check for Workers that hold a Nathan session cookie. Same evaluator as every other path. */
  async authorize(input: { applicationId?: string; cookie: string }): Promise<boolean> {
    return (await this.access(input)).allowed;
  }
  /** The access decision for a cookie's user; `sub` only when allowed (NATH-18). */
  async access(input: { applicationId?: string; cookie: string }) {
    const scope = scopedApplication(this.ctx.props, input?.applicationId);
    if (!scope.ok) return { ...outOfScope(scope.reason), sub: null };
    const sub = await cookieSubject(this.env, input?.cookie);
    const decision = await resolveAccess(this.env, scope.app, sub);
    return { ...decision, sub: decision.allowed ? sub : null };
  }
  /**
   * NATH-13 gateway and SDK path: effective roles and permissions of an OIDC subject for the pinned
   * app. Subjects are Nathan user ids (public subject type); a pairwise subject resolves to no user
   * and is denied. `applicationId`, when given, must equal the pinned application.
   */
  async resolveAccess(input: { applicationId?: string; subject: string }) {
    const scope = scopedApplication(this.ctx.props, input?.applicationId);
    if (!scope.ok) return outOfScope(scope.reason);
    return resolveAccess(this.env, scope.app, input?.subject);
  }
  /**
   * NATH-14 grant check for remote MCP servers (the SDK's nathanMcp()): verifies the access token,
   * and returns the scopes it may use now = token ∩ live grant ∩ the user's current permissions.
   * Like every call here it is app-scoped: only resources of the pinned application are answered.
   */
  async mcpGrant(input: { token: string; resource: string }) {
    const scope = scopedApplication(this.ctx.props, undefined);
    if (!scope.ok || !input || typeof input.token !== "string" || typeof input.resource !== "string") return { active: false };
    return mcpGrantStatus(this.env, createAuth(this.env, await loadSocialCredentials(this.env)), input.token, input.resource, scope.app);
  }
}
