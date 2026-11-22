/**
 * NATH-12: Nathan as a SAML 2.0 identity provider for downstream service providers (AWS IAM
 * Identity Center, Salesforce, Grafana, any SAML SP). Protocol code is in ./saml-idp-protocol.mjs,
 * keys in ./saml-idp-keys.mjs, pages in ./saml-idp-ui.mjs. Routes:
 *
 *   GET  /saml/idp, /saml/idp/metadata  IdP metadata (entityID https://<host>/saml/idp)
 *   GET  /saml/idp/sso                  SP-initiated AuthnRequest, HTTP-Redirect binding
 *   POST /saml/idp/sso                  SP-initiated AuthnRequest, HTTP-POST binding
 *   GET  /saml/idp/continue             issue the Response once the browser has a Nathan session
 *   GET/POST /saml/idp/start/<sp>       IdP-initiated sign-in (per-SP opt-in, same-origin POST)
 *   GET/POST /studio/api/saml-idp       Identity Studio (admin + step-up, confirmed, audited)
 *
 * Flow: the SSO endpoint validates the request completely (one strict parser, registered and
 * enabled SP, exact ACS, signature when required, freshness, single-use request ID), stores it as a
 * pending request and sets a signed single-use handle in a __Host- cookie, then redirects to
 * /saml/idp/continue. That top-level GET carries the Lax session cookie even when the SP posted
 * cross-site. Without a session the browser signs in and Nathan's "/" sends it back here. The
 * Response is issued only after the bound application's access decision (NATH-13, deny by
 * default), ban, SCIM and admission state, and the SP's passkey requirement (verified evidence only).
 * Every SP change and every issued or denied assertion is audited (SP, user, outcome; never content).
 */
import type { AuthEnv } from "./env";
import { audit, isAdminPrincipal } from "./admin-service";
import { mayAdminister } from "./bootstrap";
import { resolveAccess } from "./rbac";
import { isAppId } from "../shared/policy.mjs";
import { userBanned, timestampMs } from "../shared/token-claims.mjs";
import { makeCookie, parseCookie, redirectWithCookies, constantTimeEqual } from "../shared/security.mjs";
import { sealConfigSecret, openConfigSecret } from "./config-crypto.mjs";
import { fetchIdpMetadata } from "./saml-metadata.mjs";
import { readBoundedText } from "./bounded-body.mjs";
import { generateSigningKey, importSigningKey, KEY_SIZES } from "./saml-idp-keys.mjs";
import {
  SamlRequestError, idpValues, parseBindingParameters, REDIRECT_PARAMETERS, POST_PARAMETERS, decodeRedirectRequest, decodePostRequest,
  checkRelayState, parseAuthnRequest, verifyRedirectSignature, verifyPostSignature, buildSignedResponse, buildIdpMetadata,
  validateServiceProvider, parseSpMetadata, NAMEID, AC_PASSKEY, AC_UNSPECIFIED, MAX_QUERY_BYTES, MAX_FORM_BYTES, SP_ID
} from "./saml-idp-protocol.mjs";
import { autoPostPage, idpErrorPage, idpInitiatedPage } from "./saml-idp-ui.mjs";

const RESUME_COOKIE = "__Host-nathan-saml-idp";
const PENDING_SECONDS = 600;
const REPLAY_SECONDS = 900;
/** A next key must be published this long before it may sign (SPs cache metadata). */
export const ROTATION_OVERLAP_SECONDS = 86400;
const noStore = { "Cache-Control": "no-store" };
const STUDIO_MAX_BYTES = 160_000;

type Attribute = { name: string; source: string };
type Certificate = { der: string; sha256: string; notAfter: string };
type ServiceProvider = {
  id: string; name: string; entityId: string; appId: string; acsUrls: string[]; nameIdFormat: "persistent" | "email";
  attributes: Attribute[]; wantRequestsSigned: boolean; certificates: Certificate[]; signResponse: boolean;
  requirePasskey: boolean; allowIdpInitiated: boolean; defaultRelayState: string | null; enabled: boolean;
  createdBy: string; createdAt: number; updatedBy: string; updatedAt: number;
};
type KeyRow = { id: string; status: string; bits: number; certificate: string; sha256: string; not_before: string; not_after: string;
  private_key: string | null; created_by: string; created_at: number; activated_at: number | null; retired_at: number | null };

const origin = (env: AuthEnv) => new URL(env.NATHAN_ISSUER).origin;
const enc = new TextEncoder();
const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function sha256Hex(text: string) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)))].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hmac(env: AuthEnv, message: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(env.BETTER_AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode("nathan:saml-idp:resume:v1:" + message))));
}

function spFrom(row: any): ServiceProvider {
  return {
    id: row.id, name: row.name, entityId: row.entity_id, appId: row.app_id, acsUrls: JSON.parse(row.acs_urls),
    nameIdFormat: row.name_id_format, attributes: JSON.parse(row.attributes), wantRequestsSigned: row.want_requests_signed === 1,
    certificates: JSON.parse(row.certificates), signResponse: row.sign_response === 1, requirePasskey: row.require_passkey === 1,
    allowIdpInitiated: row.allow_idp_initiated === 1, defaultRelayState: row.default_relay_state ?? null, enabled: row.enabled === 1,
    createdBy: row.created_by, createdAt: row.created_at, updatedBy: row.updated_by, updatedAt: row.updated_at
  };
}
async function loadSp(env: AuthEnv, by: { id?: string; entityId?: string }): Promise<ServiceProvider | null> {
  const row = by.id !== undefined
    ? await env.DB.prepare("SELECT * FROM nathan_saml_service_providers WHERE id=? LIMIT 1").bind(by.id).first()
    : await env.DB.prepare("SELECT * FROM nathan_saml_service_providers WHERE entity_id=? LIMIT 1").bind(by.entityId).first();
  return row ? spFrom(row) : null;
}
async function publishedKeys(env: AuthEnv) {
  const rows = await env.DB.prepare("SELECT * FROM nathan_saml_idp_keys WHERE status IN ('active','next','previous') " +
    "ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'next' THEN 1 ELSE 2 END").all<KeyRow>();
  return rows.results;
}

/** Fixed-window limit in nathan_mcp_limits (migration 0004); keys hold hashes, never raw IPs. */
async function allow(env: AuthEnv, name: string, subject: string, limit: number) {
  const bucket = Math.floor(Date.now() / 60_000);
  const key = "saml-idp:" + name + ":" + (await sha256Hex(subject)).slice(0, 22) + ":" + bucket;
  const row = await env.DB.prepare("INSERT INTO nathan_mcp_limits(id,request_count,expires_at) VALUES (?,1,?) " +
    "ON CONFLICT(id) DO UPDATE SET request_count=request_count+1 RETURNING request_count").bind(key, (bucket + 2) * 60).first<{ request_count: number }>();
  return Boolean(row && row.request_count <= limit);
}

/**
 * A refused AuthnRequest: SP (or "unknown") and the refusal code only, never the message. The row id
 * is deterministic per SP, code and minute, so an unauthenticated flood writes one row per minute.
 */
async function auditRejection(env: AuthEnv, spId: string, code: string) {
  const minute = Math.floor(Date.now() / 60_000);
  await env.DB.prepare("INSERT OR IGNORE INTO nathan_security_audit (id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
    .bind("saml-idp-rejected:" + spId + ":" + code + ":" + minute, "anonymous", "saml_idp_request_rejected", spId + ":" + code, "rejected").run();
}

// ---- metadata ------------------------------------------------------------------------------------

async function metadata(env: AuthEnv) {
  const keys = await publishedKeys(env);
  if (!keys.some(k => k.status === "active"))
    return Response.json({ error: "The SAML identity provider has no signing key yet" }, { status: 404, headers: noStore });
  const values = idpValues(env.NATHAN_ISSUER);
  return new Response(buildIdpMetadata({ entityId: values.entityId, ssoUrl: values.ssoUrl, certificates: keys.map(k => k.certificate) }), {
    headers: { "Content-Type": "application/samlmetadata+xml; charset=utf-8", "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff" }
  });
}

// ---- SP-initiated SSO ----------------------------------------------------------------------------

const fail = (code: string, message: string, status?: number): never => { throw new SamlRequestError(code, message, status); };
/** Every page that refuses a sign-in names Nathan's reason code (the same code the audit log uses). */
const refusal = (title: string, message: string, code: string, options: { status?: number; signIn?: boolean } = {}) =>
  idpErrorPage(title, message + " (" + code + ")", options);

async function sso(request: Request, env: AuthEnv, url: URL): Promise<Response> {
  if (!await allow(env, "sso", request.headers.get("cf-connecting-ip") ?? "unknown", 120))
    return refusal("Too many sign-in requests", "Wait a minute and start the sign-in again from the application.", "saml_rate_limited", { status: 429 });
  let spId = "unknown";
  try {
    let params: Map<string, { raw: string; value: string }>, binding: "redirect" | "post";
    if (request.method === "GET") {
      // Only POST may carry a body (inbound lesson: a body on GET would bypass inspection).
      if (request.body !== null) fail("saml_body_not_allowed", "SAML messages in a request body must use POST");
      if (url.search.length > MAX_QUERY_BYTES) fail("saml_unreadable", "SAML request is too large", 414);
      params = parseBindingParameters(url.search.slice(1), REDIRECT_PARAMETERS);
      binding = "redirect";
    } else if (request.method === "POST") {
      if (url.search) fail("saml_unknown_parameter", "The HTTP-POST binding carries no query parameters");
      if (request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== "application/x-www-form-urlencoded")
        fail("saml_form_required", "SAML messages must use the form-encoded HTTP-POST binding", 415);
      const raw = await readBoundedText(request, MAX_FORM_BYTES);
      if (raw === null) return fail("saml_unreadable", "SAML request is too large", 413);
      params = parseBindingParameters(raw, POST_PARAMETERS);
      binding = "post";
    } else {
      return refusal("Method not allowed", "Use the HTTP-Redirect or HTTP-POST binding.", "saml_method_not_allowed", { status: 405 });
    }
    const message = params.get("SAMLRequest");
    if (!message) return fail("saml_missing_request", "SAML message rejected: exactly one SAMLRequest is required");
    if (params.has("SigAlg") !== params.has("Signature")) fail("saml_bad_signature", "SigAlg and Signature must be sent together");
    const relayState = checkRelayState(params.get("RelayState")?.value ?? null);
    const xml = binding === "redirect" ? await decodeRedirectRequest(message.value) : decodePostRequest(message.value);
    const outer = parseAuthnRequest(xml);
    const sp = await loadSp(env, { entityId: outer.issuer });
    if (!sp) return fail("saml_unknown_sp", "This application is not registered with Nathan", 404);
    spId = sp.id;
    if (!sp.enabled) fail("saml_sp_disabled", "Sign-in to this application is disabled", 403);
    const certificates = sp.certificates.map(c => c.der);
    let parsed = outer;
    if (binding === "redirect") {
      // The binding forbids an enveloped signature inside a DEFLATE-encoded message.
      if (outer.signed) fail("saml_invalid_request", "HTTP-Redirect messages are signed in the query, not in the XML");
      if (params.has("Signature") && certificates.length) {
        if (!await verifyRedirectSignature(params, certificates)) fail("saml_bad_signature", "The AuthnRequest signature is invalid");
      } else if (sp.wantRequestsSigned) fail("saml_signature_required", "This application must sign its AuthnRequests");
    } else if (outer.signed && certificates.length) {
      const signed = verifyPostSignature(xml, certificates);
      if (!signed) return fail("saml_bad_signature", "The AuthnRequest signature is invalid");
      // Process only the bytes the signature covers.
      parsed = parseAuthnRequest(signed);
      if (parsed.id !== outer.id || parsed.issuer !== outer.issuer) fail("saml_bad_signature", "The AuthnRequest signature does not cover this request");
    } else if (sp.wantRequestsSigned) fail("saml_signature_required", "This application must sign its AuthnRequests");
    const ssoUrl = idpValues(env.NATHAN_ISSUER).ssoUrl;
    if (parsed.destination !== null && parsed.destination !== ssoUrl) fail("saml_destination_mismatch", "The AuthnRequest is addressed to another identity provider");
    if (sp.wantRequestsSigned && parsed.destination === null) fail("saml_destination_mismatch", "Signed AuthnRequests must name Nathan's SSO URL as Destination");
    let acsUrl: string;
    if (parsed.acsUrl !== null) {
      if (!sp.acsUrls.includes(parsed.acsUrl)) fail("saml_acs_mismatch", "The AssertionConsumerServiceURL is not registered for this application");
      acsUrl = parsed.acsUrl;
    } else if (parsed.acsIndex !== null) {
      const indexed = sp.acsUrls[parsed.acsIndex];
      if (!indexed) return fail("saml_acs_mismatch", "The AssertionConsumerServiceIndex is not registered for this application");
      acsUrl = indexed;
    } else acsUrl = sp.acsUrls[0];
    // NameIDPolicy is not honoured: the administrator's NameID choice for this SP is authoritative, so an
    // SP cannot ask for an email address where the administrator chose a pairwise identifier.
    const replay = await env.DB.prepare("INSERT INTO nathan_saml_idp_request_ids(sp_id,request_id,expires_at) VALUES (?,?,unixepoch()+?) ON CONFLICT DO NOTHING")
      .bind(sp.id, parsed.id, REPLAY_SECONDS).run();
    if (replay.meta.changes !== 1) fail("saml_replayed_request", "This sign-in request was already used; start again from the application");
    const handle = b64url(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare("INSERT INTO nathan_saml_idp_pending(id_hash,sp_id,request_id,acs_url,relay_state,force_authn,is_passive,expires_at) " +
      "VALUES (?,?,?,?,?,?,?,unixepoch()+?)")
      .bind(await sha256Hex(handle), sp.id, parsed.id, acsUrl, relayState, parsed.forceAuthn ? 1 : 0, parsed.isPassive ? 1 : 0, PENDING_SECONDS).run();
    return redirectWithCookies(origin(env) + "/saml/idp/continue", 303,
      [makeCookie(RESUME_COOKIE, handle + await hmac(env, handle), { maxAge: PENDING_SECONDS })]);
  } catch (e) {
    if (!(e instanceof SamlRequestError)) throw e;
    await auditRejection(env, spId, e.code);
    return refusal("Sign-in request refused", e.message, e.code, { status: e.status });
  }
}

/**
 * The pending-request handle from the resume cookie, only when its HMAC verifies; otherwise the
 * reason: no cookie, or a cookie that is malformed, of the wrong length or not signed by Nathan.
 */
async function resumeHandle(env: AuthEnv, request: Request): Promise<{ handle: string } | { error: "saml_resume_missing" | "saml_resume_invalid" }> {
  const value = parseCookie(request.headers.get("Cookie"), RESUME_COOKIE);
  if (!value) return { error: "saml_resume_missing" };
  if (!/^[A-Za-z0-9_-]{86}$/.test(value)) return { error: "saml_resume_invalid" };
  const handle = value.slice(0, 43);
  return constantTimeEqual(value.slice(43), await hmac(env, handle)) ? { handle } : { error: "saml_resume_invalid" };
}
const clearResume = () => makeCookie(RESUME_COOKIE, "", { deleteCookie: true });
function withClearedResume(response: Response) { response.headers.append("Set-Cookie", clearResume()); return response; }

/** After any sign-in Nathan lands on "/": continue a pending SAML request if this browser has one. */
export async function samlIdpReturnRedirect(request: Request, env: AuthEnv): Promise<Response | null> {
  return "handle" in await resumeHandle(env, request) ? redirectWithCookies(origin(env) + "/saml/idp/continue", 302) : null;
}

async function continueSso(request: Request, env: AuthEnv, auth: any): Promise<Response> {
  const resume = await resumeHandle(env, request);
  const expired = (code: string) => withClearedResume(refusal("Sign-in expired",
    "This sign-in request expired or was already used. Start again from the application.", code, { status: 400 }));
  if (!("handle" in resume)) return expired(resume.error);
  const idHash = await sha256Hex(resume.handle);
  const row = await env.DB.prepare("SELECT *, expires_at>unixepoch() AS live FROM nathan_saml_idp_pending WHERE id_hash=? LIMIT 1").bind(idHash).first<any>();
  if (!row || row.used === 1 || row.live !== 1) return expired(!row || row.used !== 1 ? "saml_resume_expired" : "saml_resume_used");
  const pending = row;
  const consume = async () => (await env.DB.prepare("UPDATE nathan_saml_idp_pending SET used=1 WHERE id_hash=? AND used=0 AND expires_at>unixepoch()")
    .bind(idHash).run()).meta.changes === 1;
  const session = await auth.api.getSession({ headers: request.headers });
  const userId: string | null = typeof session?.user?.id === "string" ? session.user.id : null;
  // ForceAuthn: only a session created after the request counts (unixepoch() has second precision).
  const fresh = userId !== null && (pending.force_authn !== 1 || timestampMs(session.session.createdAt) >= (pending.created_at - 1) * 1000);
  if (!fresh) {
    if (pending.is_passive === 1) {
      await consume();
      await audit(env, userId ?? "anonymous", "saml_idp_assertion", pending.sp_id, "denied:passive_requires_sign_in");
      return withClearedResume(refusal("Sign-in required", "The application asked Nathan not to interact with you, but you need to sign in. Start again from the application.",
        "saml_passive_requires_sign_in"));
    }
    return redirectWithCookies(origin(env) + "/sign-in", 302);
  }
  const sp = await loadSp(env, { id: pending.sp_id });
  if (sp?.requirePasskey && !await passkeyEvidence(env, userId!, session.session.id))
    return refusal("Passkey sign-in required", sp.name + " requires a sign-in with your passkey. Sign in to Nathan with your passkey to continue.",
      "saml_passkey_required", { signIn: true });
  if (!await consume()) return expired("saml_resume_used");
  return withClearedResume(await issue(env, { sp, userId: userId!, sessionId: session.session.id, sessionCreatedAt: timestampMs(session.session.createdAt),
    requestId: pending.request_id, acsUrl: pending.acs_url, relayState: pending.relay_state ?? null, spId: pending.sp_id }));
}

async function passkeyEvidence(env: AuthEnv, userId: string, sessionId: string) {
  return env.DB.prepare("SELECT verified_at FROM nathan_admin_assurance WHERE session_id=? AND user_id=? AND method='passkey' LIMIT 1")
    .bind(sessionId, userId).first<{ verified_at: number }>();
}

/**
 * Issues a signed Response after every check, or a Nathan error page (nothing goes to the SP).
 * Audited either way: SP, user and outcome, never assertion content.
 */
async function issue(env: AuthEnv, ctx: { sp: ServiceProvider | null; spId: string; userId: string; sessionId: string; sessionCreatedAt: number;
  requestId: string | null; acsUrl: string; relayState: string | null }): Promise<Response> {
  const { sp, userId } = ctx;
  const deny = async (reason: string, title: string, message: string, status = 403) => {
    await audit(env, userId, "saml_idp_assertion", ctx.spId, "denied:" + reason);
    return refusal(title, message, "saml_" + reason.split(":")[0], { status });
  };
  if (!sp || !sp.enabled) return deny("sp_unavailable", "Application unavailable", "Sign-in to this application is disabled.");
  if (!sp.acsUrls.includes(ctx.acsUrl)) return deny("acs_changed", "Application changed", "This application's configuration changed during sign-in. Start again.");
  const [users, scim, pendingAdmission, evidence] = (await env.DB.batch([
    env.DB.prepare('SELECT "id" AS id, "email" AS email, "emailVerified" AS emailVerified, "name" AS name, "banned" AS banned, "banExpires" AS banExpires FROM "user" WHERE "id"=? LIMIT 1').bind(userId),
    env.DB.prepare("SELECT 1 AS x FROM nathan_scim_users WHERE user_id=? AND link_state='deprovisioned' AND override_cause IS NULL LIMIT 1").bind(userId),
    env.DB.prepare("SELECT 1 AS x FROM nathan_admission_pending WHERE user_id=? LIMIT 1").bind(userId),
    env.DB.prepare("SELECT verified_at FROM nathan_admin_assurance WHERE session_id=? AND user_id=? AND method='passkey' LIMIT 1").bind(ctx.sessionId, userId)
  ])).map(r => (r.results ?? []) as any[]);
  const user = users[0];
  if (!user) return deny("unknown_user", "Account unavailable", "Your Nathan account is not available.");
  if (userBanned(user)) return deny("user_blocked", "Account blocked", "This account is blocked. Contact your administrator.");
  if (scim.length) return deny("deprovisioned", "Account deactivated", "Your organization's directory has deactivated this account.");
  if (pendingAdmission.length) return deny("not_admitted", "Account not admitted", "This account has not been admitted yet. Verify your email address or ask an administrator for an invitation.");
  if (Number(user.emailVerified) !== 1) return deny("email_unverified", "Email not verified", "Verify your email address before signing in to applications.");
  const access = await resolveAccess(env, sp.appId, userId);
  if (!access.allowed) return deny("no_access:" + access.reason, "Access denied", "You do not have access to " + sp.name + ". Ask an administrator for access.");
  const passkey = evidence[0];
  if (sp.requirePasskey && !passkey) return deny("passkey_required", "Passkey sign-in required", sp.name + " requires a sign-in with your passkey.");
  const key = await env.DB.prepare("SELECT * FROM nathan_saml_idp_keys WHERE status='active' LIMIT 1").first<KeyRow>();
  if (!key?.private_key || !env.NATHAN_CONFIG_KEY) return deny("no_signing_key", "Sign-in unavailable", "Nathan has no SAML signing key configured.", 503);
  let signingKey: CryptoKey;
  try { signingKey = await importSigningKey(await openConfigSecret("saml-idp-key:v1:" + key.id, key.private_key, env.NATHAN_CONFIG_KEY)); }
  catch { return deny("signing_key_unusable", "Sign-in unavailable", "Nathan's SAML signing key cannot be used.", 503); }

  const subject = sp.nameIdFormat === "persistent" || sp.attributes.some(a => a.source === "persistent_id") ? await pairwiseSubject(env, sp.id, userId) : null;
  const groups = sp.attributes.some(a => a.source === "groups") ? await appGroups(env, sp.appId, userId) : [];
  const values: Record<string, string[]> = {
    email: [user.email], name: typeof user.name === "string" && user.name.trim() ? [user.name] : [],
    roles: access.roles, permissions: access.permissions, groups, persistent_id: subject ? [subject] : []
  };
  const attributes = sp.attributes.map(a => ({ name: a.name, values: Object.hasOwn(values, a.source) ? values[a.source] : [] }));
  const idp = idpValues(env.NATHAN_ISSUER);
  const { response } = await buildSignedResponse({
    idpEntityId: idp.entityId, spEntityId: sp.entityId, acsUrl: ctx.acsUrl, inResponseTo: ctx.requestId,
    nameId: sp.nameIdFormat === "email" ? { format: NAMEID.email, value: user.email } : { format: NAMEID.persistent, value: subject! },
    attributes,
    // AuthnContextClassRef only from verified evidence: a passkey assertion for this session, else "unspecified".
    authnInstant: passkey ? passkey.verified_at * 1000 : (Number.isFinite(ctx.sessionCreatedAt) ? ctx.sessionCreatedAt : Date.now()),
    authnContext: passkey ? AC_PASSKEY : AC_UNSPECIFIED,
    signResponse: sp.signResponse, key: signingKey, certificate: key.certificate
  });
  await audit(env, userId, "saml_idp_assertion", sp.id, ctx.requestId ? "issued" : "issued:idp_initiated");
  return autoPostPage({ acsUrl: ctx.acsUrl, samlResponse: response, relayState: ctx.relayState, spName: sp.name });
}

/** Random opaque persistent NameID, one per (SP, user), created on first use. */
async function pairwiseSubject(env: AuthEnv, spId: string, userId: string): Promise<string> {
  await env.DB.prepare("INSERT INTO nathan_saml_idp_subjects(sp_id,user_id,name_id) VALUES (?,?,?) ON CONFLICT(sp_id,user_id) DO NOTHING")
    .bind(spId, userId, b64url(crypto.getRandomValues(new Uint8Array(24)))).run();
  const row = await env.DB.prepare("SELECT name_id FROM nathan_saml_idp_subjects WHERE sp_id=? AND user_id=?").bind(spId, userId).first<{ name_id: string }>();
  if (!row) throw Error("Pairwise subject unavailable");
  return row.name_id;
}
/** Only the user's groups that hold a role in the bound application (no unrelated group names leak). */
async function appGroups(env: AuthEnv, appId: string, userId: string): Promise<string[]> {
  const rows = await env.DB.prepare("SELECT DISTINCT g.principal_id AS id FROM nathan_rbac_grants g JOIN nathan_group_members m ON m.group_id=g.principal_id " +
    "WHERE g.app_id=? AND g.principal_type='group' AND m.user_id=? ORDER BY g.principal_id LIMIT 100").bind(appId, userId).all<{ id: string }>();
  return rows.results.map(r => r.id);
}

// ---- IdP-initiated SSO ----------------------------------------------------------------------------

async function idpInitiated(request: Request, env: AuthEnv, auth: any, spId: string): Promise<Response> {
  const sp = await loadSp(env, { id: spId });
  if (!sp || !sp.enabled || !sp.allowIdpInitiated)
    return refusal("Not available", "IdP-initiated sign-in is not enabled for this application.", "saml_idp_initiated_unavailable", { status: 404 });
  if (request.method === "POST" && (request.headers.get("Origin") !== origin(env) || request.headers.get("Sec-Fetch-Site") === "cross-site"))
    return refusal("Request refused", "IdP-initiated sign-in must be confirmed on Nathan's own page.", "saml_cross_site_request", { status: 403 });
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session?.user?.id) return refusal("Sign in first", "Sign in to Nathan, then open this link again.", "saml_sign_in_required", { status: 401, signIn: true });
  if (request.method === "GET") return idpInitiatedPage({ spId: sp.id, spName: sp.name, email: session.user.email ?? "" });
  if (request.method !== "POST") return refusal("Method not allowed", "Use the confirmation page.", "saml_method_not_allowed", { status: 405 });
  if (sp.requirePasskey && !await passkeyEvidence(env, session.user.id, session.session.id))
    return refusal("Passkey sign-in required", sp.name + " requires a sign-in with your passkey.", "saml_passkey_required", { signIn: true });
  return issue(env, { sp, spId: sp.id, userId: session.user.id, sessionId: session.session.id, sessionCreatedAt: timestampMs(session.session.createdAt),
    requestId: null, acsUrl: sp.acsUrls[0], relayState: sp.defaultRelayState });
}

// ---- Identity Studio -----------------------------------------------------------------------------

function presentSp(sp: ServiceProvider, env: AuthEnv) {
  return { ...sp, certificates: sp.certificates.map(({ sha256, notAfter }) => ({ sha256, notAfter })),
    idpInitiatedUrl: sp.allowIdpInitiated ? origin(env) + "/saml/idp/start/" + sp.id : null };
}
function presentKey(k: KeyRow) {
  return { id: k.id, status: k.status, bits: k.bits, sha256: k.sha256, notBefore: k.not_before, notAfter: k.not_after,
    createdBy: k.created_by, createdAt: k.created_at, activatedAt: k.activated_at, retiredAt: k.retired_at,
    ...(k.status === "next" ? { activatableAt: k.created_at + ROTATION_OVERLAP_SECONDS } : {}) };
}
export async function samlIdpOverview(env: AuthEnv) {
  const [keys, sps] = await Promise.all([
    env.DB.prepare("SELECT * FROM nathan_saml_idp_keys ORDER BY created_at DESC, rowid DESC LIMIT 20").all<KeyRow>(),
    env.DB.prepare("SELECT * FROM nathan_saml_service_providers ORDER BY id LIMIT 200").all()
  ]);
  const warnings: string[] = [];
  if (!keys.results.some(k => k.status === "active")) warnings.push("No active signing key: generate one before enabling service providers.");
  if (!env.NATHAN_CONFIG_KEY) warnings.push("NATHAN_CONFIG_KEY is not configured; signing keys cannot be generated or used.");
  for (const k of keys.results) {
    const days = Math.floor((Date.parse(k.not_after) - Date.now()) / 86400e3);
    if (k.status === "active" && days < 60) warnings.push("The active signing certificate expires in " + days + " days: generate the next key now.");
  }
  return { idp: idpValues(env.NATHAN_ISSUER), keys: keys.results.map(presentKey), serviceProviders: sps.results.map(r => presentSp(spFrom(r), env)), warnings };
}

class AdminRefusal extends Error {}
const refuseAdmin = (message: string): never => { throw new AdminRefusal(message); };
async function audited<T>(env: AuthEnv, actor: string, action: string, target: string, fn: () => Promise<T>): Promise<T> {
  await audit(env, actor, action, target, "attempted");
  try { const value = await fn(); await audit(env, actor, action, target, "succeeded"); return value; }
  catch (e) { await audit(env, actor, action, target, "failed").catch(() => {}); throw e; }
}
const confirmed = (body: any, text: string) => { if (body?.confirm !== text) refuseAdmin("Explicit confirmation required: type " + text); };
function metadataSource(body: any) {
  if (typeof body?.metadataXml === "string" && body.metadataXml.trim()) return "pasted";
  try { return new URL(String(body?.metadataUrl ?? "")).hostname.toLowerCase().slice(0, 253) || "none"; } catch { return "invalid-url"; }
}

async function validated(env: AuthEnv, body: any) {
  const sp = await validateServiceProvider(body, { idpEntityId: idpValues(env.NATHAN_ISSUER).entityId, isAppId });
  if (!await env.DB.prepare("SELECT id FROM nathan_applications WHERE id=?").bind(sp.appId).first())
    refuseAdmin("Unknown application: register the application under Protected applications first");
  return sp;
}
const spColumns = (sp: Awaited<ReturnType<typeof validated>>) => [sp.name, sp.entityId, sp.appId, JSON.stringify(sp.acsUrls), sp.nameIdFormat,
  JSON.stringify(sp.attributes), sp.wantRequestsSigned ? 1 : 0, JSON.stringify(sp.certificates), sp.signResponse ? 1 : 0, sp.requirePasskey ? 1 : 0,
  sp.allowIdpInitiated ? 1 : 0, sp.defaultRelayState];

export async function applySamlIdpOperation(env: AuthEnv, body: any, actor: string) {
  const op = body?.op;
  if (op === "sp.preview") {
    const source = metadataSource(body);
    return audited(env, actor, "saml_idp_sp_metadata_preview", source, async () => {
      let xml: string;
      if (typeof body.metadataXml === "string" && body.metadataXml.trim()) xml = body.metadataXml;
      else if (typeof body.metadataUrl === "string" && body.metadataUrl.trim()) {
        try { xml = await fetchIdpMetadata(body.metadataUrl.trim()); }
        catch (e) { return refuseAdmin(String((e as Error).message).replace(/IdP metadata/g, "SP metadata").slice(0, 300)); }
      } else return refuseAdmin("Paste the SP metadata XML or give its HTTPS metadata URL");
      return parseSpMetadata(xml);
    });
  }
  if (op === "sp.create" || op === "sp.update") {
    const id = typeof body.id === "string" && SP_ID.test(body.id) ? body.id : refuseAdmin("Invalid SP ID: lowercase letters, digits and dashes");
    confirmed(body, (op === "sp.create" ? "CONFIRM CREATE SAML SP " : "CONFIRM UPDATE SAML SP ") + id);
    return audited(env, actor, op === "sp.create" ? "saml_idp_sp_create" : "saml_idp_sp_update", id, async () => {
      const sp = await validated(env, body);
      const clash = await env.DB.prepare("SELECT id FROM nathan_saml_service_providers WHERE entity_id=? AND id<>? LIMIT 1").bind(sp.entityId, id).first();
      if (clash) refuseAdmin("Another service provider already uses this entity ID");
      if (op === "sp.create") {
        if (await loadSp(env, { id })) refuseAdmin("A service provider with this ID already exists");
        await env.DB.prepare("INSERT INTO nathan_saml_service_providers(id,name,entity_id,app_id,acs_urls,name_id_format,attributes,want_requests_signed," +
          "certificates,sign_response,require_passkey,allow_idp_initiated,default_relay_state,enabled,created_by,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)")
          .bind(id, ...spColumns(sp), actor, actor).run();
      } else {
        const r = await env.DB.prepare("UPDATE nathan_saml_service_providers SET name=?,entity_id=?,app_id=?,acs_urls=?,name_id_format=?,attributes=?," +
          "want_requests_signed=?,certificates=?,sign_response=?,require_passkey=?,allow_idp_initiated=?,default_relay_state=?,updated_by=?,updated_at=unixepoch() WHERE id=?")
          .bind(...spColumns(sp), actor, id).run();
        if (r.meta.changes !== 1) refuseAdmin("Unknown service provider");
      }
      return presentSp((await loadSp(env, { id }))!, env);
    });
  }
  if (op === "sp.status") {
    const id = typeof body.id === "string" && SP_ID.test(body.id) ? body.id : refuseAdmin("Invalid SP ID");
    if (typeof body.enabled !== "boolean") refuseAdmin("Invalid status: enabled must be true or false");
    confirmed(body, (body.enabled ? "CONFIRM ENABLE SAML SP " : "CONFIRM DISABLE SAML SP ") + id);
    return audited(env, actor, body.enabled ? "saml_idp_sp_enable" : "saml_idp_sp_disable", id, async () => {
      const r = await env.DB.prepare("UPDATE nathan_saml_service_providers SET enabled=?,updated_by=?,updated_at=unixepoch() WHERE id=?")
        .bind(body.enabled ? 1 : 0, actor, id).run();
      if (r.meta.changes !== 1) refuseAdmin("Unknown service provider");
      return presentSp((await loadSp(env, { id }))!, env);
    });
  }
  if (op === "key.generate") {
    confirmed(body, "CONFIRM GENERATE SAML IDP KEY");
    const bits = body.bits === undefined ? 2048 : body.bits;
    if (!KEY_SIZES.includes(bits)) refuseAdmin("Key size must be 2048, 3072 or 4096 bits");
    return audited(env, actor, "saml_idp_key_generate", String(bits), async () => {
      if (!env.NATHAN_CONFIG_KEY) refuseAdmin("NATHAN_CONFIG_KEY is not configured; signing keys cannot be stored");
      const statuses = (await publishedKeys(env)).map(k => k.status);
      if (statuses.includes("next")) refuseAdmin("A next key is already published; activate or retire it first");
      const status = statuses.includes("active") ? "next" : "active";
      const id = crypto.randomUUID();
      const generated = await generateSigningKey({ bits, subject: ("Nathan SAML IdP " + new URL(env.NATHAN_ISSUER).hostname).slice(0, 64) });
      const sealed = await sealConfigSecret("saml-idp-key:v1:" + id, generated.pkcs8, env.NATHAN_CONFIG_KEY!);
      try {
        await env.DB.prepare("INSERT INTO nathan_saml_idp_keys(id,status,bits,certificate,sha256,not_before,not_after,private_key,created_by,activated_at) " +
          "VALUES (?,?,?,?,?,?,?,?,?,CASE WHEN ?='active' THEN unixepoch() END)")
          .bind(id, status, generated.bits, generated.certificate, generated.sha256, generated.notBefore, generated.notAfter, sealed, actor, status).run();
      } catch { refuseAdmin("Another key was generated concurrently; reload and try again"); }
      const row = await env.DB.prepare("SELECT * FROM nathan_saml_idp_keys WHERE id=?").bind(id).first<KeyRow>();
      return presentKey(row!);
    });
  }
  if (op === "key.activate" || op === "key.retire") {
    const sha256 = typeof body.sha256 === "string" ? body.sha256.trim().toUpperCase() : "";
    if (!/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(sha256)) refuseAdmin("Give the key's SHA-256 fingerprint");
    confirmed(body, op === "key.activate" ? "CONFIRM ACTIVATE SAML IDP KEY" : "CONFIRM RETIRE SAML IDP KEY");
    return audited(env, actor, op === "key.activate" ? "saml_idp_key_activate" : "saml_idp_key_retire", sha256, async () => {
      const key = await env.DB.prepare("SELECT * FROM nathan_saml_idp_keys WHERE sha256=? LIMIT 1").bind(sha256).first<KeyRow>();
      if (!key) return refuseAdmin("Unknown signing key");
      if (op === "key.retire") {
        if (key.status !== "previous" && key.status !== "next") refuseAdmin("Only a previous or a not yet active next key can be retired");
        const r = await env.DB.prepare("UPDATE nathan_saml_idp_keys SET status='retired',private_key=NULL,retired_at=unixepoch() WHERE id=? AND status=?")
          .bind(key.id, key.status).run();
        if (r.meta.changes !== 1) refuseAdmin("The key changed concurrently; reload and try again");
      } else {
        if (key.status !== "next") refuseAdmin("Only the next key can be activated");
        const now = Math.floor(Date.now() / 1000);
        if (now - key.created_at < ROTATION_OVERLAP_SECONDS)
          refuseAdmin("The next key has been published for less than 24 hours. Service providers that cache metadata may not trust it yet; activate it after " +
            new Date((key.created_at + ROTATION_OVERLAP_SECONDS) * 1000).toISOString());
        if ((await publishedKeys(env)).some(k => k.status === "previous")) refuseAdmin("Retire the previous key first");
        const results = await env.DB.batch([
          env.DB.prepare("UPDATE nathan_saml_idp_keys SET status='previous' WHERE status='active' AND EXISTS (SELECT 1 FROM nathan_saml_idp_keys WHERE id=? AND status='next')").bind(key.id),
          env.DB.prepare("UPDATE nathan_saml_idp_keys SET status='active',activated_at=unixepoch() WHERE id=? AND status='next'").bind(key.id)
        ]);
        if (results[1].meta.changes !== 1) refuseAdmin("The key changed concurrently; reload and try again");
      }
      return presentKey((await env.DB.prepare("SELECT * FROM nathan_saml_idp_keys WHERE id=?").bind(key.id).first<KeyRow>())!);
    });
  }
  return refuseAdmin("Unknown operation");
}

/** Admin-readable refusals only; never database internals. */
function publicMessage(e: unknown) {
  if (e instanceof AdminRefusal) return e.message;
  const m = e instanceof Error ? e.message : "";
  return m && m.length <= 300 && !/D1_|SQLITE|SQL|constraint|stack/i.test(m) ? m : "SAML application change rejected";
}

async function studio(request: Request, env: AuthEnv, auth: any): Promise<Response> {
  const reject = (status: number, error: string) => Response.json({ error }, { status, headers: noStore });
  if (request.method === "POST") {
    if (request.headers.get("Origin") !== origin(env) || request.headers.get("Sec-Fetch-Site") === "cross-site") return reject(403, "Cross-origin request denied");
    if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json") return reject(415, "JSON required");
  } else if (request.method !== "GET") return reject(405, "Method not allowed");
  const session = await auth.api.getSession({ headers: request.headers });
  if (!await isAdminPrincipal(session?.user, env) || !await mayAdminister(env, session!.user.id, session!.session.id))
    return reject(403, "Verified administrator with completed enrollment and recent passkey required");
  if (request.method === "GET") return Response.json(await samlIdpOverview(env), { headers: noStore });
  const raw = await readBoundedText(request, STUDIO_MAX_BYTES);
  if (raw === null) return reject(413, "Request too large");
  let body: any; try { body = JSON.parse(raw); } catch { return reject(400, "Invalid JSON"); }
  try { return Response.json(await applySamlIdpOperation(env, body, session!.user.id), { headers: noStore }); }
  catch (e) { return reject(409, publicMessage(e)); }
}

/** Nathan-owned SAML IdP routes. Returns null when the path is not one of them. */
export async function handleSamlIdp(request: Request, env: AuthEnv, auth: any, url: URL): Promise<Response | null> {
  const path = url.pathname;
  if (path === "/studio/api/saml-idp") return studio(request, env, auth);
  if (path !== "/saml/idp" && !path.startsWith("/saml/idp/")) return null;
  if ((path === "/saml/idp" || path === "/saml/idp/metadata") && request.method === "GET") return metadata(env);
  if (path === "/saml/idp/sso") return sso(request, env, url);
  if (path === "/saml/idp/continue" && request.method === "GET") return continueSso(request, env, auth);
  const start = /^\/saml\/idp\/start\/([^/]+)$/.exec(path);
  if (start && SP_ID.test(start[1])) return idpInitiated(request, env, auth, start[1]);
  return refusal("Not found", "Unknown SAML endpoint.", "saml_unknown_endpoint", { status: 404 });
}

/** Scheduled cleanup of expired replay-cache and pending rows. */
export async function pruneSamlIdp(env: AuthEnv) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM nathan_saml_idp_request_ids WHERE expires_at < unixepoch()"),
    env.DB.prepare("DELETE FROM nathan_saml_idp_pending WHERE expires_at < unixepoch() - 3600")
  ]);
}
