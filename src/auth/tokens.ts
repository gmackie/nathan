/**
 * NATH-15: Gatekeeper-ready access tokens.
 *
 * Better Auth 1.7.14 issues RFC 9068 JWT access tokens (`typ: at+jwt`, iss, sub, aud, exp, iat, jti,
 * client_id, azp, scope, sid) whenever the request names a configured RFC 8707 resource. Nathan
 * adds, through the supported oauth-provider `extensions[].claims.accessToken` hook:
 *   - `principal_kind` (user / machine / agent), on every JWT access token;
 *   - `roles`, an optional hint from NATH-13's evaluator for the app bound to the token's audience;
 *   - `nathan_amr` from verified email or passkey sign-in. Only passkeys add `nathan_acr` and `nathan_auth_time`.
 * Better Auth strips the reserved names `acr`, `amr` and `auth_time` from every claim source, so
 * Nathan cannot and does not emit them on access tokens. See docs/gatekeeper.md.
 *
 * Identity Studio operations here (POST /studio/api/tokens) are admin-only (checked by the caller),
 * same-origin, size-limited and audited.
 */
import type { AuthEnv } from "./env";
import { APIError } from "better-auth/api";
import { audit } from "./admin-service";
import { resolveAccess } from "./rbac";
import { principalKind, evidenceClaims, rolesClaim, audienceApp, validateAudience, liveSession, userBanned, apiScopeAllowed,
  MAX_ACCESS_TOKEN_SECONDS, API_SCOPE, AUDIENCE_SCOPES } from "../shared/token-claims.mjs";

export { MAX_ACCESS_TOKEN_SECONDS, API_SCOPE, AUDIENCE_SCOPES };

const CLIENT_ID = /^[A-Za-z0-9._-]{1,200}$/;
const APP_ID = /^[a-z][a-z0-9-]{0,62}$/;

type ClaimInput = {
  user?: { id?: unknown } | null;
  client: { clientId: string };
  sessionId?: string | null;
  scopes?: string[];
  grantType?: string;
  resources?: string[];
};

/** An OAuth token-endpoint error (RFC 6749 §5.2) that Better Auth returns as a 400 JSON body. */
const MAX_TOKEN_RESOURCES = 16;
const tokenError = (error: "invalid_grant" | "invalid_scope" | "invalid_target", description: string) =>
  new APIError("BAD_REQUEST", { error, error_description: description });

/**
 * Claims Nathan adds to every JWT access token, and the checks Better Auth does not make before it
 * issues one. Errors propagate, so a D1 failure fails the token request rather than issuing a token
 * without its principal kind. The checks run before Better Auth rotates a refresh token, so a
 * refused refresh leaves the grant as it was.
 *
 * For a grant that carries a user (authorization code, or refresh from one):
 *   - a banned user gets no token (`invalid_grant`), whatever the client;
 *   - API_SCOPE needs an administrator-marked agent client (`invalid_scope`);
 *   - a `user` token for a registered audience needs the grant's Better Auth session to be live:
 *     present, the same user's and unexpired (`invalid_grant`). Signing out, revoking the session
 *     and banning the user (which deletes the sessions) all end such grants. Nathan refuses rather
 *     than downgrading the kind. Agent clients keep offline (refresh) access without a live session;
 *     their tokens say `agent` and carry no session evidence.
 */
export async function accessTokenClaims(env: AuthEnv, input: ClaimInput): Promise<Record<string, unknown>> {
  const userId = typeof input.user?.id === "string" ? input.user.id : null;
  // Every distinct resource Better Auth will put in `aud` is checked. Better Auth neither dedupes
  // nor caps the list, so truncating it would let padding hide a registered audience from the
  // live-session check and the roles rule; too many distinct resources are refused instead.
  const resources = Array.isArray(input.resources) ? [...new Set(input.resources.filter(r => typeof r === "string"))] : [];
  if (resources.length > MAX_TOKEN_RESOURCES)
    throw tokenError("invalid_target", "At most " + MAX_TOKEN_RESOURCES + " distinct resources per token");
  const sessionId = typeof input.sessionId === "string" && input.sessionId ? input.sessionId : null;
  const statements = [env.DB.prepare("SELECT principal_kind FROM nathan_client_principals WHERE client_id=? LIMIT 1").bind(input.client.clientId)];
  if (userId) {
    statements.push(env.DB.prepare('SELECT "banned" AS banned, "banExpires" AS banExpires FROM "user" WHERE "id"=? LIMIT 1').bind(userId));
    statements.push(resources.length
      ? env.DB.prepare("SELECT identifier, app_id FROM nathan_token_audiences WHERE identifier IN (" + resources.map(() => "?").join(",") + ")").bind(...resources)
      : env.DB.prepare("SELECT identifier, app_id FROM nathan_token_audiences WHERE 0"));
    // The grant's session, and authentication evidence that counts only while that session exists.
    statements.push(env.DB.prepare('SELECT s."id" AS id, s."userId" AS userId, s."expiresAt" AS expiresAt, a.session_id, a.user_id, a.method, a.verified_at, e.session_id AS email_session_id ' +
      'FROM "session" s LEFT JOIN nathan_admin_assurance a ON a.session_id=s."id" AND a.user_id=s."userId" LEFT JOIN nathan_email_otp_sessions e ON e.session_id=s."id" AND e.user_id=s."userId" AND e.hosted=1 WHERE s."id"=? LIMIT 1').bind(sessionId ?? ""));
  }
  const [kindRows, userRows, audiences, sessionRows] = (await env.DB.batch(statements)).map(r => (r.results ?? []) as any[]);
  const clientKind = kindRows[0]?.principal_kind;
  const kind = principalKind({ hasUser: userId !== null, clientKind });
  const claims: Record<string, unknown> = { principal_kind: kind };
  if (!userId) return claims;

  const now = Date.now();
  if (userBanned(userRows[0], now)) throw tokenError("invalid_grant", "The user is banned");
  if (!apiScopeAllowed({ hasUser: true, clientKind, scopes: input.scopes }))
    throw tokenError("invalid_scope", API_SCOPE + " is only for client credentials and agent clients");
  const session = liveSession(sessionRows[0], { userId, sessionId: sessionId ?? undefined, now }) ? sessionRows[0] : null;
  if (kind === "user" && audiences.length > 0 && !session)
    throw tokenError("invalid_grant", "The sign-in session for this grant has ended");

  const appId = audienceApp(audiences, resources);
  const customerIssuer = env.NATHAN_APP_ORIGIN === env.NATHAN_ISSUER;
  if (customerIssuer && (!appId || appId !== env.NATHAN_APP_ID))
    throw tokenError("invalid_target", "The resource does not belong to the application");
  if (appId) {
    const decision = await resolveAccess(env, appId, userId);
    if (customerIssuer && !decision.allowed)
      throw tokenError("invalid_grant", "The account cannot use the application");
    const roles = rolesClaim(decision);
    if (roles) claims.roles = roles;
  }
  if (session && sessionId) Object.assign(claims, evidenceClaims(session, { userId, sessionId }));
  return claims;
}

/**
 * Better Auth `hooks.before` check on /oauth2/authorize: a client that is not an
 * administrator-marked agent may not ask a user to delegate API_SCOPE. An omitted `scope` counts
 * as asking for it when the client's default scopes include it (Better Auth then grants the
 * client's scopes, or every provider scope). Refused requests get a 400 `invalid_scope` and no code.
 */
export async function guardAuthorizationScopes(env: AuthEnv, ctx: any, providerScopes: readonly string[]): Promise<void> {
  if (ctx?.path !== "/oauth2/authorize") return;
  const source = ctx.method === "POST" ? ctx.body : ctx.query;
  const clientId = source?.client_id;
  if (typeof clientId !== "string" || !clientId) return; // Better Auth refuses the request itself.
  const scope = source.scope;
  const requested = typeof scope === "string" ? scope.split(" ").filter(Boolean) : null;
  if (requested && !requested.includes(API_SCOPE)) return;
  const row = await env.DB.prepare('SELECT c."scopes" AS scopes, p.principal_kind AS kind FROM "oauthClient" c ' +
    'LEFT JOIN nathan_client_principals p ON p.client_id=c."clientId" WHERE c."clientId"=? LIMIT 1').bind(clientId).first<any>();
  if (!row || row.kind === "agent") return;
  if (!requested) {
    let defaults: unknown = null;
    try { defaults = row.scopes ? JSON.parse(row.scopes) : null; } catch { defaults = null; }
    const effective = Array.isArray(defaults) ? defaults : providerScopes;
    if (!effective.includes(API_SCOPE)) return;
  }
  throw new APIError("BAD_REQUEST", { error: "invalid_scope",
    error_description: (requested ? "" : "Name the scopes you need: the default includes " + API_SCOPE + ". ") +
      API_SCOPE + " is only for client credentials and administrator-marked agent clients" });
}

/** Registered as `oauthProvider({ extensions: [...] })`; claims are strictly additive. */
export function nathanAccessTokenExtension(env: AuthEnv) {
  return { claims: { accessToken: (input: ClaimInput) => accessTokenClaims(env, input) } };
}

export async function tokenOverview(env: AuthEnv) {
  const [audiences, links, clients] = (await env.DB.batch([
    env.DB.prepare('SELECT a.identifier, a.app_id AS app, r."accessTokenTtl" AS accessTokenTtl, r."disabled" AS disabled ' +
      'FROM nathan_token_audiences a LEFT JOIN "oauthResource" r ON r."identifier"=a.identifier ORDER BY a.identifier LIMIT 200'),
    env.DB.prepare('SELECT l."resourceId" AS identifier, l."clientId" AS clientId FROM "oauthClientResource" l ' +
      'JOIN nathan_token_audiences a ON a.identifier=l."resourceId" LIMIT 2000'),
    env.DB.prepare('SELECT c."clientId" AS id, c."name" AS name, c."grantTypes" AS grantTypes, c."disabled" AS disabled, ' +
      "COALESCE(p.principal_kind,'auto') AS principalKind FROM \"oauthClient\" c LEFT JOIN nathan_client_principals p ON p.client_id=c.\"clientId\" " +
      'ORDER BY c."createdAt" DESC LIMIT 200')
  ])).map(r => (r.results ?? []) as any[]);
  return {
    audiences: audiences.map(a => ({ identifier: a.identifier, app: a.app ?? null, accessTokenTtl: a.accessTokenTtl ?? null,
      disabled: a.disabled === 1, clients: links.filter(l => l.identifier === a.identifier).map(l => l.clientId) })),
    clients: clients.map(c => {
      let grantTypes: unknown = [];
      try { grantTypes = JSON.parse(c.grantTypes || "[]"); } catch { grantTypes = []; }
      return { id: c.id, name: c.name, disabled: c.disabled === 1, grantTypes, principalKind: c.principalKind };
    }),
    maxAccessTokenSeconds: MAX_ACCESS_TOKEN_SECONDS
  };
}

export const TOKEN_OPERATIONS = ["audience.register", "audience.remove", "audience.link", "audience.unlink", "client.kind", "machine.create"];

/**
 * NATH-14: a remote MCP server's identifier is a Nathan audience row but never a Better Auth one.
 * Its audience and app binding belong to the MCP admin (`/studio/api/mcp`), so this section never
 * touches it: otherwise Better Auth could issue tokens for it and the two bindings could diverge.
 */
async function refuseMcpResource(env: AuthEnv, identifier: string) {
  const mcp = await env.DB.prepare("SELECT identifier FROM nathan_mcp_resources WHERE identifier=? LIMIT 1").bind(identifier).first();
  if (mcp) throw Error("Invalid audience: " + identifier + " is a remote MCP server; manage it under Remote MCP servers");
}
async function registeredAudience(env: AuthEnv, value: unknown) {
  const identifier = validateAudience(value, new URL(env.NATHAN_ISSUER).origin);
  await refuseMcpResource(env, identifier);
  const row = await env.DB.prepare("SELECT identifier FROM nathan_token_audiences WHERE identifier=? LIMIT 1").bind(identifier).first();
  if (!row) throw Error("Unknown audience: register it first");
  return identifier;
}
async function existingClient(env: AuthEnv, value: unknown) {
  if (typeof value !== "string" || !CLIENT_ID.test(value)) throw Error("Invalid client id");
  const row = await env.DB.prepare('SELECT "clientId" AS id FROM "oauthClient" WHERE "clientId"=? LIMIT 1').bind(value).first();
  if (!row) throw Error("Unknown OAuth client");
  return value;
}
/** Runs a Better Auth admin call between attempted and succeeded/failed audit rows. */
async function audited<T>(env: AuthEnv, actor: string, action: string, target: string, run: () => Promise<T>): Promise<T> {
  await audit(env, actor, action, target, "attempted");
  try {
    const value = await run();
    await audit(env, actor, action, target, "succeeded");
    return value;
  } catch (error) {
    await audit(env, actor, action, target, "failed");
    throw error;
  }
}

export async function applyTokenOperation(auth: any, env: AuthEnv, headers: Headers, body: any, actor: string): Promise<Record<string, unknown>> {
  const op = body?.op;
  if (!TOKEN_OPERATIONS.includes(op)) throw Error("Unknown token operation");
  const origin = new URL(env.NATHAN_ISSUER).origin;

  if (op === "audience.register") {
    const identifier = validateAudience(body.identifier, origin);
    await refuseMcpResource(env, identifier);
    let app: string | null = null;
    if (body.app !== undefined && body.app !== null && body.app !== "") {
      if (typeof body.app !== "string" || !APP_ID.test(body.app)) throw Error("Invalid application id");
      if (!await env.DB.prepare("SELECT id FROM nathan_applications WHERE id=? LIMIT 1").bind(body.app).first())
        throw Error("Unknown application");
      app = body.app;
    }
    return audited(env, actor, "token_audience_register", identifier + (app ? " app=" + app : ""), async () => {
      // Nathan owns the issuance policy of its audiences: 900 s, fixed scopes, no resource-level custom
      // claims (which would outrank principal_kind and roles), enabled.
      const policy = { accessTokenTtl: MAX_ACCESS_TOKEN_SECONDS, allowedScopes: AUDIENCE_SCOPES, customClaims: null, disabled: false };
      const existing = await env.DB.prepare('SELECT "identifier" FROM "oauthResource" WHERE "identifier"=? LIMIT 1').bind(identifier).first();
      if (existing) await auth.api.adminUpdateOAuthResource({ headers, params: { identifier }, body: policy });
      else await auth.api.adminCreateOAuthResource({ headers, body: { identifier, name: identifier, ...policy } });
      await env.DB.prepare("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,?,?) " +
        "ON CONFLICT(identifier) DO UPDATE SET app_id=excluded.app_id, updated_at=unixepoch()").bind(identifier, app, actor).run();
      return { identifier, app, accessTokenTtl: MAX_ACCESS_TOKEN_SECONDS, allowedScopes: AUDIENCE_SCOPES };
    });
  }

  if (op === "audience.remove") {
    const identifier = await registeredAudience(env, body.identifier);
    if (body.confirm !== "CONFIRM REMOVE AUDIENCE " + identifier) throw Error("Explicit confirmation required");
    const links = (await env.DB.prepare('SELECT count(*) AS n FROM "oauthClientResource" WHERE "resourceId"=?').bind(identifier).first<any>())?.n ?? 0;
    return audited(env, actor, "token_audience_remove", identifier + " unlinked=" + links, async () => {
      // Disable rather than delete: Better Auth refuses new tokens for it; issued tokens expire within 900 s.
      await auth.api.adminUpdateOAuthResource({ headers, params: { identifier }, body: { disabled: true } });
      // Drop every client link with it, so registering the identifier again starts with no clients.
      const [unlinked] = await env.DB.batch([
        env.DB.prepare('DELETE FROM "oauthClientResource" WHERE "resourceId"=?').bind(identifier),
        env.DB.prepare("DELETE FROM nathan_token_audiences WHERE identifier=?").bind(identifier)
      ]);
      return { identifier, removed: true, unlinkedClients: unlinked.meta?.changes ?? links };
    });
  }

  if (op === "audience.link" || op === "audience.unlink") {
    const identifier = await registeredAudience(env, body.identifier);
    const clientId = await existingClient(env, body.clientId);
    const action = op === "audience.link" ? "token_audience_link" : "token_audience_unlink";
    return audited(env, actor, action, identifier + " client=" + clientId, async () => {
      const call = op === "audience.link" ? auth.api.adminLinkClientResource : auth.api.adminUnlinkClientResource;
      await call({ headers, params: { identifier, client_id: clientId } });
      return { identifier, clientId, linked: op === "audience.link" };
    });
  }

  if (op === "client.kind") {
    const clientId = await existingClient(env, body.clientId);
    if (!["agent", "auto"].includes(body.kind)) throw Error("Invalid principal kind: agent or auto");
    // Marking a client agent widens it (offline refresh without a live session, API_SCOPE), so it
    // needs confirmation, and the user grants it already holds were issued as session-bound: they
    // are revoked so they cannot become offline grants.
    if (body.kind === "agent" && body.confirm !== "CONFIRM MARK AGENT " + clientId) throw Error("Explicit confirmation required");
    // Back to classify-by-grant widens the client: its user-delegated tokens then say `user`.
    if (body.kind === "auto" && body.confirm !== "CONFIRM CLASSIFY BY GRANT " + clientId) throw Error("Explicit confirmation required");
    const change = body.kind === "agent"
      ? env.DB.prepare("INSERT INTO nathan_client_principals(client_id,principal_kind,set_by) VALUES (?,'agent',?) " +
        "ON CONFLICT(client_id) DO UPDATE SET principal_kind='agent', set_by=excluded.set_by, updated_at=unixepoch()").bind(clientId, actor)
      : env.DB.prepare("DELETE FROM nathan_client_principals WHERE client_id=?").bind(clientId);
    // Classified by grant again, the client may no longer hold user-delegated API_SCOPE grants:
    // its refresh and opaque access tokens that carry it are revoked with the change.
    const revoke = body.kind === "agent" ? [
      env.DB.prepare('DELETE FROM "oauthRefreshToken" WHERE "clientId"=? AND "userId" IS NOT NULL').bind(clientId),
      env.DB.prepare('DELETE FROM "oauthAccessToken" WHERE "clientId"=? AND "userId" IS NOT NULL').bind(clientId)
    ] : body.kind === "auto" ? [
      env.DB.prepare('DELETE FROM "oauthRefreshToken" WHERE "clientId"=? AND instr("scopes",?)>0').bind(clientId, API_SCOPE),
      env.DB.prepare('DELETE FROM "oauthAccessToken" WHERE "clientId"=? AND "userId" IS NOT NULL AND instr("scopes",?)>0').bind(clientId, API_SCOPE)
    ] : [];
    // The change and its audit row commit together.
    await env.DB.batch([change, ...revoke, env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(), actor, "client_principal_kind", clientId + " kind=" + body.kind, "succeeded")]);
    return { clientId, principalKind: body.kind,
      note: body.kind === "agent"
        ? "Existing user grants for this client were revoked; users must authorize it again. Issued access tokens expire within 900 s."
        : "Applies to tokens issued from now on; tokens already issued keep their kind until they expire (at most 900 s)." };
  }

  // machine.create: a confidential client-credentials client for one registered audience.
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!name || name.length > 100 || /[\x00-\x1f\x7f]/.test(name)) throw Error("Invalid client name");
  if (body.confirm !== "CONFIRM MACHINE CLIENT " + name) throw Error("Explicit confirmation required");
  const kind = body.kind === undefined || body.kind === "machine" ? "machine" : body.kind === "agent" ? "agent" : null;
  if (!kind) throw Error("Invalid principal kind: machine or agent");
  const audience = await registeredAudience(env, body.audience);
  return audited(env, actor, "machine_client_create", name + " " + kind + " " + audience, async () => {
    const client = await auth.api.adminCreateOAuthClient({
      headers,
      body: {
        client_name: name,
        grant_types: ["client_credentials"],
        token_endpoint_auth_method: "client_secret_basic",
        client_credentials_scopes: [API_SCOPE],
        resources: [audience],
        skip_consent: false
      }
    });
    if (typeof client?.client_id !== "string") throw Error("Client creation failed");
    if (kind === "agent")
      await env.DB.batch([
        env.DB.prepare("INSERT INTO nathan_client_principals(client_id,principal_kind,set_by) VALUES (?,'agent',?)").bind(client.client_id, actor),
        env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
          .bind(crypto.randomUUID(), actor, "client_principal_kind", client.client_id + " kind=agent", "succeeded")
      ]);
    return { ...client, principalKind: kind,
      tokenRequest: { grant_type: "client_credentials", scope: API_SCOPE, resource: audience },
      note: "Store the client secret now; it is not shown again." };
  });
}
