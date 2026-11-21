/**
 * NATH-15: Gatekeeper-ready access tokens.
 *
 * Better Auth 1.7.14 issues RFC 9068 JWT access tokens (`typ: at+jwt`, iss, sub, aud, exp, iat, jti,
 * client_id, azp, scope, sid) whenever the request names a configured RFC 8707 resource. Nathan
 * adds, through the supported oauth-provider `extensions[].claims.accessToken` hook:
 *   - `principal_kind` (user / machine / agent), on every JWT access token;
 *   - `roles`, an optional hint from NATH-13's evaluator for the app bound to the token's audience;
 *   - `nathan_amr` / `nathan_acr` / `nathan_auth_time` from verified passkey sign-in evidence only.
 * Better Auth strips the reserved names `acr`, `amr` and `auth_time` from every claim source, so
 * Nathan cannot and does not emit them on access tokens. See docs/gatekeeper.md.
 *
 * Identity Studio operations here (POST /studio/api/tokens) are admin-only (checked by the caller),
 * same-origin, size-limited and audited.
 */
import type { AuthEnv } from "./env";
import { audit } from "./admin-service";
import { resolveAccess } from "./rbac";
import { principalKind, evidenceClaims, rolesClaim, audienceApp, validateAudience,
  MAX_ACCESS_TOKEN_SECONDS, API_SCOPE } from "../shared/token-claims.mjs";

export { MAX_ACCESS_TOKEN_SECONDS, API_SCOPE };
/** Scopes a registered audience accepts: user sign-in scopes plus the machine API scope. */
export const AUDIENCE_SCOPES = ["openid", "profile", "email", "offline_access", API_SCOPE];

const CLIENT_ID = /^[A-Za-z0-9._-]{1,200}$/;
const APP_ID = /^[a-z][a-z0-9-]{0,62}$/;

type ClaimInput = {
  user?: { id?: unknown } | null;
  client: { clientId: string };
  sessionId?: string;
  resources?: string[];
};

/**
 * Claims Nathan adds to every JWT access token. Errors propagate, so a D1 failure fails the token
 * request rather than issuing a token without its principal kind.
 */
export async function accessTokenClaims(env: AuthEnv, input: ClaimInput): Promise<Record<string, unknown>> {
  const userId = typeof input.user?.id === "string" ? input.user.id : null;
  const resources = Array.isArray(input.resources) ? input.resources.filter(r => typeof r === "string").slice(0, 16) : [];
  const statements = [env.DB.prepare("SELECT principal_kind FROM nathan_client_principals WHERE client_id=? LIMIT 1").bind(input.client.clientId)];
  if (userId && resources.length)
    statements.push(env.DB.prepare("SELECT identifier, app_id FROM nathan_token_audiences WHERE identifier IN (" +
      resources.map(() => "?").join(",") + ")").bind(...resources));
  const [kind, audiences] = (await env.DB.batch(statements)).map(r => (r.results ?? []) as any[]);
  const claims: Record<string, unknown> = {
    principal_kind: principalKind({ hasUser: userId !== null, clientKind: kind[0]?.principal_kind })
  };
  if (!userId) return claims;
  const appId = audiences ? audienceApp(audiences) : null;
  if (appId) {
    const roles = rolesClaim(await resolveAccess(env, appId, userId));
    if (roles) claims.roles = roles;
  }
  if (typeof input.sessionId === "string" && input.sessionId) {
    // Evidence counts only while its Better Auth session still exists.
    const row = await env.DB.prepare(
      'SELECT a.session_id, a.user_id, a.method, a.verified_at FROM nathan_admin_assurance a JOIN "session" s ON s."id"=a.session_id AND s."userId"=a.user_id ' +
      "WHERE a.session_id=? AND a.user_id=? LIMIT 1").bind(input.sessionId, userId).first();
    Object.assign(claims, evidenceClaims(row, { userId, sessionId: input.sessionId }));
  }
  return claims;
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

async function registeredAudience(env: AuthEnv, value: unknown) {
  const identifier = validateAudience(value, new URL(env.NATHAN_ISSUER).origin);
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
    return audited(env, actor, "token_audience_remove", identifier, async () => {
      // Disable rather than delete: Better Auth refuses new tokens for it; issued tokens expire within 900 s.
      await auth.api.adminUpdateOAuthResource({ headers, params: { identifier }, body: { disabled: true } });
      await env.DB.prepare("DELETE FROM nathan_token_audiences WHERE identifier=?").bind(identifier).run();
      return { identifier, removed: true };
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
    // Back to classify-by-grant widens the client: its user-delegated tokens then say `user`.
    if (body.kind === "auto" && body.confirm !== "CONFIRM CLASSIFY BY GRANT " + clientId) throw Error("Explicit confirmation required");
    const change = body.kind === "agent"
      ? env.DB.prepare("INSERT INTO nathan_client_principals(client_id,principal_kind,set_by) VALUES (?,'agent',?) " +
        "ON CONFLICT(client_id) DO UPDATE SET principal_kind='agent', set_by=excluded.set_by, updated_at=unixepoch()").bind(clientId, actor)
      : env.DB.prepare("DELETE FROM nathan_client_principals WHERE client_id=?").bind(clientId);
    // The change and its audit row commit together.
    await env.DB.batch([change, env.DB.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(), actor, "client_principal_kind", clientId + " kind=" + body.kind, "succeeded")]);
    return { clientId, principalKind: body.kind,
      note: "Applies to tokens issued from now on; tokens already issued keep their kind until they expire (at most 900 s)." };
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
