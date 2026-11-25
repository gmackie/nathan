import { createHash, randomUUID } from "node:crypto";
import { normalizeEmail } from "../src/auth/admission-policy.mjs";
import { auditStatement } from "../src/shared/rbac-store.mjs";
import { planSync, syncStatements, validateManifest } from "../src/shared/rbac-manifest.mjs";
import { AUDIENCE_SCOPES, MAX_ACCESS_TOKEN_SECONDS } from "../src/shared/token-claims.mjs";

/** Initialize the owner invitation, app roles, confidential PKCE client and API resource in the caller's guarded D1 batch. */
export function standaloneWebStatements(spec, owner, secret, { displayName, rolePermissions, scopes, grantTypes }) {
  if (!owner || normalizeEmail(owner) !== owner) throw Error("Supply one normalized operator email");
  if (typeof secret !== "string" || !/^[A-Za-z0-9_-]{43,128}$/.test(secret)) throw Error("Invalid confidential web client secret");
  const { worker, origin, clientId } = spec;
  const app = worker.vars.NATHAN_APP_ID;
  const actor = "cli:" + worker.account_id;
  const now = new Date().toISOString();
  // Better Auth's default storeClientSecret uses base64url(SHA-256(secret)), without padding.
  const verifier = createHash("sha256").update(secret).digest("base64url");
  const resource = origin + "/api";
  const sql = (sql, ...params) => ({ sql, params });
  const perms = [...new Set(Object.values(rolePermissions).flat())];
  const manifest = validateManifest({
    permissions: Object.fromEntries(perms.map(p => [p, ""])),
    roles: Object.fromEntries(Object.entries(rolePermissions).map(([name, permissions]) => [name, { permissions }]))
  });
  const initial = { app: { id: app, accessMode: "approved" }, permissions: [], roles: [] };
  return [
    sql("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')", actor, owner),
    sql("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,?,unixepoch()+7*86400)", randomUUID(), owner, actor),
    auditStatement(actor, "invitation_create", "bootstrap-owner", "succeeded"),
    sql("INSERT INTO nathan_applications(id,hostname,roles,enabled,access_mode) VALUES (?,?,'[]',1,'approved')", app, new URL(origin).hostname),
    ...syncStatements(app, planSync(initial, manifest), actor),
    sql("INSERT INTO oauthClient(id,clientId,clientSecret,name,disabled,skipConsent,subjectType,scopes,redirectUris,tokenEndpointAuthMethod," +
      "applicationType,grantTypes,responseTypes,requirePKCE,metadata,createdAt,updatedAt) VALUES (?,?,?,?,0,0,'public',?,?," +
      "'client_secret_basic','web',?,?,1,?,?,?)", randomUUID(), clientId, verifier, displayName, JSON.stringify(scopes), JSON.stringify([origin + "/auth/callback"]),
      JSON.stringify(grantTypes), JSON.stringify(["code"]), JSON.stringify({ appearance: { wordmark: displayName } }), now, now),
    sql("INSERT INTO oauthResource(id,identifier,name,accessTokenTtl,allowedScopes,disabled,policyVersion,createdAt,updatedAt) " +
      "VALUES (?,?,?, ?,?,0,1,?,?)", randomUUID(), resource, resource, MAX_ACCESS_TOKEN_SECONDS, JSON.stringify(AUDIENCE_SCOPES), now, now),
    sql("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,?,?)", resource, app, actor),
    sql("INSERT INTO oauthClientResource(id,clientId,resourceId,createdAt) VALUES (?,?,?,?)", randomUUID(), clientId, resource, now),
    auditStatement(actor, "client_create", clientId, "succeeded"),
    auditStatement(actor, "token_audience_register", resource, "succeeded"),
    auditStatement(actor, "token_audience_link", clientId, "succeeded")
  ];
}
