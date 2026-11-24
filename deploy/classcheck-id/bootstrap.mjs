/** One-time, account-authorized initialization of each dedicated ClassCheck installation. */
import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { text } from "node:stream/consumers";
import { pathToFileURL } from "node:url";
import { CloudflareClient } from "../../scripts/lib/cloudflare.mjs";
import { stripJsonc } from "../../scripts/lib/wrangler.mjs";
import { normalizeEmail } from "../../src/auth/admission-policy.mjs";
import { auditStatement } from "../../src/shared/rbac-store.mjs";
import { planSync, syncStatements, validateManifest } from "../../src/shared/rbac-manifest.mjs";
import { AUDIENCE_SCOPES, MAX_ACCESS_TOKEN_SECONDS } from "../../src/shared/token-claims.mjs";

const rolePermissions = {
  member: ["profile:read"],
  guardian: ["profile:read", "family:read", "family:write"],
  staff: ["profile:read", "school:read", "school:manage", "attendance:write", "transport:manage", "family:read", "family:write"],
  driver: ["profile:read", "school:read", "trips:drive"],
  platform_admin: ["profile:read", "platform:admin", "school:read", "school:manage", "attendance:write", "transport:manage", "family:read", "family:write"]
};

export const receiptId = stage => "install:classcheck:" + stage;

export async function readStage(stage) {
  if (stage !== "staging" && stage !== "production") throw Error("Choose staging or production");
  const config = new URL("../classcheck-" + stage + "/wrangler.auth.jsonc", import.meta.url);
  const worker = JSON.parse(stripJsonc(await readFile(config, "utf8")));
  const origin = stage === "staging" ? "https://beta.classcheck.io" : "https://classcheck.io";
  const name = "nathan-classcheck-" + (stage === "staging" ? "stg" : "prod") + "-auth";
  const db = worker.d1_databases.find(v => v.binding === "DB");
  if (worker.name !== name || db?.database_name !== name || worker.vars.NATHAN_APP_ORIGIN !== origin ||
      worker.vars.NATHAN_APP_ID !== "classcheck") throw Error("Dedicated installation configuration mismatch");
  return { stage, worker, db, origin, name, clientId: "classcheck-web-" + stage };
}

export function installStatements(spec, owner, secret) {
  if (!owner || normalizeEmail(owner) !== owner) throw Error("Supply one normalized operator email");
  if (typeof secret !== "string" || !/^[A-Za-z0-9_-]{43,128}$/.test(secret)) throw Error("Invalid confidential web client secret");
  const { stage, worker, origin, clientId } = spec;
  const app = worker.vars.NATHAN_APP_ID;
  const actor = "cli:" + worker.account_id;
  const now = new Date().toISOString();
  const scopes = JSON.stringify(["openid", "email", "profile", "offline_access"]);
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
    // A stable primary key makes a second or concurrent install fail before changing anything.
    // A fresh install has no user or tenant registration. Fail closed on mistaken reuse.
    sql("INSERT INTO nathan_security_audit (id,actor,action,target,outcome) SELECT ?,?,'classcheck_install',?, " +
      "CASE WHEN NOT EXISTS (SELECT 1 FROM user) AND NOT EXISTS (SELECT 1 FROM nathan_applications) " +
      "AND NOT EXISTS (SELECT 1 FROM oauthClient) THEN 'succeeded' ELSE NULL END", receiptId(stage), actor, spec.name),
    sql("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,state) VALUES('primary',?,?,'pending')", actor, owner),
    sql("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,?,unixepoch()+7*86400)", randomUUID(), owner, actor),
    auditStatement(actor, "invitation_create", "bootstrap-owner", "succeeded"),
    sql("INSERT INTO nathan_applications(id,hostname,roles,enabled,access_mode) VALUES (?,?,'[]',1,'approved')", app, new URL(origin).hostname),
    ...syncStatements(app, planSync(initial, manifest), actor),
    sql("INSERT INTO oauthClient(id,clientId,clientSecret,name,disabled,skipConsent,subjectType,scopes,redirectUris,tokenEndpointAuthMethod," +
      "applicationType,grantTypes,responseTypes,requirePKCE,metadata,createdAt,updatedAt) VALUES (?,?,?,'ClassCheck',0,0,'public',?,?," +
      "'client_secret_basic','web',?,?,1,?,?,?)", randomUUID(), clientId, verifier, scopes, JSON.stringify([origin + "/auth/callback"]),
      JSON.stringify(["authorization_code", "refresh_token"]), JSON.stringify(["code"]), JSON.stringify({appearance:{wordmark:"ClassCheck"}}), now, now),
    sql("INSERT INTO oauthResource(id,identifier,name,accessTokenTtl,allowedScopes,disabled,policyVersion,createdAt,updatedAt) " +
      "VALUES (?,?,?, ?,?,0,1,?,?)", randomUUID(), resource, resource, MAX_ACCESS_TOKEN_SECONDS, JSON.stringify(AUDIENCE_SCOPES), now, now),
    sql("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,?,?)", resource, app, actor),
    sql("INSERT INTO oauthClientResource(id,clientId,resourceId,createdAt) VALUES (?,?,?,?)", randomUUID(), clientId, resource, now),
    auditStatement(actor, "client_create", clientId, "succeeded"),
    auditStatement(actor, "token_audience_register", resource, "succeeded"),
    auditStatement(actor, "token_audience_link", clientId, "succeeded")
  ];
}

async function main([stage, command, destination, ...extra]) {
  if (extra.length || (command !== "--apply" && command !== "--batch-out") ||
      (command === "--batch-out" ? !destination : destination)) throw Error("Expected <stage> --apply or <stage> --batch-out <private-file>");
  const spec = await readStage(stage);
  const secret = (await text(process.stdin)).trimEnd();
  const ops = installStatements(spec, process.env.NATHAN_ADMIN_EMAILS, secret);
  if (command === "--batch-out") {
    await writeFile(destination, JSON.stringify({ accountId: spec.worker.account_id, databaseId: spec.db.database_id,
      receipt: receiptId(stage), batch: ops }), { flag: "wx", mode: 0o600 });
    console.log("Prepared the install batch for " + spec.name);
    return;
  }
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, spec.worker.account_id);
  const db = await api.databaseNamed(spec.name);
  if (db?.uuid !== spec.db.database_id) throw Error("Dedicated database identity mismatch");
  const readReceipt = () => api.queryDatabase(db.uuid,
    "SELECT id FROM nathan_security_audit WHERE id=? AND action='classcheck_install' AND target=? AND outcome='succeeded'", [receiptId(stage), spec.name]);
  if (!(await readReceipt()).length) {
    await api.batchDatabase(db.uuid, ops);
    if (!(await readReceipt()).length) throw Error("Install receipt missing");
  }
  console.log("Verified install receipt for " + spec.name + " and client " + spec.clientId);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main(process.argv.slice(2)).catch(e => { console.error(e.message); process.exitCode = 1; });
