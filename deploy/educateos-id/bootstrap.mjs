/** Install the dedicated EducateOS staging web client and the independent management owner. */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { text } from "node:stream/consumers";
import { pathToFileURL } from "node:url";
import { CloudflareClient } from "../../scripts/lib/cloudflare.mjs";
import { auditStatement } from "../../src/shared/rbac-store.mjs";
import { standaloneWebStatements } from "../standalone-web-install.mjs";
import { applicationOrigin, configuration, renderConfig, webClientId, workerName } from "./cloudflare.config.ts";

const receipt = "install:educateos:staging";
const action = "educateos_install";
const resource = applicationOrigin + "/api";
const callback = JSON.stringify([applicationOrigin + "/auth/callback"]);
const logout = JSON.stringify([applicationOrigin + "/sign-in"]);
const backchannel = applicationOrigin + "/auth/backchannel-logout";

/** A private, parameterized D1 batch and two readbacks. It contains only the client's stored verifier. */
export async function prepareInstall(owner, secret) {
  const worker = await configuration();
  if (await readFile(new URL("./wrangler.auth.jsonc", import.meta.url), "utf8") !== await renderConfig())
    throw Error("Regenerate the dedicated EducateOS Worker configuration before installation");
  const app = worker.vars.NATHAN_APP_ID;
  const actor = "cli:" + worker.account_id;
  const spec = { worker, origin: applicationOrigin, clientId: webClientId };
  const guard = {
    sql: `INSERT INTO nathan_security_audit(id,actor,action,target,outcome)
      SELECT ?,?,?,?,CASE WHEN NOT EXISTS(SELECT 1 FROM user)
        AND NOT EXISTS(SELECT 1 FROM nathan_applications) AND NOT EXISTS(SELECT 1 FROM oauthClient)
        AND NOT EXISTS(SELECT 1 FROM oauthResource) AND NOT EXISTS(SELECT 1 FROM nathan_bootstrap_status)
        AND NOT EXISTS(SELECT 1 FROM nathan_invitations) THEN 'succeeded' ELSE NULL END`,
    params: [receipt, actor, action, workerName],
  };
  const batch = [
    guard,
    ...standaloneWebStatements(spec, owner, secret, {
      displayName: "EducateOS", rolePermissions: { member: ["profile:read"] },
      scopes: ["openid", "email"], grantTypes: ["authorization_code"],
    }),
    {
      sql: `UPDATE oauthClient SET enableEndSession=1,postLogoutRedirectUris=?,backchannelLogoutUri=?,
        backchannelLogoutSessionRequired=0 WHERE clientId=?`,
      params: [logout, backchannel, webClientId],
    },
    auditStatement(actor, "client_logout_configure", webClientId, "succeeded"),
  ];
  const checkReceipt = {
    sql: "SELECT id FROM nathan_security_audit WHERE id=? AND action=? AND target=? AND outcome='succeeded'",
    params: [receipt, action, workerName],
  };
  // Return only a verdict. The database never has to return the client verifier, owner or invitations.
  const verify = {
    sql: `SELECT EXISTS(SELECT 1 FROM oauthClient c
      JOIN oauthClientResource cr ON cr.clientId=c.clientId
      JOIN oauthResource r ON r.identifier=cr.resourceId AND r.disabled=0
      JOIN nathan_token_audiences t ON t.identifier=r.identifier
      JOIN nathan_provisionable_apps a ON a.id=t.app_id
      JOIN nathan_rbac_role_permissions p ON p.app_id=a.id AND p.role_key='member' AND p.permission_key='profile:read'
      WHERE c.clientId=?1 AND c.clientSecret=?2 AND c.disabled=0 AND c.requirePKCE=1 AND c.skipConsent=0
        AND c.subjectType='public' AND c.tokenEndpointAuthMethod='client_secret_basic' AND c.applicationType='web'
        AND c.scopes='["openid","email"]' AND c.grantTypes='["authorization_code"]'
        AND c.redirectUris=?3 AND c.enableEndSession=1 AND c.postLogoutRedirectUris=?4
        AND c.backchannelLogoutUri=?5 AND c.backchannelLogoutSessionRequired=0
        AND r.identifier=?6 AND a.id=?7 AND a.hostname=?8
        AND EXISTS(SELECT 1 FROM nathan_bootstrap_status WHERE id='primary')
      ) AS configured`,
    params: [webClientId, createHash("sha256").update(secret).digest("base64url"),
      callback, logout, backchannel, resource, app, new URL(applicationOrigin).hostname],
  };
  return { accountId: worker.account_id, databaseId: worker.d1_databases[0].database_id, receipt, batch, checkReceipt, verify };
}

/** Read the receipt before applying. A concurrent winner and an interrupted response are safe to retry. */
export async function applyInstall(api, install, verifyOnly = false) {
  const db = await api.databaseNamed(workerName);
  if (db?.uuid !== install.databaseId || api.accountId !== install.accountId) throw Error("Dedicated EducateOS database identity mismatch");
  const read = ({ sql, params }) => api.queryDatabase(db.uuid, sql, params);
  if (!(await read(install.checkReceipt)).length && !verifyOnly) {
    try { await api.batchDatabase(db.uuid, install.batch); }
    catch (error) { if (!(await read(install.checkReceipt)).length) throw error; }
  }
  if (!(await read(install.checkReceipt)).length || (await read(install.verify))[0]?.configured !== 1)
    throw Error("Dedicated EducateOS installation did not match the expected registration");
}

async function main([operation, destination, ...rest]) {
  if (rest.length || !["--apply", "--batch-out", "--verify"].includes(operation) ||
      ((operation === "--batch-out") !== Boolean(destination))) throw Error("Choose --apply, --verify or --batch-out <new-private-file>");
  const install = await prepareInstall(process.env.NATHAN_ADMIN_EMAILS, (await text(process.stdin)).trimEnd());
  if (operation === "--batch-out") {
    await writeFile(destination, JSON.stringify(install), { flag: "wx", mode: 0o600 });
    console.log("Prepared the private EducateOS staging install batch.");
    return;
  }
  const api = new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN, install.accountId);
  await applyInstall(api, install, operation === "--verify");
  console.log("Verified the EducateOS staging install receipt and confidential client configuration.");
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main(process.argv.slice(2)).catch(() => {
    console.error("EducateOS staging installation failed. Check the operation, inputs, private batch destination and D1 registration.");
    process.exitCode = 1;
  });
