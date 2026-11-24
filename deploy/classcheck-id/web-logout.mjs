import { randomUUID } from "node:crypto";
import { AUDIENCE_SCOPES, MAX_ACCESS_TOKEN_SECONDS } from "../../src/shared/token-claims.mjs";
import { runUpgrade, startUpgrade } from "./upgrade.mjs";

const operation = "classcheck_web_logout";

/** Enable RP-initiated logout for the installed web client only, once per stage. */
export function webLogout(spec) {
  const now = new Date().toISOString();
  const returned = JSON.stringify([spec.origin + "/sign-in"]);
  const currentScopes = JSON.stringify(AUDIENCE_SCOPES);
  const originalScopes = JSON.stringify(["openid","email","profile","offline_access"]);
  const resource = spec.origin + "/api";
  const actor = "cli:" + spec.worker.account_id;
  return [startUpgrade(spec, operation), {
    sql: "UPDATE oauthClient SET enableEndSession=1,postLogoutRedirectUris=?,updatedAt=? WHERE clientId=? AND clientSecret IS NOT NULL " +
      "AND disabled=0 AND skipConsent=0 AND requirePKCE=1 AND subjectType='public' AND tokenEndpointAuthMethod='client_secret_basic' " +
      "AND applicationType='web' AND redirectUris=? AND enableEndSession IS NULL AND postLogoutRedirectUris IS NULL " +
      "AND EXISTS (SELECT 1 FROM oauthClientResource WHERE clientId=oauthClient.clientId AND resourceId=?)",
    params: [returned, now, spec.clientId, JSON.stringify([spec.origin + "/auth/callback"]), resource]
  }, {
    // Refuse to overwrite a changed or disabled client. A NULL outcome rolls back the complete batch.
    sql: "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,'client_logout_configure',?," +
      "CASE WHEN changes()=1 THEN 'succeeded' ELSE NULL END)",
    params: [randomUUID(), actor, spec.clientId]
  }, {
    sql: "UPDATE oauthResource SET allowedScopes=?1,updatedAt=?2,policyVersion=CASE WHEN allowedScopes=?1 THEN policyVersion " +
      "ELSE COALESCE(policyVersion,1)+1 END WHERE identifier=?3 AND accessTokenTtl=?4 AND allowedScopes IN (?1,?5) " +
      "AND disabled=0 AND customClaims IS NULL",
    params: [currentScopes, now, resource, MAX_ACCESS_TOKEN_SECONDS, originalScopes]
  }, {
    sql: "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,'token_audience_scopes',?," +
      "CASE WHEN changes()=1 THEN 'succeeded' ELSE NULL END)",
    params: [randomUUID(), actor, resource]
  }];
}

runUpgrade(import.meta.url, operation, webLogout);
