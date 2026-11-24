import { randomUUID } from "node:crypto";
import { runUpgrade, startUpgrade } from "./upgrade.mjs";

const operation = "classcheck_web_backchannel";

/** Register the ClassCheck receiver after the same-stage web Worker supports signed logout. */
export function webBackchannel(spec) {
  const uri = spec.origin + "/auth/backchannel-logout";
  return [
    startUpgrade(spec, operation),
    {
      sql: "UPDATE oauthClient SET backchannelLogoutUri=?1,backchannelLogoutSessionRequired=0,updatedAt=?2 " +
        "WHERE clientId=?3 AND disabled=0 AND clientSecret IS NOT NULL AND tokenEndpointAuthMethod='client_secret_basic' " +
        "AND applicationType='web' AND requirePKCE=1 AND skipConsent=0 AND subjectType='public' AND redirectUris=?4 " +
        "AND enableEndSession=1 AND postLogoutRedirectUris=?5 AND (backchannelLogoutUri IS NULL OR backchannelLogoutUri=?1) " +
        "AND COALESCE(backchannelLogoutSessionRequired,0)=0 " +
        "AND EXISTS(SELECT 1 FROM oauthClientResource WHERE clientId=?3 AND resourceId=?6)",
      params: [uri, new Date().toISOString(), spec.clientId, JSON.stringify([spec.origin + "/auth/callback"]),
        JSON.stringify([spec.origin + "/sign-in"]), spec.origin + "/api"]
    },
    {
      sql: "INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES (?,?,'client_logout_configure',?," +
        "CASE WHEN changes()=1 THEN 'succeeded' ELSE NULL END)",
      params: [randomUUID(), "cli:" + spec.worker.account_id, spec.clientId]
    }
  ];
}

runUpgrade(import.meta.url, operation, webBackchannel);
