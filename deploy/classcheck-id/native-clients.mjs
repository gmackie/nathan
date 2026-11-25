import { randomUUID } from "node:crypto";
import { auditStatement } from "../../src/shared/rbac-store.mjs";
import { runUpgrade, startUpgrade } from "./upgrade.mjs";

const operation = "classcheck_native_registration";

/** Run once for each stage after its PKCE clients are ready: node native-clients.mjs <stage> --apply. */
export function nativeClients(spec) {
  const actor = "cli:" + spec.worker.account_id;
  const now = new Date().toISOString();
  const statements = [startUpgrade(spec, operation)];
  for (const [app, label] of [["parent", "ClassCheck Parent"], ["driver", "ClassCheck Driver"]]) {
    const client = "classcheck-" + app + "-" + spec.stage;
    const redirect = "io.classcheck." + app + ":/oauth";
    statements.push({
      sql: "INSERT INTO oauthClient(id,clientId,name,disabled,skipConsent,subjectType,scopes,redirectUris,tokenEndpointAuthMethod," +
        "applicationType,grantTypes,responseTypes,requirePKCE,metadata,createdAt,updatedAt) " +
        "VALUES(?,?,?,0,0,'public',?,?,'none','native',?,?,1,?,?,?)",
      params: [randomUUID(), client, label, JSON.stringify(["openid","email","profile","offline_access"]), JSON.stringify([redirect]),
        JSON.stringify(["authorization_code","refresh_token"]), JSON.stringify(["code"]), JSON.stringify({appearance:{wordmark:"ClassCheck"}}), now, now]
    }, {
      sql: "INSERT INTO oauthClientResource(id,clientId,resourceId,createdAt) VALUES(?,?,?,?)",
      params: [randomUUID(), client, spec.origin + "/api", now]
    },
    auditStatement(actor,"client_create",client,"succeeded"),
    auditStatement(actor,"token_audience_link",client,"succeeded"));
  }
  return statements;
}

runUpgrade(import.meta.url, operation, nativeClients);
