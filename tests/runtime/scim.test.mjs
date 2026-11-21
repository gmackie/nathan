import test, { after } from "node:test";
import assert from "node:assert/strict";
import { authWorker, base64url } from "./helpers.mjs";

const HOST = "login.example.test";
let mf;
after(() => mf?.dispose());

test("SCIM requests reach the connection's directory in the Workers runtime", async () => {
  mf = await authWorker(HOST);
  const db = await mf.getD1Database("DB");
  const token = "nathscim_" + base64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));
  await db.prepare("INSERT INTO nathan_scim_connections(id,domain,enabled,created_by) VALUES('acme','acme.example',1,'test')").run();
  await db.prepare("INSERT INTO nathan_scim_credentials(id,connection_id,token_hash) VALUES('t1','acme',?)").bind(digest).run();
  const response = await mf.dispatchFetch("https://" + HOST + "/scim/v2/acme/ServiceProviderConfig",
    { headers: { Authorization: "Bearer " + token } });
  assert.equal(response.status, 200, "got " + response.status + " " + await response.clone().text());
  const unauthenticated = await mf.dispatchFetch("https://" + HOST + "/scim/v2/acme/Users");
  assert.equal(unauthenticated.status, 401);
});
