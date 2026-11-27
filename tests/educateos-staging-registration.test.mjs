import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readdirSync, readFileSync } from "node:fs";
import * as registration from "../deploy/staging/educateos-registration/registration.mjs";
import * as hosted from "../deploy/staging/educateos-registration/hosted.mjs";
import { CloudflareClient } from "../scripts/lib/cloudflare.mjs";

const userId = "staging-test-user";
const clientId = "nmcp_fixture";
const app = "educateos-staging";
const resource = "https://staging.educateos.io/mcp";
const issuer = "https://nathan-stg.gmac.io";
const callback = "http://127.0.0.1:33418/callback";
const credentialRef = "gmac-idp-staging-cf-d1-admin";
const version = { id: "ver_b5a7b990-5067-4d3d-b59e-f148eff383ce", credential: credentialRef, actor: "rotation:" + credentialRef };
const digest = "sha256:032dfaa521fdafcd7a17f53d8b5ae159215993063bb771ce3fb026705a9385da";
const entry = () => ({
  ref: credentialRef, retrievableBy: ["nathan-cli"], latestVersion: null,
  issuance: { provider: "cloudflare-mcp", authority: "gmac-cloudflare-mcp", authorityKind: "mcp-oauth",
    authorityReady: true, policy: { id: credentialRef, providerId: "cloudflare-mcp", authority: "gmac-cloudflare-mcp",
      providerAccount: "c07a7e704db1808e1fff91bed2b1cd49", scopes: ["D1 Write"], destinations: [] } }
});

test("the one-time Workflow refuses an otherwise valid configured user outside the approved grant", () => {
  const original = "nmcp_IRafVNUd0evxoUFqUycqDsJ958Be9KQGNONWw7bPW4U";
  assert.throws(() => hosted.requireApprovedTarget("different-verified-staging-user", original), /approved staging target/);
  assert.throws(() => hosted.requireApprovedTarget(undefined, original), /approved staging target/);
});

function fixture() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  for (const file of readdirSync("migrations").filter(f => /^\d{4}_.*\.sql$/.test(f)).sort()) {
    db.exec(readFileSync("migrations/" + file, "utf8"));
  }
  db.prepare('INSERT INTO "user"(id,name,email,"emailVerified","createdAt","updatedAt") VALUES (?,?,?,1,0,0)')
    .run(userId, "Teacher", "teacher@example.test");
  const batches = [];
  const api = {
    db, batches,
    async databaseNamed(name) {
      return {name, uuid:"6ee7794d-d20d-4b7b-8518-984b8efe26e6"};
    },
    async queryDatabase(_id, sql, params = []) {
      assert.match(sql, /^\s*SELECT\b/i, "all writes belong to a single D1 batch");
      return db.prepare(sql).all(...params);
    },
    async batchDatabase(_id, statements) {
      const writing = statements.some(s => !/^\s*SELECT\b/i.test(s.sql));
      if (writing) {
        batches.push(statements);
        api.beforeWrite?.();
      }
      db.exec("BEGIN");
      try {
        const result = statements.map(s => db.prepare(s.sql).all(...(s.params ?? [])));
        db.exec("COMMIT");
        if (writing && api.loseResponse) throw Error("response lost");
        return result;
      } catch (error) {
        if (db.isTransaction) db.exec("ROLLBACK");
        throw error;
      }
    }
  };
  return api;
}

test("the hosted apply verifies the fixed grant, scope catalog and audit and can read it back without writing again", async () => {
  const api = fixture();
  const result = await registration.applyAndVerify(api, userId, clientId);
  assert.equal(result.app, app);
  assert.equal(result.role, "teacher");
  assert.equal(result.userId, userId);
  assert.equal(result.resource, resource);
  assert.deepEqual(result.permissions, ["lms:draft","lms:read","lms:write","mcp:tools"]);
  assert.deepEqual(result.sensitiveScopes, ["lms:write"]);
  assert.equal(result.originalClientActive, false);
  assert.equal(api.batches.length, 1);
  for (const action of ["app_manifest_apply","rbac_manifest_sync","application_enable","mcp_resource_register","rbac_grant_create"]) {
    assert.deepEqual(api.db.prepare("SELECT DISTINCT outcome FROM nathan_security_audit WHERE action=? ORDER BY outcome")
      .all(action).map(row => row.outcome), ["attempted","succeeded"]);
  }
  await registration.applyAndVerify(api, userId, clientId);
  assert.equal(api.batches.length, 1);
  api.db.prepare("UPDATE nathan_mcp_scopes SET sensitive=0 WHERE resource=? AND scope='lms:write'").run(resource);
  await assert.rejects(registration.applyAndVerify(api, userId, clientId), /reconcil/i);
  assert.equal(api.batches.length, 1);
});

test("an incomplete older apply, an ineligible teacher, and an audience collision all leave the target alone", async () => {
  for (const setup of [
    db => db.prepare("INSERT INTO nathan_security_audit(id,actor,action,target,outcome) VALUES ('old','cli:account','app_manifest_apply',?,'attempted')").run(app),
    db => db.prepare('UPDATE "user" SET banned=1 WHERE id=?').run(userId),
    db => db.prepare("INSERT INTO nathan_applications(id,hostname) VALUES ('other','staging.educateos.io')").run()
  ]) {
    const api = fixture();
    setup(api.db);
    await assert.rejects(registration.applyAndVerify(api, userId, clientId));
    assert.equal(api.db.prepare("SELECT count(*) n FROM nathan_rbac_grants").get().n, 0);
    assert.equal(api.batches.length, 0);
  }
});

test("a changed precondition rolls back the batch, and a lost commit response is reconciled read-only", async () => {
  const race = fixture();
  const auditCount = () => race.db.prepare("SELECT count(*) n FROM nathan_security_audit").get().n;
  const before = auditCount();
  race.beforeWrite = () => race.db.prepare('UPDATE "user" SET "emailVerified"=0 WHERE id=?').run(userId);
  await assert.rejects(registration.applyAndVerify(race, userId, clientId));
  assert.equal(race.db.prepare("SELECT count(*) n FROM nathan_applications").get().n, 0);
  assert.equal(auditCount(), before);
  const lost = fixture();
  lost.loseResponse = true;
  assert.equal((await registration.applyAndVerify(lost, userId, clientId)).role, "teacher");
  assert.equal(lost.batches.length, 1);
});

test("the hosted helper waits for Llavero's exact issuance and refuses a different account or consumer", async () => {
  const item = entry();
  const list = () => Response.json({ credentials: [item] });
  assert.equal(await hosted.issuedVersion("fixture-client", async (url, init) => {
    assert.equal(String(url), "https://keys.gmac.io/api/llavero/agent/credentials");
    assert.equal(init.redirect, "manual");
    return list();
  }), null);
  item.latestVersion = version;
  assert.equal(await hosted.issuedVersion("fixture-client", list), version.id);
  item.latestVersion = { ...version, actor: "owner:manual-intake" };
  await assert.rejects(hosted.issuedVersion("fixture-client", list));
  item.latestVersion = version;
  item.retrievableBy = ["another-agent"];
  await assert.rejects(hosted.issuedVersion("fixture-client", list));
  item.retrievableBy = ["nathan-cli"];
  item.issuance.policy.providerAccount = "other";
  await assert.rejects(hosted.issuedVersion("fixture-client", list));
});

test("the hosted helper releases only the selected rotation version to the staging operation", async () => {
  const item = { ...entry(), latestVersion: version };
  const released = { version, value: "fixture-only", extra: "unrelated" };
  const approved = { action: "rotation.approve", subject: { policy: credentialRef, digest } };
  const issued = { action: "rotate.issue", actor: version.actor, subject: {
    policy: credentialRef, credential: credentialRef, stage: "custody", versionId: version.id
  } };
  const audit = { chain: { ok: true }, events: [approved, issued] };
  const request = async (url, init) => {
    assert.equal(init.redirect, "manual");
    assert.equal(init.headers.Authorization, "Bearer fixture-client");
    if (url.endsWith("/audit")) return Response.json(audit);
    if (init.method === "GET") return Response.json({ credentials: [item] });
    assert.equal(url, "https://keys.gmac.io/api/llavero/agent/credentials/" + credentialRef + "/retrieve");
    assert.deepEqual(JSON.parse(init.body), { versionId: version.id });
    return Response.json(released);
  };
  const use = async value => {
    assert.equal(value, "fixture-only");
    return { app };
  };
  const run = () => hosted.withIssuedCredential("fixture-client", use, request);
  assert.deepEqual(await run(), { app });
  audit.events = [issued];
  await assert.rejects(run(), /approval/);
  audit.events = [issued, approved];
  await assert.rejects(run(), /approval/);
  audit.events = [{ ...approved, subject: { ...approved.subject, digest: "other" } }, issued];
  await assert.rejects(run(), /approval/);
  audit.events = [approved, issued, { action: "rotation.disable", subject: { policy: credentialRef } }];
  await assert.rejects(run(), /approval/);
  audit.events = [approved, issued];
  released.version = { ...version, actor: "owner:other" };
  await assert.rejects(run());
  released.version = { ...version, id: "ver_other" };
  await assert.rejects(run());
});

test("malformed Llavero replies cannot put upstream response text in Workflow errors", async () => {
  const invalid = () => new Response("private-upstream-text", { status: 200 });
  await assert.rejects(hosted.issuedVersion("fixture-client", invalid), error =>
    !error.message.includes("private-upstream") && /Llavero/.test(error.message));
});

test("Browser Run must observe the authorization request's own 302 to Nathan sign-in", () => {
  const url = hosted.authorizationUrl(clientId);
  assert.equal(url.searchParams.get("resource"), resource);
  assert.equal(url.searchParams.get("redirect_uri"), callback);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.match(url.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
  const trace = { firstUrl: url.href, status:302, location:"/sign-in", hops:1, finalStatus:200, finalUrl:issuer+"/sign-in" };
  assert.deepEqual(hosted.verifyRedirect(url, trace), {httpStatus:302, redirect:issuer+"/sign-in"});
  const expired = { firstUrl: url.href, finalUrl: url.href, status: 400, finalStatus: 400,
    hops: 0, pageTitle: "Unknown client · Nathan" };
  assert.equal(hosted.verifyRedirect(url, expired), null);
  assert.throws(() => hosted.verifyRedirect(url, { ...expired, pageTitle: "Invalid redirect · Nathan" }));
  for (const change of [{status:200},{hops:0},{hops:2},{firstUrl:issuer+"/sign-in"},
    {location:"https://example.test/sign-in"},{location:"/sign-in?error=invalid_target"},{location:"/sign-in?next=/somewhere"},
    {finalStatus:403},{finalUrl:issuer+"/sign-in?error=access_denied"}]) {
    assert.throws(() => hosted.verifyRedirect(url, {...trace, ...change}));
  }
});

test("the D1 REST client rejects redirects in workerd before parsing a response", async t => {
  const f = t.mock.method(globalThis, "fetch", async (_url, init) => {
    assert.equal(init.redirect, "manual");
    return new Response(null, {status:307, headers:{location:"https://elsewhere.example/"}});
  });
  await assert.rejects(new CloudflareClient("fixture", "test").accounts(), /redirect/i);
  assert.equal(f.mock.callCount(), 1);
});

test("a fresh public loopback client has no secret and never receives Llavero credentials", async () => {
  const request = async (url, init) => {
    assert.equal(url, issuer + "/mcp-oauth/register");
    assert.equal(new Headers(init.headers).has("Authorization"), false);
    assert.equal(init.redirect, "manual");
    assert.deepEqual(JSON.parse(init.body).redirect_uris, [callback]);
    return Response.json({client_id:clientId,token_endpoint_auth_method:"none",redirect_uris:[callback]}, {status:201});
  };
  assert.equal(await hosted.registerPublicClient(request), clientId);
  await assert.rejects(hosted.registerPublicClient(async () =>
    Response.json({client_id:clientId,token_endpoint_auth_method:"none",redirect_uris:["https://other.test/"]},{status:201})));
});

test("durable steps wait for issuance, checkpoint D1, and retry only Browser Run after a browser outage", async () => {
  const stored = new Map(), calls = [];
  const step = {
    async do(name, config, fn) {
      if (!stored.has(name)) stored.set(name, await fn());
      return stored.get(name);
    },
    async sleep() {}
  };
  let polls = 0, attempts = 0;
  const jobs = {
    version:async () => ++polls === 1 ? null : "v1",
    apply:async () => { calls.push("apply"); return {app,role:"teacher",userId,originalClientActive:false}; },
    register:async () => { calls.push("register"); return clientId; },
    probe:async () => { calls.push("probe"); if (++attempts===1) throw Error("unavailable"); return {httpStatus:302,redirect:issuer+"/sign-in"}; }
  };
  const run = () => hosted.completeRegistration(step,clientId,jobs);
  await assert.rejects(run(), /unavailable/);
  const receipt = await run();
  assert.deepEqual(calls, ["apply","register","probe","probe"]);
  assert.equal(receipt.clientId, clientId);
  assert.equal(receipt.clientSource, "fresh public loopback");
  assert.equal(receipt.oauth.httpStatus, 302);
});

test("a public client expiring after the D1 checkpoint is replaced without replaying the apply", async () => {
  const calls = [];
  const jobs = {
    version: async () => version.id,
    apply: async () => { calls.push("apply"); return { originalClientActive: true }; },
    register: async () => { calls.push("register"); return "nmcp_replacement"; },
    probe: async client => {
      calls.push(client);
      return client === clientId ? null : { httpStatus: 302, redirect: issuer + "/sign-in" };
    }
  };
  const step = { do: (_name, _config, fn) => fn() };
  const receipt = await hosted.completeRegistration(step, clientId, jobs);
  assert.deepEqual(calls, ["apply", clientId, "register", "nmcp_replacement"]);
  assert.equal(receipt.clientId, "nmcp_replacement");
  assert.equal(receipt.clientSource, "fresh public loopback");
  assert.equal(receipt.oauth.httpStatus, 302);
});

test("Browser Run can replace its own expired probe client after a long outage", async () => {
  const calls = [];
  const jobs = {
    version: async () => version.id,
    apply: async () => { calls.push("apply"); return { originalClientActive: false }; },
    register: async () => "nmcp_" + calls.push("register"),
    probe: async id => {
      calls.push(id);
      return id === "nmcp_2" ? null : { httpStatus: 302, redirect: issuer + "/sign-in" };
    }
  };
  const names = new Set();
  const step = { do(name, _config, fn) {
    assert.equal(names.has(name), false, "each new client has a separate Workflow checkpoint");
    names.add(name);
    return fn();
  } };
  const receipt = await hosted.completeRegistration(step, clientId, jobs);
  assert.deepEqual(calls, ["apply", "register", "nmcp_2", "register", "nmcp_4"]);
  assert.equal(receipt.clientId, "nmcp_4");
});
