import test, { after } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { bundle, migrate, randomKey, cookiesOf, start, authWorker } from "./helpers.mjs";
import { verifyIdentityHostname } from "../../src/installer/verify-idp.ts";

const HOST = "login.example.test";
const INSTALLER = "https://install.example.test";
const instances = [];
after(() => Promise.all(instances.map(mf => mf.dispose())));

test("installer verify stage accepts a freshly installed auth Worker", async () => {
  const mf = await authWorker(HOST);
  instances.push(mf);
  await verifyIdentityHostname(HOST, (url, init) => mf.dispatchFetch(url, { ...init, redirect: "manual" }));
});

test("installer verify stage rejects an inactive auth Worker", async () => {
  const mf = await authWorker(HOST, { NATHAN_INSTALL_ACTIVE: "false" });
  instances.push(mf);
  await assert.rejects(
    verifyIdentityHostname(HOST, (url, init) => mf.dispatchFetch(url, { ...init, redirect: "manual" })),
    /not activated/);
});

test("installer Cloudflare login sets state and session cookies", async () => {
  const outbound = async request => {
    const url = new URL(request.url);
    if (url.href === "https://dash.cloudflare.com/oauth2/token") {
      const form = new URLSearchParams(await request.text());
      assert.equal(form.get("code"), "cf-code");
      assert.ok(form.get("code_verifier"), "PKCE verifier must be sent");
      return Response.json({ access_token: "cf-access", refresh_token: "cf-refresh", expires_in: 3600 });
    }
    if (url.href === "https://api.cloudflare.com/client/v4/user")
      return Response.json({ success: true, result: { id: "u1", email: "owner@example.test" } });
    return new Response("unexpected outbound " + url.href, { status: 599 });
  };
  const mf = await start({
    scriptPath: bundle("installer"),
    d1Databases: { INSTALLER_DB: "installer-db" },
    serviceBindings: { ASSETS: () => new Response("asset") },
    outboundService: outbound,
    bindings: {
      PUBLIC_ORIGIN: INSTALLER, CF_OAUTH_CLIENT_ID: "cf-client", CF_OAUTH_CLIENT_SECRET: "cf-secret",
      CF_OAUTH_SCOPES: "user-details.read", INSTALLER_ENCRYPTION_KEY: randomKey()
    }
  });
  instances.push(mf);
  const db = await mf.getD1Database("INSTALLER_DB");
  for (const file of readdirSync("migrations/installer").filter(f => f.endsWith(".sql")).sort())
    await migrate(db, "migrations/installer/" + file);

  const begin = await mf.dispatchFetch(INSTALLER + "/api/login", { redirect: "manual" });
  assert.equal(begin.status, 302, "login must redirect to Cloudflare, got " + begin.status + " " + await begin.clone().text());
  const authorize = new URL(begin.headers.get("Location"));
  assert.equal(authorize.origin, "https://dash.cloudflare.com");
  const state = cookiesOf(begin)["__Host-nathan-installer-state"];
  assert.equal(state?.value, authorize.searchParams.get("state"), "state cookie must match the authorize state");

  const callback = await mf.dispatchFetch(INSTALLER + "/api/callback?code=cf-code&state=" + state.value,
    { redirect: "manual", headers: { Cookie: "__Host-nathan-installer-state=" + state.value } });
  assert.equal(callback.status, 303, "callback must complete, got " + callback.status + " " + await callback.clone().text());
  const jar = cookiesOf(callback);
  assert.ok(jar["__Host-nathan-installer"]?.value, "callback must set the installer session cookie");
  assert.match(jar["__Host-nathan-installer-state"].raw, /Max-Age=0/);

  const session = await mf.dispatchFetch(INSTALLER + "/api/session",
    { headers: { Cookie: "__Host-nathan-installer=" + jar["__Host-nathan-installer"].value } });
  assert.equal(session.status, 200);
  assert.deepEqual((await session.json()).user, { email: "owner@example.test" });
});
