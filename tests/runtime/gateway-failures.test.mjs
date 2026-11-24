/**
 * NATH-13 gateway failure handling in workerd: every way the access check can be misconfigured or
 * unavailable fails closed with 503, never with a pass-through and never with a silent 403.
 * All gateways share one sessions database, so one login is valid on each of them.
 */
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { bundle, migrateGateway, randomKey, cookiesOf, start, COMPAT } from "./helpers.mjs";

const AUTH_HOST = "login.example.test";
const ISSUER = "https://" + AUTH_HOST + "/api/auth";
const ORIGIN = "https://billing.example.test";
const CLIENT = "billing-gateway";
const { privateKey, publicKey } = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };

const issued = new Map();
async function idp(request) {
  const url = new URL(request.url);
  if (url.href === ISSUER + "/.well-known/openid-configuration")
    return Response.json({ issuer: ISSUER, authorization_endpoint: ISSUER + "/oauth2/authorize", token_endpoint: ISSUER + "/oauth2/token", jwks_uri: ISSUER + "/jwks" });
  if (url.href === ISSUER + "/jwks") return Response.json({ keys: [jwk] });
  if (url.href === ISSUER + "/oauth2/token" && request.method === "POST") {
    const grant = issued.get(new URLSearchParams(await request.text()).get("code"));
    if (!grant) return Response.json({ error: "invalid_grant" }, { status: 400 });
    const idToken = await new SignJWT({ nonce: grant.nonce, email: "u1@example.test", email_verified: true, sid: "sid-1" })
      .setProtectedHeader({ alg: "ES256", kid: "k1" }).setIssuer(ISSUER).setAudience(CLIENT).setSubject(grant.sub)
      .setIssuedAt().setExpirationTime("5m").sign(privateKey);
    return Response.json({ id_token: idToken, access_token: "x", token_type: "Bearer" });
  }
  return new Response("unexpected outbound " + url.href, { status: 599 });
}

const stub = (name, body) => ({
  name, modules: true, ...COMPAT,
  script: 'import { WorkerEntrypoint } from "cloudflare:workers";\n' +
    "export class NathanVerifier extends WorkerEntrypoint { async resolveAccess() { " + body + " } }\n" +
    "export default { fetch() { return new Response(null, { status: 404 }); } };"
});
const KEY = randomKey();
const gatewayWorker = (name, { nathan = { name: "nathan-allow", entrypoint: "NathanVerifier" }, vars = {} } = {}) => ({
  name, modules: true, ...COMPAT, scriptPath: bundle("gateway"),
  d1Databases: { SESSIONS: "failure-gateway-sessions" },
  serviceBindings: { UPSTREAM: () => new Response("upstream ok"), ...(nathan ? { NATHAN: nathan } : {}) },
  outboundService: idp,
  bindings: Object.fromEntries(Object.entries({
    NATHAN_ISSUER: ISSUER, PUBLIC_ORIGIN: ORIGIN, APPLICATION_ID: "billing",
    OIDC_CLIENT_ID: CLIENT, OIDC_CLIENT_SECRET: "s".repeat(40), SESSION_ENCRYPTION_KEY: randomKey(),
    SESSION_TTL_SECONDS: "3600", REQUIRE_AAL2: "false", NATHAN_PRINCIPAL_KEY: KEY, ACCESS_CACHE_TTL_SECONDS: "0", ...vars
  }).filter(([, value]) => value !== undefined))
});

/** Gateways that must answer 503, by the misconfiguration or outage they exercise. */
const FAILING = {
  "missing NATHAN binding": gatewayWorker("g-no-binding", { nathan: null }),
  "RPC throws": gatewayWorker("g-rpc-throws", { nathan: { name: "nathan-throws", entrypoint: "NathanVerifier" } }),
  "binding not pinned (real NathanVerifier, no props)": gatewayWorker("g-unpinned", { nathan: { name: "auth", entrypoint: "NathanVerifier" } }),
  "binding pinned to another app (real NathanVerifier)": gatewayWorker("g-mismatch", { nathan: { name: "auth", entrypoint: "NathanVerifier", props: { applicationId: "payroll" } } }),
  "NATHAN_PRINCIPAL_KEY missing": gatewayWorker("g-no-key", { vars: { NATHAN_PRINCIPAL_KEY: undefined } }),
  "NATHAN_PRINCIPAL_KEY shorter than 32 bytes": gatewayWorker("g-short-key", { vars: { NATHAN_PRINCIPAL_KEY: randomKey().slice(0, 30) } }),
  "NATHAN_PRINCIPAL_KEY missing, even for a denied user": gatewayWorker("g-no-key-deny", { nathan: { name: "nathan-deny", entrypoint: "NathanVerifier" }, vars: { NATHAN_PRINCIPAL_KEY: undefined } }),
  "ACCESS_CACHE_TTL_SECONDS=61": gatewayWorker("g-ttl-61", { vars: { ACCESS_CACHE_TTL_SECONDS: "61" } }),
  "ACCESS_CACHE_TTL_SECONDS=3600": gatewayWorker("g-ttl-hour", { vars: { ACCESS_CACHE_TTL_SECONDS: "3600" } }),
  "ACCESS_CACHE_TTL_SECONDS=1.5": gatewayWorker("g-ttl-fraction", { vars: { ACCESS_CACHE_TTL_SECONDS: "1.5" } })
};

let mf, cookie;
before(async () => {
  mf = await start({
    workers: [
      gatewayWorker("g-control", { vars: { ACCESS_CACHE_TTL_SECONDS: "60" } }),
      gatewayWorker("g-deny", { nathan: { name: "nathan-deny", entrypoint: "NathanVerifier" } }),
      ...Object.values(FAILING),
      stub("nathan-allow", 'return { allowed: true, reason: "granted", roles: [], permissions: [] };'),
      stub("nathan-deny", 'return { allowed: false, reason: "no_grant", roles: [], permissions: [] };'),
      stub("nathan-throws", 'throw new Error("identity Worker unavailable");'),
      {
        name: "auth", modules: true, ...COMPAT, scriptPath: bundle("auth"),
        d1Databases: { DB: "failure-auth-db" },
        durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
        bindings: {
          NATHAN_ISSUER: "https://" + AUTH_HOST, NATHAN_ADMIN_EMAILS: "", NATHAN_SECURITY_PROFILE: "business",
          NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_INSTALL_ACTIVE: "true", NATHAN_MCP_WRITE_ENABLED: "false",
          NATHAN_REALM_APEX: "", ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false", NATHAN_ADMIN_STEPUP_REQUIRED: "true",
          BETTER_AUTH_SECRET: randomKey() + randomKey(), NATHAN_CONFIG_KEY: randomKey()
        }
      }
    ]
  });
  await migrateGateway(await mf.getD1Database("SESSIONS", "g-control"));
  const control = await mf.getWorker("g-control");
  const begin = await control.fetch(ORIGIN + "/__nathan/login?returnTo=/", { redirect: "manual" });
  const authorize = new URL(begin.headers.get("Location"));
  const code = "code-" + crypto.randomUUID();
  issued.set(code, { nonce: authorize.searchParams.get("nonce"), sub: "u1" });
  const callback = await control.fetch(ORIGIN + "/__nathan/callback?code=" + code + "&state=" + authorize.searchParams.get("state"),
    { redirect: "manual", headers: { Cookie: "__Host-nathan-flow=" + cookiesOf(begin)["__Host-nathan-flow"].value } });
  assert.equal(callback.status, 303, await callback.clone().text());
  cookie = "__Host-nathan-session=" + cookiesOf(callback)["__Host-nathan-session"].value;
});
after(() => mf?.dispose());

const visit = async name => (await mf.getWorker(name)).fetch(ORIGIN + "/reports", { headers: { Cookie: cookie } });

test("controls: a well-configured gateway proxies (TTL 60 is allowed) and an evaluator deny is a 403", async () => {
  const ok = await visit("g-control");
  assert.equal(ok.status, 200, await ok.clone().text());
  assert.equal(await ok.text(), "upstream ok");
  const denied = await visit("g-deny");
  assert.equal(denied.status, 403);
  assert.match(await denied.text(), /Access denied/);
});

for (const [scenario, worker] of Object.entries(FAILING)) {
  test("fails closed with 503: " + scenario, async () => {
    const response = await visit(worker.name);
    assert.equal(response.status, 503, scenario + ": " + await response.clone().text());
    assert.equal(await response.text(), "Access verification temporarily unavailable");
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  });
}
