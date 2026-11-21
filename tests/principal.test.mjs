import test, { after } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, UnsecuredJWT, exportJWK, generateKeyPair } from "jose";
import { signPrincipal, verifyPrincipal, principalKey, PRINCIPAL_HEADER, MAX_PRINCIPAL_LIFETIME } from "../src/shared/principal.mjs";
import { nathan } from "../src/sdk/nathan.mjs";
import { evaluateAccess } from "../src/shared/policy.mjs";

const encodedKey = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
const otherKey = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
const GATEWAY = "https://app.example.test";
const claims = { sub: "u1", email: "u1@example.test", app: "billing", roles: ["editor"], permissions: ["invoices:read", "invoices:write"] };
const sign = (overrides = {}, options = {}) => signPrincipal({ ...claims, ...overrides }, { key: encodedKey, issuer: GATEWAY, ...options });
const verify = (token, options = {}) => verifyPrincipal(token, { key: encodedKey, app: "billing", issuer: GATEWAY, ...options });
const rawKey = () => principalKey(encodedKey);
const now = () => Math.floor(Date.now() / 1000);

test("principal keys must be at least 32 random bytes in base64url", () => {
  assert.equal(principalKey(encodedKey).byteLength, 32);
  for (const bad of ["", "short", "a".repeat(20), "not base64url!".repeat(4), undefined, 12])
    assert.throws(() => principalKey(bad), /PRINCIPAL_KEY/, String(bad));
});

test("a gateway-signed principal round-trips with a lifetime of at most 60 seconds", async () => {
  const token = await sign();
  const principal = await verify(token);
  assert.deepEqual({ sub: principal.sub, email: principal.email, app: principal.app, roles: principal.roles, permissions: principal.permissions },
    claims);
  assert.ok(principal.exp - principal.iat <= MAX_PRINCIPAL_LIFETIME);
  assert.equal(MAX_PRINCIPAL_LIFETIME, 60);
  assert.equal(PRINCIPAL_HEADER, "X-Nathan-Principal");
});

test("forged, unsigned, re-keyed or tampered principals are rejected", async () => {
  const token = await sign();
  const [header, payload, signature] = token.split(".");
  const tampered = JSON.parse(Buffer.from(payload, "base64url"));
  tampered.permissions.push("admin:all");
  const forgedPayload = Buffer.from(JSON.stringify(tampered)).toString("base64url");
  const cases = {
    flippedSignature: header + "." + payload + "." + (signature[0] === "A" ? "B" : "A") + signature.slice(1),
    elevatedPayload: header + "." + forgedPayload + "." + signature,
    otherKey: await signPrincipal(claims, { key: otherKey, issuer: GATEWAY }),
    unsigned: new UnsecuredJWT({ ...claims }).setIssuer(GATEWAY).setAudience("billing").setIssuedAt().setExpirationTime("30s").encode(),
    noSignature: header + "." + payload + ".",
    garbage: "not-a-token",
    empty: "",
    oversized: token + "A".repeat(20000)
  };
  for (const [name, value] of Object.entries(cases)) assert.equal(await verify(value), null, name);
  assert.equal(await verify(undefined), null);
});

test("principals for another app, another gateway, wrong type or algorithm are rejected", async () => {
  assert.equal(await verify(await sign(), { app: "payroll" }), null);
  assert.equal(await verify(await sign({ app: "payroll" })), null, "app claim must match the audience");
  assert.equal(await verify(await sign(), { issuer: "https://other.example.test" }), null);
  const base = new SignJWT({ ...claims }).setIssuer(GATEWAY).setAudience("billing").setSubject("u1").setIssuedAt().setExpirationTime("30s");
  assert.equal(await verify(await base.setProtectedHeader({ alg: "HS256", typ: "JWT" }).sign(rawKey())), null, "typ");
  const hs512 = new SignJWT({ ...claims }).setIssuer(GATEWAY).setAudience("billing").setSubject("u1").setIssuedAt().setExpirationTime("30s")
    .setProtectedHeader({ alg: "HS512", typ: "nathan-principal+jwt" });
  assert.equal(await verify(await hs512.sign(new Uint8Array(64).fill(1))), null, "alg");
});

test("expired, future-dated or long-lived principals are rejected", async () => {
  const craft = (iat, exp, extra = {}) => new SignJWT({ ...claims, ...extra }).setProtectedHeader({ alg: "HS256", typ: "nathan-principal+jwt" })
    .setIssuer(GATEWAY).setAudience("billing").setSubject("u1").setIssuedAt(iat).setExpirationTime(exp).sign(rawKey());
  const t = now();
  assert.ok(await verify(await craft(t, t + 60)), "a 60 s principal is accepted");
  assert.equal(await verify(await craft(t - 120, t - 60)), null, "expired");
  assert.equal(await verify(await craft(t, t + 61)), null, "lifetime over 60 s");
  assert.equal(await verify(await craft(t + 120, t + 150)), null, "issued in the future");
  assert.equal(await verify(await craft(t, t + 30, { roles: "editor" })), null, "roles must be an array");
  assert.equal(await verify(await craft(t, t + 30, { permissions: ["Bad Key"] })), null, "permission keys are validated");
  assert.equal(await verify(await craft(t, t + 30, { email: 7 })), null, "email must be a string or null");
  assert.ok(await verify(await craft(t, t + 30, { email: null })), "email may be null");
  assert.equal(await verify(await sign({}, { lifetime: 61 })), null);
  await assert.rejects(() => sign({ roles: ["Not A Role"] }), /Invalid principal/);
});

// ---- SDK -------------------------------------------------------------------------------------

const ISSUER = "https://login.example.test/api/auth";
const AUDIENCE = "https://api.example.test";
const { privateKey, publicKey } = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = String(input instanceof Request ? input.url : input);
  if (url === ISSUER + "/jwks") return Response.json({ keys: [jwk] });
  return realFetch(input, init);
};
after(() => { globalThis.fetch = realFetch; });

const accessToken = (sub, { typ = "at+jwt", audience = AUDIENCE, extra = {} } = {}) =>
  new SignJWT({ scope: "openid", ...extra }).setProtectedHeader({ alg: "ES256", kid: "k1", typ })
    .setIssuer(ISSUER).setAudience(audience).setSubject(sub).setIssuedAt().setExpirationTime("5m").sign(privateKey);

/** A stand-in for the NATHAN service binding: the identity Worker's resolveAccess RPC. */
const binding = decide => ({
  calls: [],
  async resolveAccess(input) { this.calls.push(input); return { ...decide(input), email: input.subject + "@example.test" }; }
});
const env = (extra = {}) => ({ NATHAN_PRINCIPAL_KEY: encodedKey, NATHAN_APPLICATION_ID: "billing", NATHAN_ISSUER: ISSUER, NATHAN_AUDIENCE: AUDIENCE, ...extra });
const request = headers => new Request("https://billing.internal/invoices", { headers });

test("nathan() reads a gateway principal and answers hasRole, can and require", async () => {
  const user = await nathan(request({ [PRINCIPAL_HEADER]: await sign() }), env());
  assert.equal(user.authenticated, true);
  assert.equal(user.allowed, true);
  assert.equal(user.via, "gateway");
  assert.equal(user.sub, "u1");
  assert.equal(user.email, "u1@example.test");
  assert.ok(user.hasRole("editor"));
  assert.ok(!user.hasRole("admin"));
  assert.ok(user.can("invoices:write"));
  assert.ok(!user.can("invoices:delete"));
  assert.equal(user.require("invoices:write"), null);
  const denied = user.require("invoices:delete");
  assert.equal(denied.status, 403);
  assert.deepEqual(await denied.json(), { error: "forbidden", permission: "invoices:delete" });
  assert.equal(user.requireRole("admin").status, 403);
  assert.equal(user.forbidden().status, 403);
});

test("nathan() rejects a forged or unsigned principal and never falls back to a bearer token", async () => {
  const forged = new UnsecuredJWT({ ...claims }).setIssuer(GATEWAY).setAudience("billing").setIssuedAt().setExpirationTime("30s").encode();
  const rpc = binding(() => ({ allowed: true, reason: "granted", roles: ["editor"], permissions: ["invoices:write"] }));
  for (const value of [forged, await signPrincipal(claims, { key: otherKey, issuer: GATEWAY }), "garbage"]) {
    const user = await nathan(request({ [PRINCIPAL_HEADER]: value, Authorization: "Bearer " + await accessToken("u1") }), env({ NATHAN: rpc }));
    assert.equal(user.authenticated, false);
    assert.equal(user.can("invoices:write"), false);
    assert.equal(user.hasRole("editor"), false);
    const response = user.require("invoices:write");
    assert.equal(response.status, 401);
  }
  assert.equal(rpc.calls.length, 0);
});

test("nathan() fails closed when the SDK is not configured", async () => {
  const token = await sign();
  for (const missing of [{ NATHAN_PRINCIPAL_KEY: undefined }, { NATHAN_APPLICATION_ID: undefined }, { NATHAN_PRINCIPAL_KEY: "short" }]) {
    const user = await nathan(request({ [PRINCIPAL_HEADER]: token }), env(missing));
    assert.equal(user.authenticated, false, JSON.stringify(missing));
  }
  const anonymous = await nathan(request({}), env());
  assert.equal(anonymous.authenticated, false);
  assert.equal(anonymous.forbidden().status, 401);
});

test("nathan() API mode verifies the bearer access token and resolves roles through the NATHAN binding", async () => {
  const rpc = binding(() => ({ allowed: true, reason: "granted", roles: ["viewer"], permissions: ["invoices:read"] }));
  const user = await nathan(request({ Authorization: "Bearer " + await accessToken("u7") }), env({ NATHAN: rpc }));
  assert.equal(user.via, "token");
  assert.equal(user.sub, "u7");
  assert.ok(user.can("invoices:read"));
  assert.deepEqual(rpc.calls, [{ applicationId: "billing", subject: "u7" }]);
  for (const bad of [await accessToken("u7", { typ: "JWT" }), await accessToken("u7", { audience: "https://other.example.test" }),
    await accessToken("u7", { extra: { cnf: { jkt: "x" } } }), "abc"]) {
    const rejected = await nathan(request({ Authorization: "Bearer " + bad }), env({ NATHAN: rpc }));
    assert.equal(rejected.authenticated, false);
  }
  const noBinding = await nathan(request({ Authorization: "Bearer " + await accessToken("u7") }), env());
  assert.equal(noBinding.authenticated, true);
  assert.equal(noBinding.allowed, false, "without a role source the API path grants nothing");
  assert.equal(noBinding.can("invoices:read"), false);
  assert.equal(noBinding.forbidden().status, 403);
});

test("nathan() API mode refuses machine (client-credentials) tokens: sub equals client_id or azp", async () => {
  const rpc = binding(() => ({ allowed: true, reason: "granted", roles: ["viewer"], permissions: ["invoices:read"] }));
  for (const extra of [{ client_id: "svc-1" }, { azp: "svc-1" }, { client_id: "svc-1", azp: "svc-1" }]) {
    const machine = await nathan(request({ Authorization: "Bearer " + await accessToken("svc-1", { extra }) }), env({ NATHAN: rpc }));
    assert.equal(machine.authenticated, false, JSON.stringify(extra));
    assert.equal(machine.forbidden().status, 401);
  }
  assert.deepEqual(rpc.calls, [], "a machine token never reaches the role lookup");
  // A user token from a client (sub is the user, client_id/azp the client) is fine.
  const user = await nathan(request({ Authorization: "Bearer " + await accessToken("u7", { extra: { client_id: "svc-1", azp: "svc-1" } }) }), env({ NATHAN: rpc }));
  assert.equal(user.authenticated, true);
  assert.ok(user.can("invoices:read"));
});

// The SDK maps one evaluator decision to the same answers on both paths. Locally signed tokens and a
// stand-in binding; tests/runtime/rbac.test.mjs proves the same table with tokens issued by the
// built identity Worker and the real NathanVerifier RPC.
test("the SDK gives the same answers for one decision on the gateway and bearer paths (unit table)", async () => {
  const roles = [{ key: "viewer", permissions: ["invoices:read"] }, { key: "editor", permissions: ["invoices:read", "invoices:write"] }];
  const scenarios = {
    directGrant: { app: { id: "billing", enabled: true, accessMode: "approved" }, user: { id: "u1", banned: false }, groups: [], grants: [{ role: "editor", principalType: "user", principalId: "u1" }], roles },
    groupGrant: { app: { id: "billing", enabled: true, accessMode: "approved" }, user: { id: "u1", banned: false }, groups: ["finance"], grants: [{ role: "viewer", principalType: "group", principalId: "finance" }], roles },
    signedIn: { app: { id: "billing", enabled: true, accessMode: "any_signed_in" }, user: { id: "u1", banned: false }, groups: [], grants: [], roles },
    noGrant: { app: { id: "billing", enabled: true, accessMode: "approved" }, user: { id: "u1", banned: false }, groups: [], grants: [], roles },
    blocked: { app: { id: "billing", enabled: true, accessMode: "any_signed_in" }, user: { id: "u1", banned: true }, groups: [], grants: [], roles },
    disabled: { app: { id: "billing", enabled: false, accessMode: "approved" }, user: { id: "u1", banned: false }, groups: [], grants: [{ role: "editor", principalType: "user", principalId: "u1" }], roles }
  };
  const questions = user => ({
    allowed: user.authenticated && user.allowed, roles: user.roles, permissions: user.permissions,
    canRead: user.can("invoices:read"), canWrite: user.can("invoices:write"), isEditor: user.hasRole("editor"),
    requireWrite: user.require("invoices:write")?.status ?? 200
  });
  for (const [name, input] of Object.entries(scenarios)) {
    const decision = evaluateAccess(input);
    // Gateway path: the gateway only forwards allowed principals and answers 403 itself otherwise.
    const viaGateway = decision.allowed
      ? questions(await nathan(request({ [PRINCIPAL_HEADER]: await sign({ sub: "u1", roles: decision.roles, permissions: decision.permissions }) }), env()))
      : { allowed: false, roles: [], permissions: [], canRead: false, canWrite: false, isEditor: false, requireWrite: 403 };
    const viaToken = questions(await nathan(request({ Authorization: "Bearer " + await accessToken("u1") }), env({ NATHAN: binding(() => decision) })));
    assert.deepEqual(viaToken, viaGateway, name);
  }
});
