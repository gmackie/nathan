import test from "node:test";
import assert from "node:assert/strict";
import { nathanMcp } from "../src/sdk/mcp.mjs";

const RESOURCE = "https://notes.example.com/mcp";
const ISSUER = "https://login.example.com/api/auth";
const TOKEN = "eyJhbGciOiJFZERTQSJ9." + "a".repeat(40) + "." + "b".repeat(40);
const bearer = token => new Request(RESOURCE, { method: "POST", headers: { Authorization: "Bearer " + token } });

function binding(answer) {
  const calls = [];
  return { calls, mcpGrant: async input => { calls.push(input); if (answer instanceof Error) throw answer; return typeof answer === "function" ? answer() : answer; } };
}
function withClock(start, run) {
  const real = Date.now;
  let now = start;
  Date.now = () => now;
  return Promise.resolve(run(ms => { now += ms; })).finally(() => { Date.now = real; });
}

test("nathanMcp validates its resource and serves RFC 9728 metadata naming Nathan's MCP authorization server", async () => {
  for (const bad of ["http://notes.example.com/mcp", "https://notes.example.com/mcp?x=1", "https://notes.example.com/mcp#a", "notes", undefined])
    assert.throws(() => nathanMcp({ NATHAN_ISSUER: ISSUER }, { resource: bad }), /exact https URL/, String(bad));
  assert.throws(() => nathanMcp({}, { resource: RESOURCE }), /NATHAN_ISSUER/);
  const mcp = nathanMcp({ NATHAN_ISSUER: ISSUER }, { resource: RESOURCE, scopes: ["notes:read", "notes:write"], resourceName: "Notes" });
  for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
    const response = await mcp.handle(new Request("https://notes.example.com" + path), () => assert.fail("not a tool call"));
    assert.deepEqual(await response.json(), { resource: RESOURCE, authorization_servers: ["https://login.example.com/mcp-oauth"],
      bearer_methods_supported: ["header"], scopes_supported: ["notes:read", "notes:write"], resource_name: "Notes" });
  }
  const challenge = await mcp.handle(new Request(RESOURCE, { method: "POST" }), () => assert.fail("no token"));
  assert.equal(challenge.status, 401);
  assert.equal(challenge.headers.get("WWW-Authenticate"),
    'Bearer resource_metadata="https://notes.example.com/.well-known/oauth-protected-resource/mcp", scope="notes:read notes:write"');
});

test("user.can reads Nathan's effective scopes; require() answers insufficient_scope", async () => {
  const exp = Math.floor(Date.now() / 1000) + 300;
  const NATHAN = binding({ active: true, sub: "u-alice", clientId: "nmcp_x", grantId: "g", scopes: ["notes:read"], exp });
  const mcp = nathanMcp({ NATHAN_ISSUER: ISSUER, NATHAN }, { resource: RESOURCE });
  const response = await mcp.handle(bearer(TOKEN), user => {
    assert.equal(user.sub, "u-alice");
    assert.equal(user.principalKind, "agent");
    assert.equal(user.can("notes:read"), true);
    assert.equal(user.can("notes:write"), false);
    assert.equal(user.require("notes:read"), null);
    return user.require("notes:write");
  });
  assert.equal(response.status, 403);
  assert.match(response.headers.get("WWW-Authenticate"), /^Bearer error="insufficient_scope", scope="notes:write", resource_metadata="/);
  assert.deepEqual(NATHAN.calls, [{ token: TOKEN, resource: RESOURCE }]);
  const inactive = nathanMcp({ NATHAN_ISSUER: ISSUER, NATHAN: binding({ active: false }) }, { resource: RESOURCE });
  const denied = await inactive.handle(bearer(TOKEN), () => assert.fail("inactive grant"));
  assert.equal(denied.status, 401);
  assert.match(denied.headers.get("WWW-Authenticate"), /error="invalid_token"/);
});

test("grant checks are cached for at most 30 seconds, so edits and revocation land within 60", async () => {
  await withClock(1_800_000_000_000, async advance => {
    let scopes = ["notes:read", "notes:write"];
    const exp = Math.floor(Date.now() / 1000) + 300;
    const NATHAN = binding(() => ({ active: true, sub: "u", clientId: "c", grantId: "g", scopes, exp }));
    const mcp = nathanMcp({ NATHAN_ISSUER: ISSUER, NATHAN }, { resource: RESOURCE, cacheSeconds: 3600 });
    const can = async () => (await mcp.authenticate(bearer(TOKEN))).can("notes:write");
    assert.equal(await can(), true);
    scopes = ["notes:read"]; // the user edits the connection
    advance(29_000);
    assert.equal(await can(), true, "still cached");
    assert.equal(NATHAN.calls.length, 1);
    advance(1_001);
    assert.equal(await can(), false, "a requested cache of an hour is clamped to 30 s");
    assert.equal(NATHAN.calls.length, 2);
  });
});

test("an unreachable Nathan fails closed with 503, and malformed tokens never reach Nathan", async () => {
  const down = binding(Error("binding down"));
  const mcp = nathanMcp({ NATHAN_ISSUER: ISSUER, NATHAN: down }, { resource: RESOURCE });
  const response = await mcp.handle(bearer(TOKEN), () => assert.fail("must not run"));
  assert.equal(response.status, 503);
  for (const token of ["short", "not a jwt at all but long enough to pass the length check", "a.b"]) {
    const r = await mcp.handle(bearer(token), () => assert.fail("must not run"));
    assert.equal(r.status, 401);
  }
  assert.equal(down.calls.length, 1);
});

test("without a binding: a JWKS outage answers 503 (retry), a bad token 401", async () => {
  const { generateKeyPair, exportJWK, SignJWT } = await import("jose");
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const other = await generateKeyPair("EdDSA", { crv: "Ed25519" });
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "EdDSA", use: "sig" };
  let n = 0;
  const sign = (claims, key = privateKey, kid = "k1") => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ principal_kind: "agent", nathan_grant: "g", client_id: "c", scope: "notes:read", sub: "u-alice", aud: RESOURCE,
      iat: now, exp: now + 300, jti: "j" + n++, ...claims }).setProtectedHeader({ alg: "EdDSA", typ: "at+jwt", kid }).sign(key);
  };
  const real = globalThis.fetch;
  /** Each case gets its own issuer so the SDK's per-issuer key set cache never carries over. */
  async function run(jwks, claims = {}, key, kid) {
    const host = "login" + n++ + ".example.com";
    const iss = "https://" + host + "/api/auth";
    const calls = [];
    globalThis.fetch = async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      calls.push(url);
      if (url === iss + "/jwks") return jwks(init);
      if (url === "https://" + host + "/mcp-oauth/grant") return Response.json({ active: true, sub: "u-alice", clientId: "c", grantId: "g", scopes: ["notes:read"], exp: Math.floor(Date.now() / 1000) + 300 });
      throw Error("unexpected fetch " + url);
    };
    try {
      const mcp = nathanMcp({ NATHAN_ISSUER: iss }, { resource: RESOURCE, cacheSeconds: 0 });
      const token = await sign({ iss, ...claims }, key, kid);
      const response = await mcp.handle(bearer(token), user => Response.json({ sub: user.sub }));
      return { status: response.status, calls, challenge: response.headers.get("WWW-Authenticate") };
    } finally { globalThis.fetch = real; }
  }
  const keys = () => Response.json({ keys: [jwk] });

  const ok = await run(keys);
  assert.equal(ok.status, 200, "a good token passes the local check and the grant check over HTTPS");
  assert.equal(ok.calls.length, 2);

  for (const [what, jwks] of [
    ["non-200 key set", () => new Response("upstream down", { status: 502 })],
    ["invalid key set (ERR_JWKS_INVALID)", () => Response.json({ nope: true })],
    ["key set timeout (ERR_JWKS_TIMEOUT)", () => { throw new DOMException("The operation timed out", "TimeoutError"); }],
    ["network error", () => { throw new TypeError("fetch failed"); }],
    ["not JSON", () => new Response("<html>", { status: 200, headers: { "Content-Type": "text/html" } })]
  ]) {
    const outage = await run(jwks);
    assert.equal(outage.status, 503, what + " is Nathan being unavailable, not a bad token");
    assert.equal(outage.calls.filter(u => u.endsWith("/mcp-oauth/grant")).length, 0, what);
  }

  for (const [what, claims, key, kid] of [
    ["signed by another key", {}, other.privateKey, "k1"],
    ["unknown key id (ERR_JWKS_NO_MATCHING_KEY)", {}, other.privateKey, "k2"],
    ["another audience", { aud: "https://other.example.com/mcp" }],
    ["expired", { exp: Math.floor(Date.now() / 1000) - 3600 }],
    ["not an agent token", { principal_kind: "user" }]
  ]) {
    const bad = await run(keys, claims, key, kid);
    assert.equal(bad.status, 401, what);
    assert.match(bad.challenge, /error="invalid_token"/, what);
    assert.equal(bad.calls.filter(u => u.endsWith("/mcp-oauth/grant")).length, 0, what + ": never reaches the grant check");
  }
});
