/** Shared helpers for tests that run built Worker bundles in workerd via Miniflare. */
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

export const COMPAT = { compatibilityDate: "2026-10-27", compatibilityFlags: ["nodejs_compat"] };

export function bundle(name) {
  const path = ".nathan/build-" + name + "/worker.js";
  if (!existsSync(path)) throw Error("Missing " + path + ": run `npm run test:runtime`, which builds bundles first");
  return path;
}

/** Applies a migration file statement by statement; D1's exec() rejects multi-line statements.
 * A CREATE TRIGGER ... BEGIN ...; END statement is kept whole. */
export async function migrate(db, file) {
  const sql = readFileSync(file, "utf8")
    .split("\n").filter(line => !line.trim().startsWith("--")).join("\n");
  const statements = [];
  let trigger = null;
  for (const part of sql.split(/;\s*(?:\n|$)/).map(s => s.trim()).filter(Boolean)) {
    if (trigger !== null) trigger += ";\n" + part;
    else if (/^CREATE\s+TRIGGER\b/i.test(part)) trigger = part;
    else { statements.push(part); continue; }
    if (/\bEND$/i.test(trigger)) { statements.push(trigger); trigger = null; }
  }
  if (trigger !== null) throw Error("Unterminated CREATE TRIGGER in " + file);
  for (const statement of statements) await db.prepare(statement).run();
}

export function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}
export const randomKey = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

export function cookiesOf(response) {
  const jar = {};
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const index = pair.indexOf("=");
    jar[pair.slice(0, index)] = { value: pair.slice(index + 1), raw: line };
  }
  return jar;
}

/** Miniflare 5 uses a config schema; convert from the documented v4 option shape. */
export async function start(options) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, ...COMPAT, ...options }));
  await mf.ready;
  return mf;
}

/**
 * The built identity Worker with every top-level migration applied. Caller disposes it.
 * `options` adds Miniflare options such as `outboundService` (mocked outbound HTTP, including
 * workerd's node:dns, which resolves over DNS-over-HTTPS at cloudflare-dns.com).
 */
export async function authWorker(host, vars = {}, options = {}) {
  const mf = await start({
    ...options,
    scriptPath: bundle("auth"),
    d1Databases: { DB: "auth-db-" + crypto.randomUUID() },
    durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
    bindings: {
      NATHAN_ISSUER: "https://" + host, NATHAN_ADMIN_EMAILS: "admin@example.test",
      NATHAN_SECURITY_PROFILE: "business", NATHAN_BOOTSTRAP_REQUIRED: "true",
      NATHAN_INSTALL_ACTIVE: "true", NATHAN_MCP_WRITE_ENABLED: "false", NATHAN_REALM_APEX: "",
      ENABLE_PASSWORD: "false", ENTERPRISE_SSO: "false", NATHAN_ADMIN_STEPUP_REQUIRED: "true",
      BETTER_AUTH_SECRET: randomKey() + randomKey(), NATHAN_CONFIG_KEY: randomKey(), ...vars
    }
  });
  const db = await mf.getD1Database("DB");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort())
    await migrate(db, "migrations/" + file);
  return mf;
}

// ---- Real Better Auth sessions and Nathan-issued tokens -----------------------------------------

/** Better Auth's signed session cookie for a session token (HMAC-SHA256 with BETTER_AUTH_SECRET). */
export async function signedSessionCookie(secret, token) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = Buffer.from(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token))).toString("base64");
  return "__Secure-nathan.session_token=" + encodeURIComponent(token + "." + signature);
}
/** Inserts a one-hour Better Auth session for a user; returns its id and cookie. */
export async function insertSession(db, secret, userId) {
  const id = "sess-" + crypto.randomUUID(), token = "tok" + randomKey(), now = new Date().toISOString();
  await db.prepare('INSERT INTO "session"("id","expiresAt","token","createdAt","updatedAt","userId") VALUES (?,?,?,?,?,?)')
    .bind(id, new Date(Date.now() + 3600_000).toISOString(), token, now, now, userId).run();
  return { id, cookie: await signedSessionCookie(secret, token) };
}
/** Creates the bootstrap administrator (passkey + TOTP enrolled, session stepped up); returns its session. */
export async function enrollAdmin(db, secret, { id = "admin-1", email = "admin@example.test" } = {}) {
  const now = new Date().toISOString();
  const run = (statement, ...params) => db.prepare(statement).bind(...params).run();
  await run('INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt","role") VALUES (?,?,?,1,?,?,\'admin\')', id, id, email, now, now);
  await run("INSERT INTO nathan_bootstrap_status(id,cloudflare_user_id,admin_email,admin_user_id,state) VALUES ('primary','cf',?,?,'complete')", email, id);
  await run('INSERT INTO "passkey"("id","publicKey","userId","credentialID","counter","deviceType","backedUp") VALUES (?,\'x\',?,?,0,\'singleDevice\',0)', "pk-" + id, id, "cred-" + id);
  await run('INSERT INTO "twoFactor"("id","secret","backupCodes","userId","verified") VALUES (?,\'x\',\'x\',?,1)', "tf-" + id, id);
  const session = await insertSession(db, secret, id);
  await run("INSERT INTO nathan_admin_assurance(session_id,user_id,method) VALUES (?,?,'passkey')", session.id, id);
  return session;
}
/** POSTs same-origin JSON to an Identity Studio API as the given session. */
export function studioPost(fetcher, origin, path, body, cookie) {
  return fetcher.fetch(origin + path, {
    method: "POST", body: JSON.stringify(body),
    headers: { Cookie: cookie, Origin: origin, "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin" }
  });
}
/**
 * NATH-39: Identity Studio is a Kumo SPA in one island. Given a fetcher (or fetch function) and a
 * /studio response, checks the shell
 * (renderPage CSP with nonce'd scripts, no style= attributes, no inline script but the import map)
 * and returns { html, code }: `code` is the island module plus every chunk it imports, fetched
 * from the same Worker and each checked against the SRI hash the page pins.
 */
export async function studioShell(fetcher, origin, response) {
  if (response.status !== 200) throw Error("Studio returned " + response.status);
  const csp = response.headers.get("content-security-policy") ?? "";
  const nonce = /script-src 'self' 'nonce-([^']+)'/.exec(csp)?.[1];
  if (!nonce || !/frame-ancestors 'none'/.test(csp)) throw Error("Studio CSP is not the renderPage island policy: " + csp);
  if (response.headers.get("referrer-policy") !== "same-origin") throw Error("Studio Referrer-Policy must stay same-origin");
  const html = await response.text();
  if (/\sstyle=/i.test(html)) throw Error("Studio markup has a style= attribute");
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  for (const [, attrs] of scripts) if (!attrs.includes('nonce="' + nonce + '"')) throw Error("Studio script without the page nonce");
  const inline = scripts.filter(([, attrs, body]) => body);
  if (inline.length !== 1 || !/type="importmap"/.test(inline[0][1])) throw Error("Studio has inline script besides the import map");
  const integrity = JSON.parse(inline[0][2]).integrity;
  const island = scripts.map(([, attrs]) => /type="module" src="([^"]+)" integrity="([^"]+)"/.exec(attrs)).filter(Boolean);
  if (island.length !== 1 || !/^\/__nathan\/ui\/studio-[A-Za-z0-9_-]+\.js$/.test(island[0][1])) throw Error("Studio must load exactly the studio island");
  if (!html.includes('data-nathan-island="studio"')) throw Error("Studio island container missing");
  const get = typeof fetcher === "function" ? fetcher : url => fetcher.fetch(url);
  const code = [];
  for (const [src, hash] of Object.entries(integrity)) {
    const asset = await get(origin + src);
    const bytes = Buffer.from(await asset.arrayBuffer());
    if (asset.status !== 200 || "sha384-" + createHash("sha384").update(bytes).digest("base64") !== hash) throw Error(src + " does not match its SRI hash");
    code.push(bytes.toString("utf8"));
  }
  if (integrity[island[0][1]] !== island[0][2]) throw Error("island SRI differs between the script tag and the import map");
  return { html, code: code.join("\n") };
}
/** A DPoP proof JWT (RFC 9449) for one request, from a fresh ES256 key. */
export async function dpopProof(method, url) {
  const { generateKeyPair, exportJWK, SignJWT } = await import("jose");
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  return new SignJWT({ htm: method, htu: url, jti: crypto.randomUUID() })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(publicKey) }).setIssuedAt().sign(privateKey);
}
/**
 * A user access token issued by Nathan's own authorization and token endpoints (authorization
 * code + PKCE, public client). With `dpop`, the token request carries a DPoP proof, so Nathan
 * binds the token to that key (`cnf.jkt`).
 */
export async function nathanUserToken(fetcher, { issuer, cookie, clientId, redirectUri, scope = "openid nathan:read", resource, dpop = false }) {
  const { createHash } = await import("node:crypto");
  const verifier = randomKey() + randomKey();
  const query = new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: redirectUri, scope, state: randomKey(),
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource
  });
  const authorize = await fetcher.fetch(issuer + "/oauth2/authorize?" + query, { redirect: "manual", headers: { Cookie: cookie } });
  const location = authorize.headers.get("Location") ?? (authorize.status === 200 ? (await authorize.json()).url : null);
  const code = location && new URL(location).searchParams.get("code");
  if (!code) throw Error("Nathan did not issue an authorization code: " + authorize.status);
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (dpop) headers.DPoP = await dpopProof("POST", issuer + "/oauth2/token");
  const response = await fetcher.fetch(issuer + "/oauth2/token", {
    method: "POST", headers,
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier, resource }).toString()
  });
  const body = await response.json();
  if (response.status !== 200 || !body.access_token) throw Error("Nathan token request failed: " + response.status + " " + JSON.stringify(body));
  return body.access_token;
}
/** A client-credentials access token issued by Nathan's token endpoint. */
export async function nathanClientToken(fetcher, { issuer, clientId, clientSecret, scope, resource }) {
  const response = await fetcher.fetch(issuer + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + btoa(clientId + ":" + clientSecret) },
    body: new URLSearchParams({ grant_type: "client_credentials", scope, resource }).toString()
  });
  const body = await response.json();
  if (response.status !== 200 || !body.access_token) throw Error("Nathan client-credentials request failed: " + response.status + " " + JSON.stringify(body));
  return body.access_token;
}

/**
 * One raw HTTP/1.1 exchange with a Miniflare instance, for requests fetch() cannot make, such as a
 * body on GET. The request goes out in a single write (with Content-Length when there is a body)
 * and the response is read until the server closes. MF-Original-URL tells Miniflare's entry the
 * public https URL. Returns the status and the raw response text.
 */
export async function rawHttp(mf, host, { method = "GET", path = "/", headers = {}, body } = {}) {
  const { connect } = await import("node:net");
  const base = new URL(await mf.ready);
  const payload = body === undefined ? null : Buffer.from(body);
  const head = [method + " " + path + " HTTP/1.1", "Host: " + host, "Connection: close", "MF-Original-URL: https://" + host + path,
    ...(payload ? ["Content-Length: " + payload.length] : []), ...Object.entries(headers).map(([k, v]) => k + ": " + v)].join("\r\n") + "\r\n\r\n";
  return new Promise((resolve, reject) => {
    const chunks = [];
    let socketError = null;
    const socket = connect(Number(base.port), base.hostname, () => socket.end(payload ? Buffer.concat([Buffer.from(head), payload]) : head));
    socket.on("data", c => chunks.push(c));
    socket.on("error", e => { socketError = e; });
    socket.on("close", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      if (!text) return reject(socketError ?? new Error("no response"));
      resolve({ status: Number(text.split(" ")[1]), text });
    });
  });
}

/**
 * A request body streamed without Content-Length (chunked) that never ends: `bytes` of filler in
 * 64 KiB pieces, then the stream stays open. A server that reads with a byte limit answers once it
 * has seen more than the limit; one that buffers the whole body (request.text()) waits forever.
 * (A body that does end, sent faster than it is read, races the server's early close: the client
 * can lose the response to EPIPE/ECONNRESET, so tests do not use one.) `pulled()` counts the
 * bytes the receiver asked for.
 */
export function openEndedBody(bytes) {
  let pulled = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (pulled >= bytes) return new Promise(() => {});
      const size = Math.min(65536, bytes - pulled);
      pulled += size;
      controller.enqueue(new Uint8Array(size).fill(97));
    }
  });
  return { body, pulled: () => pulled };
}
