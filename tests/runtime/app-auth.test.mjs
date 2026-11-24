import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { EventEmitter } from "node:events";
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { bundle, COMPAT, cookiesOf, migrate, randomKey, start } from "./helpers.mjs";

const origin = "https://classcheck.example.test", issuer = origin + "/api/auth", resource = origin + "/api";
const management = "https://id.example.test", callback = origin + "/auth/callback";
const id = "classcheck-web", secret = randomKey();
const digest = value => createHash("sha256").update(value).digest("base64url");
async function proof(keys, method, url, accessToken) {
  return new SignJWT({htm:method,htu:url,...(accessToken ? {ath:digest(accessToken)} : {})})
    .setProtectedHeader({alg:"ES256",typ:"dpop+jwt",jwk:await exportJWK(keys.publicKey)})
    .setIssuedAt().setJti(crypto.randomUUID()).sign(keys.privateKey);
}
let mf, app, db;
const inbox = new EventEmitter();
const sql = (query, ...args) => db.prepare(query).bind(...args).run();
const get = (path, options = {}) => app.fetch(origin + path, { redirect: "manual", ...options });
const post = (path, body, cookie = "") => get(path, { method: "POST", headers: {
  "Content-Type": "application/json", Origin: origin, Cookie: cookie, "CF-Connecting-IP": "192.0.2.24"
}, body: JSON.stringify(body) });

const deliveryTimeout = 30_000;
async function requestMail(email, query) {
  const delivery = Promise.withResolvers();
  inbox.once(email, delivery.resolve);
  let timer;
  try {
    const challenge = await post("/sign-in/email/request", {email, oauth_query:query});
    assert.equal(challenge.status, 202);
    timer = setTimeout(() => delivery.reject(Error("No email arrived after challenge acceptance")), deliveryTimeout);
    return { challenge, mail: await delivery.promise };
  } finally {
    clearTimeout(timer);
    inbox.off(email, delivery.resolve);
  }
}

async function waitForPublication(email) {
  const deadline = Date.now() + deliveryTimeout;
  while (!await db.prepare("SELECT 1 FROM nathan_email_delivery_order WHERE email=? AND delivered>0").bind(email).first()) {
    assert.ok(Date.now() < deadline, "Nathan did not publish the email challenge");
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

before(async () => {
  const caller = (name, pin) => ({ name, ...COMPAT, modules: true, routes: name === "web" ? ["classcheck.example.test/*"] : [], script: "export default {fetch(r,e){return e.AUTH.fetch(r)}}",
    serviceBindings: { AUTH: { name: "auth", entrypoint: "NathanAppAuth", props: { applicationId: pin } } } });
  mf = await start({workers: [caller("web","classcheck"), caller("other","unrelated"), {
    name: "auth", modules: true, ...COMPAT, scriptPath: bundle("auth"), d1Databases: { DB: "standalone-app-auth" },
    durableObjects: { SCIM_DIRECTORY: { className: "NathanScimDirectory", useSQLite: true } },
    outboundService: async request => {
      assert.equal(request.url, "https://api.resend.com/emails");
      const mail = await request.json();
      inbox.emit(mail.to[0], mail);
      return Response.json({ id: crypto.randomUUID() });
    },
    bindings: { NATHAN_ISSUER: management, NATHAN_APP_ORIGIN: origin, NATHAN_APP_ID: "classcheck",
      NATHAN_ADMIN_EMAILS: "owner@example.test", NATHAN_ACCESS_TEAM_DOMAIN: "example.cloudflareaccess.com",
      NATHAN_ACCESS_AUD: "a".repeat(64), NATHAN_BOOTSTRAP_REQUIRED: "true", NATHAN_ADMIN_STEPUP_REQUIRED: "true",
      NATHAN_SECURITY_PROFILE: "business", NATHAN_INSTALL_ACTIVE: "true", ENABLE_PASSWORD: "true",
      ENABLE_EMAIL_OTP: "true", EMAIL_FROM: "ClassCheck <noreply@example.test>", RESEND_API_KEY: "test-mail",
      NATHAN_INSTANCE_NAME: "ClassCheck", ENTERPRISE_SSO: "false", NATHAN_CONFIG_KEY: randomKey(), BETTER_AUTH_SECRET: randomKey() }
  }]});
  db = await mf.getD1Database("DB", "auth");
  for (const file of readdirSync("migrations").filter(f => f.endsWith(".sql")).sort()) await migrate(db, "migrations/" + file);
  await sql("INSERT INTO nathan_applications(id,hostname,enabled) VALUES ('classcheck','classcheck.example.test',1)");
  await sql("INSERT INTO oauthClient(id,clientId,clientSecret,name,redirectUris,disabled,skipConsent,requirePKCE,tokenEndpointAuthMethod,grantTypes,scopes) VALUES (?,?,?,?,?,0,0,1,'client_secret_basic',?,?)",
    "c", id, digest(secret), "ClassCheck", JSON.stringify([callback]), JSON.stringify(["authorization_code","refresh_token"]), JSON.stringify(["openid","email","offline_access"]));
  await sql("INSERT INTO oauthResource(id,identifier,name,allowedScopes,accessTokenTtl,disabled) VALUES ('r',?,'ClassCheck API',?,900,0)", resource, '["openid","email","offline_access"]');
  await sql("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES ('cr',?,?)", id, resource);
  await sql("INSERT INTO nathan_token_audiences(identifier,app_id,created_by) VALUES (?,'classcheck','operator')", resource);
  app = await mf.getWorker("web");
});
after(() => mf?.dispose());

test("only the configured first-party origin and pinned binding serve app operations", async () => {
  const doc = await (await get("/api/auth/.well-known/openid-configuration")).json();
  assert.equal(doc.issuer, issuer);
  assert.equal(doc.token_endpoint, issuer + "/oauth2/token");
  assert.deepEqual(doc.token_endpoint_auth_methods_supported, ["client_secret_basic","client_secret_post","none"]);
  for (const path of ["/sign-in", "/consent", "/studio", "/api/auth/get-session", "/api/auth/admin/list-users", "/sign-in/email"])
    assert.equal((await get(path)).status, 404, path);
  assert.equal((await post("/api/auth/sign-in/email", {email:"guest@example.test", password:"unused"})).status, 404);
  assert.equal((await app.fetch(management + "/api/auth/jwks")).status, 421);
  const other = await mf.getWorker("other");
  assert.equal((await other.fetch(issuer + "/jwks")).status, 403);
  assert.equal((await post("/sign-in/context",{oauth_query:"client_id=unknown"})).status, 400);
  assert.equal((await get("/api/auth/sign-out", {method:"POST", headers:{Origin:management}})).status, 403);
});

for (const method of ["code","link"]) test("ClassCheck " + method + " through a real binding resumes private OIDC with ClassCheck cookies and pages", async () => {
  const email = method + "@example.test", verifier = randomKey(), nonce = randomKey(), state = randomKey();
  const keysForProof = method === "link" ? await generateKeyPair("ES256") : null;
  const scopes = method === "code" ? ["openid","email","offline_access"] : ["openid","email"];
  await sql("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,'operator',unixepoch()+3600)", crypto.randomUUID(), email);
  const params = new URLSearchParams({client_id:id, redirect_uri:callback, resource, response_type:"code", scope:scopes.join(" "),
    state, nonce, login_hint:email, code_challenge:digest(verifier), code_challenge_method:"S256"});
  const authorization = await get("/api/auth/oauth2/authorize?" + params, {headers:{Accept:"text/html","Sec-Fetch-Mode":"navigate"}});
  const login = new URL(authorization.headers.get("Location") ?? (await authorization.json()).url, origin);
  assert.equal(login.origin + login.pathname, origin + "/sign-in");
  const query = login.search.slice(1);
  assert.deepEqual(await (await post("/sign-in/context", {oauth_query:query})).json(),
    {clientName:"ClassCheck",scopes,loginHint:email,enterpriseSso:false});
  const { challenge, mail } = await requestMail(email, query);
  await waitForPublication(email);
  const {flowId} = await challenge.json();
  const browser = "__Host-nathan-email=" + cookiesOf(challenge)["__Host-nathan-email"].value;
  const link = new URL(mail.text.match(/https:\/\/\S+/)[0]);
  assert.equal(link.origin + link.pathname, origin + "/sign-in/email");
  const digits = mail.text.match(/\b[0-9]{6}\b/)[0];
  assert.equal(link.hash, "#" + flowId + "." + digits);
  const input = method === "link" ? link.hash.slice(1).split(".") : [flowId,digits];
  const response = await post("/sign-in/email/verify", {flowId:input[0],code:input[1]}, browser);
  assert.equal(response.status, 200, await response.clone().text());
  const session = "__Secure-nathan.session_token=" + cookiesOf(response)["__Secure-nathan.session_token"].value;
  const consent = new URL((await response.json()).url,origin);
  assert.equal(consent.origin + consent.pathname, origin + "/consent");
  const approved = await post("/api/auth/oauth2/consent",{accept:true,oauth_query:consent.search.slice(1)},session);
  const returned = new URL((await approved.json()).url);
  assert.equal(returned.origin + returned.pathname, callback);
  assert.equal(returned.searchParams.get("state"),state);
  const exchange = await get("/api/auth/oauth2/token",{method:"POST",headers:{
    "Content-Type":"application/x-www-form-urlencoded", Authorization:"Basic " + btoa(id + ":" + secret),
    ...(keysForProof ? {DPoP:await proof(keysForProof,"POST",issuer+"/oauth2/token")} : {})},
    body:new URLSearchParams({grant_type:"authorization_code",client_id:id,redirect_uri:callback,resource,code_verifier:verifier,code:returned.searchParams.get("code")}).toString()});
  assert.equal(exchange.status,200,await exchange.clone().text().then(s=>exchange.ok ? "" : s));
  const tokens = await exchange.json();
  const keys = createLocalJWKSet(await (await get("/api/auth/jwks")).json());
  const {payload} = await jwtVerify(tokens.id_token,keys,{issuer,audience:id});
  assert.equal(payload.nonce,nonce);
  const userInfoHeaders = keysForProof ? {Authorization:"DPoP "+tokens.access_token,DPoP:await proof(keysForProof,"GET",issuer+"/oauth2/userinfo",tokens.access_token)}
    : {Authorization:"Bearer " + tokens.access_token};
  const info = await get("/api/auth/oauth2/userinfo",{headers:userInfoHeaders});
  assert.equal(info.status,200, await info.clone().text());
  assert.equal((await info.json()).sub,payload.sub);
  assert.equal((await post("/sign-in/email/verify",{flowId,code:digits},browser)).status,400);
  if (keysForProof) {
    assert.equal((await get("/api/auth/oauth2/userinfo",{headers:{Authorization:"DPoP "+tokens.access_token}})).status,401);
  } else {
    assert.ok(tokens.refresh_token);
    await sql('UPDATE "user" SET role=? WHERE id=?',"admin",payload.sub);
    assert.equal((await get("/api/auth/oauth2/authorize?"+params,{headers:{Cookie:session}})).status,403);
    assert.equal((await get("/api/auth/oauth2/userinfo",{headers:userInfoHeaders})).status,401);
    const refresh = await get("/api/auth/oauth2/token",{method:"POST",headers:{
      "Content-Type":"application/x-www-form-urlencoded",Authorization:"Basic " + btoa(id+":"+secret)},
      body:new URLSearchParams({grant_type:"refresh_token",refresh_token:tokens.refresh_token,resource}).toString()});
    assert.equal(refresh.status,400);
  }
  assert.equal((await post("/api/auth/sign-out",{},session)).status,200);
});

test("operator bootstrap stays available to management when its email is submitted on ClassCheck", async t => {
  const email = "owner@example.test", verifier = randomKey();
  let sent = false;
  const recordMail = () => { sent = true; };
  inbox.on(email, recordMail);
  t.after(() => inbox.off(email, recordMail));
  const idOfInvite = crypto.randomUUID();
  await sql("INSERT INTO nathan_invitations(id,email,created_by,expires_at) VALUES (?,?,'operator',unixepoch()+3600)",idOfInvite,email);
  const params = new URLSearchParams({client_id:id,redirect_uri:callback,resource,response_type:"code",scope:"openid email",
    state:randomKey(),nonce:randomKey(),code_challenge:digest(verifier),code_challenge_method:"S256",login_hint:email});
  const start = await get("/api/auth/oauth2/authorize?" + params);
  const login = new URL(start.headers.get("location") ?? (await start.json()).url,origin);
  const challenge = await post("/sign-in/email/request",{email,oauth_query:login.search.slice(1)});
  assert.equal(challenge.status,202);
  // A published, non-delivered challenge has no invitation_id or subject. Wait on publication so
  // an accidentally queued real delivery can't pass the assertion by finishing after the test.
  await waitForPublication(email);
  assert.equal(sent, false, "the operator must receive no ClassCheck sign-in proof");
  assert.deepEqual(await db.prepare("SELECT subject_id,invitation_id FROM nathan_email_sign_ins WHERE email=?").bind(email).first(),{subject_id:null,invitation_id:null});
  assert.equal(await db.prepare("SELECT uses FROM nathan_invitations WHERE id=?").bind(idOfInvite).first("uses"),0);
});
