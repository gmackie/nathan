import { createHash, randomBytes } from "node:crypto";
import { account, callback, issuer, resource } from "./registration.mjs";

const agentApi = "https://keys.gmac.io/api/llavero/agent";
const ref = "gmac-idp-staging-cf-d1-admin";
const approvedDigest = "sha256:032dfaa521fdafcd7a17f53d8b5ae159215993063bb771ce3fb026705a9385da";
const approvedUser = "0bbf4e07e8f46ae51e1f3963be9f564621fc9598bfa5a727f104776d7cef4498";
const originalClient = "nmcp_IRafVNUd0evxoUFqUycqDsJ958Be9KQGNONWw7bPW4U";
const isClient = value => typeof value === "string" && /^nmcp_[A-Za-z0-9_-]{1,160}$/.test(value);

export function requireApprovedTarget(userId, client) {
  if (typeof userId !== "string" || createHash("sha256").update(userId).digest("hex") !== approvedUser ||
      client !== originalClient) throw Error("Configuration does not match the approved staging target");
}

async function readJson(response, service) {
  try {
    return await response.json();
  } catch {
    throw Error(service + " returned invalid JSON");
  }
}

async function llavero(token, path, versionId, request) {
  if (!token) throw Error("Hosted nathan-cli identity is not enrolled");
  const init = {method:"GET", headers:{Authorization:"Bearer " + token}, redirect:"manual", signal:AbortSignal.timeout(15000)};
  if (versionId) {
    init.method = "POST";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify({versionId});
  }
  const response = await request(agentApi + path, init);
  if (!response.ok) throw Error("Llavero refused the hosted helper (" + response.status + ")");
  return readJson(response, "Llavero");
}

// Agent intake can also create a version of this ref. Only the rotation
// service writes this actor after the owner authorizes the issuance policy.
function isIssued(version) {
  return version?.credential === ref && version.actor === "rotation:" + ref &&
    typeof version.id === "string" && /^ver_[A-Za-z0-9_-]{1,64}$/.test(version.id);
}

export async function issuedVersion(agentToken, request = fetch) {
  const listing = await llavero(agentToken,"/credentials",null,request);
  if (!Array.isArray(listing?.credentials)) throw Error("Invalid Llavero credential listing");
  const entry = listing.credentials.find(c => c?.ref === ref);
  const issuance = entry?.issuance;
  const policy = issuance?.policy;
  if (entry?.retrievableBy?.length !== 1 || entry.retrievableBy[0] !== "nathan-cli" ||
      issuance?.authorityKind !== "mcp-oauth" || issuance.authority !== "gmac-cloudflare-mcp" ||
      issuance.provider !== "cloudflare-mcp" || policy?.id !== ref || policy.providerAccount !== account ||
      policy.providerId !== issuance.provider || policy.authority !== issuance.authority ||
      policy.scopes?.length !== 1 || policy.scopes[0] !== "D1 Write" || policy.destinations?.length !== 0) {
    throw Error("Llavero staging issuance policy mismatch");
  }
  if (!entry.latestVersion || issuance.authorityReady !== true) return null;
  if (!isIssued(entry.latestVersion)) throw Error("Llavero version did not come from the staging issuance policy");
  return entry.latestVersion.id;
}

// The credential exists only inside this step invocation. Workflow storage,
// Browser Run, logs and integration errors receive no credential values.
export async function withIssuedCredential(agentToken, use, request = fetch) {
  const versionId = await issuedVersion(agentToken, request);
  if (!versionId) throw Error("Llavero has not issued the staging credential");
  const audit = await llavero(agentToken, "/audit", null, request);
  let approved = false, issued = false;
  if (audit?.chain?.ok === true && Array.isArray(audit.events)) {
    // The vault verifies its chain and returns events in ascending sequence.
    for (const { action, subject, actor } of audit.events) {
      if (subject?.policy !== ref) continue;
      if (action === "rotation.propose" || action === "rotation.disable") {
        approved = false;
        issued = false;
      } else if (action === "rotation.approve") {
        approved = subject.digest === approvedDigest;
        issued = false;
      } else if (approved && action === "rotate.issue" && actor === "rotation:" + ref &&
                 subject.stage === "custody" && subject.credential === ref && subject.versionId === versionId) {
        issued = true;
      }
    }
  }
  if (!approved || !issued) throw Error("Llavero approval and issuance evidence is missing");
  const release = await llavero(agentToken, "/credentials/" + ref + "/retrieve", versionId, request);
  if (!isIssued(release?.version) || release.version.id !== versionId ||
      typeof release.value !== "string" || !release.value) throw Error("Llavero returned an invalid release");
  return use(release.value);
}

export function authorizationUrl(clientId) {
  if (!isClient(clientId)) throw Error("Invalid public client ID");
  const verifier = randomBytes(32).toString("base64url");
  const url = new URL("/mcp-oauth/authorize", issuer);
  url.search = new URLSearchParams({client_id:clientId, redirect_uri:callback, response_type:"code",
    resource, scope:"lms:read", code_challenge_method:"S256",
    code_challenge:createHash("sha256").update(verifier).digest("base64url"), state:randomBytes(24).toString("base64url")}).toString();
  return url;
}

export async function registerPublicClient(request = fetch) {
  const response = await request(issuer + "/mcp-oauth/register", {method:"POST",redirect:"manual",
    signal:AbortSignal.timeout(15000), headers:{"Content-Type":"application/json"},
    body:JSON.stringify({client_name:"EducateOS staging registration check", redirect_uris:[callback],
      token_endpoint_auth_method:"none", grant_types:["authorization_code","refresh_token"], response_types:["code"]})});
  if (response.status !== 201) throw Error("Public loopback registration failed (" + response.status + ")");
  const client = await readJson(response, "Nathan");
  if (!isClient(client?.client_id) || client.token_endpoint_auth_method !== "none" ||
      client.redirect_uris?.length !== 1 || client.redirect_uris[0] !== callback || "client_secret" in client) {
    throw Error("Unexpected public loopback registration");
  }
  return client.client_id;
}

export function isSignIn(url) {
  return url.href === issuer + "/sign-in";
}

export function verifyRedirect(authorize, trace) {
  if (trace.hops === 0 && trace.status === 400 && trace.finalStatus === 400 &&
      trace.firstUrl === authorize.href && trace.finalUrl === authorize.href && trace.pageTitle === "Unknown client · Nathan") {
    return null;
  }
  if (trace.firstUrl !== authorize.href || trace.status !== 302 || trace.hops !== 1 || trace.finalStatus !== 200 ||
      !trace.location || !isSignIn(new URL(trace.location, issuer)) || !isSignIn(new URL(trace.finalUrl))) {
    throw Error("OAuth authorization did not redirect directly to Nathan sign-in");
  }
  return {httpStatus:302, redirect:issuer + "/sign-in"};
}

export const instanceId = "educateos-staging-2026-11-24";
const retryRead = {retries:{limit:4, delay:"1 minute", backoff:"exponential"}, timeout:"2 minutes"};
const once = {retries:{limit:0, delay:"1 second"}, timeout:"2 minutes"};

export async function completeRegistration(step, originalClient, jobs) {
  for (let poll = 1; ; poll++) {
    const issued = await step.do("Check Llavero issuance " + poll, retryRead, jobs.version);
    if (issued) break;
    await step.sleep("Await issuance " + poll, poll <= 3 ? "1 minute" : "1 hour");
  }
  const d1 = await step.do("Apply or verify the staging grant", retryRead, jobs.apply);
  if (d1.originalClientActive) {
    const oauth = await step.do("Verify original client in Browser Run", retryRead, () => jobs.probe(originalClient));
    if (oauth) return {...d1, clientId:originalClient, clientSource:"original public loopback", oauth};
  }
  for (let attempt = 1; attempt <= 2; attempt++) {
    const clientId = await step.do("Register public loopback client " + attempt, once, jobs.register);
    const oauth = await step.do("Verify fresh client " + attempt + " in Browser Run", retryRead, () => jobs.probe(clientId));
    if (oauth) return {...d1, clientId, clientSource:"fresh public loopback", oauth};
  }
  throw Error("Both fresh public clients expired before verification");
}
