import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { realmForLoginHostname, isHostnameWithinRealm, realmCallback } from "../../src/shared/realm.mjs";

export const ALLOWED_PROFILES = new Set(["standard", "business", "high"]);
const SLUG = /^[a-z][a-z0-9-]{0,62}$/;
function domainValid(host) {
  if (typeof host !== "string" || host.length > 253 || host.toLowerCase() !== host) return false;
  return host.split(".").length >= 2 && host.split(".").every(x =>
    x.length >= 1 && x.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x));
}
function validUri(uri) {
  try {
    const url = new URL(uri);
    return url.protocol === "https:" && !url.username && !url.password && !url.hash && url.origin !== "null";
  } catch { return false; }
}
export function validateConfig(value) {
  const errors = [];
  if (!value || typeof value !== "object" || Array.isArray(value)) return ["Configuration must be a JSON object"];
  if (!SLUG.test(value.name || "")) errors.push("name must be a lowercase deployment slug");
  if (!domainValid(value.hostname)) errors.push("hostname must be a valid lowercase DNS name");
  if (!ALLOWED_PROFILES.has(value.securityProfile)) errors.push("securityProfile must be standard, business, or high");
  if (value.accountId != null && !/^[a-f0-9]{32}$/.test(value.accountId)) errors.push("accountId must be a 32-character Cloudflare account ID");
  if (value.database?.type !== "d1" || !SLUG.test(value.database?.name || "")) errors.push("database must specify a valid D1 name");
  if (value.realm !== undefined) {
    if(!value.realm || typeof value.realm!=="object" || Array.isArray(value.realm)) errors.push("realm must be a domain-wide SSO object");
    else {
      try{
        const derived=realmForLoginHostname(value.hostname);
        if(value.realm.apex!==derived.apex || value.realm.issuerHostname!==derived.issuerHostname || value.realm.includeApex!==true ||
           value.realm.includeSubdomains!==true || value.realm.registration!=="approved-only")
          errors.push("realm must match login.<apex>, include root and subdomains, and require explicit OIDC registration approval");
      }catch(e){errors.push("realm requires issuer hostname login.<domain>");}
    }
  }
  if (value.providers != null && (typeof value.providers !== "object" || Array.isArray(value.providers)))
    errors.push("providers must be an object");
  if (!Array.isArray(value.applications)) errors.push("applications must be an array");
  else {
    const ids = new Set(), hosts = new Set();
    for (const app of value.applications) {
      if (!app || !SLUG.test(app.id || "")) { errors.push("Each application needs an id slug"); continue; }
      if (ids.has(app.id)) errors.push("Duplicate application id: " + app.id);
      ids.add(app.id);
      if (!["worker", "external", "gateway"].includes(app.kind)) errors.push(app.id + ": invalid kind");
      if (app.kind === "worker" && !SLUG.test(app.workerName || "")) errors.push(app.id + ": workerName required");
      if (app.hostname && !domainValid(app.hostname)) errors.push(app.id + ": invalid hostname");
      if (app.protection === "gateway" && !app.hostname) errors.push(app.id + ": hostname required for gateway");
      if (app.hostname && hosts.has(app.hostname)) errors.push(app.id + ": duplicate hostname");
      if (app.hostname) hosts.add(app.hostname);
      if (app.redirectUris && (!Array.isArray(app.redirectUris) || app.redirectUris.some(x => !validUri(x))))
        errors.push(app.id + ": redirectUris must be exact HTTPS URLs without fragments");
    }
  }
  return errors;
}
export async function loadConfig(filename = "nathan.config.json") {
  const value = JSON.parse(await readFile(resolve(filename), "utf8"));
  const errors = validateConfig(value);
  if (errors.length) throw new Error(errors.join("\n"));
  return value;
}
export function buildPlan(cfg) {
  const out = [
    { operation: "propose", resource: "worker", name: cfg.name + "-auth" },
    { operation: "propose", resource: "d1", name: cfg.database.name },
    { operation: "propose", resource: "custom-domain", name: cfg.hostname }
  ];
  if(cfg.realm)out.push({operation:"propose",resource:"domain-wide-sso-realm",
    name:cfg.realm.apex,issuer:"https://"+cfg.hostname+"/api/auth",
    coverage:[cfg.realm.apex,"*."+cfg.realm.apex],registration:"approved-only",
    wildcardRouting:false,wildcardRedirectUris:false});
  for (const app of cfg.applications) {
    out.push({ operation: "propose", resource: "oidc-client", name: app.id,
      ...(cfg.realm && app.hostname && isHostnameWithinRealm(app.hostname,cfg.realm.apex) && app.hostname!==cfg.hostname
        ? {redirect:realmCallback(app.hostname,cfg.realm.apex,cfg.hostname,
          app.protection==="gateway"?"gateway":"worker",app.callbackPath)}:{})
    });
    if (app.protection === "gateway")
      out.push({ operation: "propose", resource: "gateway-worker", name: cfg.name + "-" + app.id + "-gateway" });
    if (app.kind === "worker")
      out.push({ operation: "propose", resource: "worker-binding", name: app.workerName });
  }
  return out;
}
