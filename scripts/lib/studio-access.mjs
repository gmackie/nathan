import { mkdir, readFile, writeFile, rename } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { normalizeEmail } from "../../src/auth/admission-policy.mjs";
import { inspectDeployment, zoneForHostname } from "./cloudflare.mjs";
import { validateDomainName } from "../../src/shared/realm.mjs";

const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const authenticators = ["totp", "security_key", "biometrics"];

export function studioAccessOptions(cfg) {
  const hostname = validateDomainName("admin." + validateDomainName(cfg.hostname));
  const { identityProviderId, emails } = cfg.studioAccess ?? {};
  if (!uuid.test(identityProviderId ?? "")) throw Error("Select the Cloudflare ID of the administrator identity provider");
  const local = new Set((cfg.adminEmails ?? []).map(normalizeEmail));
  if (!Array.isArray(emails) || !emails.length || emails.some(e => !normalizeEmail(e) || !local.has(normalizeEmail(e))))
    throw Error("Each Studio Access email must be in the Nathan administrator allowlist");
  return { hostname, identityProviderId, emails: [...new Set(emails.map(normalizeEmail))].sort() };
}

async function inventory(api, path) {
  const rows = [];
  const seen = new Set();
  for (let page = 1; page <= 100; page++) {
    const list = await api.request(path + "?per_page=50&page=" + page);
    if (!Array.isArray(list)) throw Error("Invalid Cloudflare Access inventory");
    for (const row of list) {
      if (!row?.id || seen.has(row.id)) throw Error("Ambiguous Cloudflare Access inventory");
      seen.add(row.id);
      rows.push(row);
    }
    if (list.length < 50) return rows;
  }
  throw Error("Access inventory exceeded the discovery limit");
}

function publicDestinations(app) {
  return [...new Set([app.domain, ...(app.self_hosted_domains ?? []),
    ...(app.destinations ?? []).filter(d => d.type === "public").map(d => d.uri)].filter(Boolean))];
}

function coversHost(destination, hostname) {
  const pattern = destination.toLowerCase().replace(/^https?:\/\//, "").split(/[/:]/)[0];
  // Account for wildcard and path-specific applications before claiming an exact hostname.
  const escaped = pattern.split("*").map(part => part.replace(/[^a-z0-9-]/g, c => "\\" + c));
  return new RegExp("^" + escaped.join(".*") + "$").test(hostname);
}

export async function inspectStudioHostname(api, cfg) {
  const { hostname } = studioAccessOptions(cfg);
  const worker = cfg.name + "-auth";
  const zones = await api.zones();
  const zone = zoneForHostname(zones, hostname);
  if (zone?.status !== "active") throw Error("Studio hostname needs an active Cloudflare zone");
  const [domains, records, routes] = await Promise.all([api.request("/accounts/" + api.accountId + "/workers/domains?hostname=" + hostname), api.dnsRecords(zone.id, hostname),
    api.request("/zones/" + zone.id + "/workers/routes")]);
  if (!Array.isArray(routes) || routes.some(r => coversHost(r.pattern, hostname)))
    throw Error("A Worker route covers the Studio hostname or its route inventory is unavailable");
  if (!Array.isArray(records) || !Array.isArray(domains)) throw Error("Incomplete hostname inventory");
  const existing = domains.filter(d => d.hostname === hostname);
  if (existing.length > 1 || existing.some(d => d.service !== worker || d.zone_id !== zone.id) ||
      (records.length && !existing.length)) throw Error("Conflicting Studio DNS or Worker custom domain");
  return existing.length > 0;
}

// A receipt ties retries before the first migration to the exact D1 returned by Cloudflare.
function databaseReceipt(cfg, folder) {
  const intent = JSON.stringify([cfg.accountId, cfg.name, cfg.database.name, cfg.hostname, normalizeEmail(cfg.adminEmails?.[0])]);
  return join(folder, createHash("sha256").update(intent).digest("hex") + ".json");
}

export async function rememberStudioDatabase(cfg, db, folder = ".nathan/installations") {
  await mkdir(folder, { recursive: true, mode: 0o700 });
  const path = databaseReceipt(cfg, folder);
  const tmp = path + "." + randomUUID();
  await writeFile(tmp, JSON.stringify({ db }), { mode: 0o600, flag: "wx" });
  await rename(tmp, path);
}

async function createdStudioDatabase(cfg, db, folder) {
  try { return JSON.parse(await readFile(databaseReceipt(cfg, folder), "utf8")).db === db; }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
}

export async function inspectStudioInstallation(api, cfg, snapshot, folder = ".nathan/installations") {
  const worker = cfg.name + "-auth";
  const settings = snapshot.existingAuthWorker
    ? await api.request("/accounts/" + api.accountId + "/workers/scripts/" + worker + "/settings")
    : null;
  if (snapshot.existingAuthWorker && !Array.isArray(settings?.bindings)) throw Error("Existing Worker bindings could not be verified");
  if (!cfg.studioAccess) {
    if (settings?.bindings.some(b => ["NATHAN_ADMIN_ORIGIN", "NATHAN_ACCESS_TEAM_DOMAIN", "NATHAN_ACCESS_AUD"].includes(b.name)))
      throw Error("Existing Worker requires Cloudflare Access. Restore its Studio Access configuration before deploying");
    return;
  }
  const { hostname, emails } = studioAccessOptions(cfg);
  const attached = await inspectStudioHostname(api, cfg);
  if (!snapshot.existingAuthWorker) {
    if (!emails.includes(normalizeEmail(cfg.adminEmails[0]))) throw Error("A fresh CLI installation requires its initial owner in the Access policy");
    if (attached) throw Error("Existing Studio custom domain requires a matching Nathan Worker");
    if (!snapshot.existingDatabase) return;
  }
  const db = snapshot.existingDatabase?.uuid ?? snapshot.existingDatabase?.id;
  if (!db || (settings && (!settings.bindings?.some(b => b.name === "DB" && b.type === "d1" && b.id === db) ||
      !settings.bindings.some(b => b.name === "NATHAN_ISSUER" && b.type === "plain_text" && b.text === "https://" + cfg.hostname))))
    throw Error("Existing Worker issuer or database differs from the Studio installation");
  if (!settings && await createdStudioDatabase(cfg, db, folder)) {
    const schema = await api.queryDatabase(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='nathan_bootstrap_status'");
    if (!schema.length) return;
    const seed = await api.queryDatabase(db, "SELECT id FROM nathan_bootstrap_status LIMIT 1");
    if (!seed.length) return;
  }
  const owners = await api.queryDatabase(db, "SELECT state,admin_email,cloudflare_user_id FROM nathan_bootstrap_status WHERE id='primary'");
  if (owners.length !== 1 || owners[0].cloudflare_user_id !== "cli:" + api.accountId ||
      owners[0].admin_email !== normalizeEmail(cfg.adminEmails[0])) throw Error("Existing Worker has a different installation owner");
  // A retry can finish an interrupted first install after the private deployment or D1 seed.
  // Only the seeded owner may complete bootstrap and the live Worker must already be Access-bound.
  if (owners[0].state !== "complete" && emails.includes(owners[0].admin_email) &&
      (!settings || settings.bindings.some(b => b.name === "NATHAN_ADMIN_ORIGIN" && b.text === "https://" + hostname))) return;
  for (const email of emails) {
    const matches = await api.queryDatabase(db,
      `SELECT u.id FROM "user" u JOIN nathan_bootstrap_status b ON b.id='primary' ` +
      "WHERE lower(u.email)=? AND u.emailVerified=1 AND u.role='admin' AND coalesce(u.banned,0)=0 " +
      "AND NOT EXISTS(SELECT 1 FROM nathan_scim_users d WHERE d.user_id=u.id AND d.link_state='deprovisioned' AND d.override_cause IS NULL) " +
      "AND (b.admin_user_id=u.id OR EXISTS(SELECT 1 FROM nathan_admin_grants g WHERE g.user_id=u.id AND g.email=lower(u.email) AND g.enabled=1))",
      [email]);
    if (matches.length !== 1 || owners[0].state !== "complete") throw Error("Complete local administrator enrollment and grants before the Studio cutover");
  }
}

function sameValues(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && expected.every(x => actual.includes(x));
}

function verifyApplication(app, policies, desired) {
  const policy = policies.length === 1 && policies[0];
  const expectedPolicy = desired.policies[0];
  const selectors = policy?.include?.map(rule =>
    Object.keys(rule).length === 1 && typeof rule.email?.email === "string" ? normalizeEmail(rule.email.email) : null);
  if (app.type !== "self_hosted" || app.name !== desired.name || app.domain !== desired.domain ||
      !sameValues(publicDestinations(app), [desired.domain]) || app.destinations?.some(d => d.type !== "public") ||
      !sameValues(app.allowed_idps, desired.allowed_idps) || app.allow_authenticate_via_warp || app.options_preflight_bypass ||
      !app.mfa_config || app.mfa_config.mfa_disabled === true ||
      !sameValues(app.mfa_config.allowed_authenticators, desired.mfa_config.allowed_authenticators) ||
      app.mfa_config.session_duration !== desired.mfa_config.session_duration || app.session_duration !== desired.session_duration ||
      (policy?.session_duration != null && policy.session_duration !== desired.session_duration) ||
      policy?.decision !== "allow" || policy.require?.length || policy.exclude?.length || policy.mfa_config ||
      !sameValues(selectors, expectedPolicy.include.map(rule => rule.email.email)) || !/^[a-f0-9]{64}$/.test(app.aud ?? "")) {
    throw Error("Existing Access application or policy differs from the Studio plan. No existing application is modified");
  }
}

export async function reconcileStudioAccess(api, cfg, apply = false) {
  const { hostname, identityProviderId, emails } = studioAccessOptions(cfg);
  const base = "/accounts/" + api.accountId + "/access";
  const [org, idp] = await Promise.all([
    api.request(base + "/organizations"), api.request(base + "/identity_providers/" + identityProviderId)
  ]);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(org.auth_domain ?? ""))
    throw Error("Expected the Cloudflare Access team domain for this account");
  if (idp.id !== identityProviderId || !["azureAD", "github"].includes(idp.type))
    throw Error("Select a native Microsoft Entra ID or GitHub identity provider from this Cloudflare account");
  const methods = authenticators.filter(method => org.mfa_config?.allowed_authenticators?.includes(method));
  if (!methods.length) throw Error("Enable independent MFA methods in the Cloudflare Access organization before installing Studio Access");
  const desired = {
    name: "Nathan Studio (" + cfg.hostname + ")", type: "self_hosted", domain: hostname,
    allowed_idps: [identityProviderId], session_duration: "1h",
    mfa_config: { allowed_authenticators: methods, session_duration: "1h", mfa_disabled: false },
    policies: [{ name: "Nathan Studio administrators", decision: "allow", precedence: 1,
      include: emails.map(email => ({ email: { email } })), require: [], exclude: [] }]
  };
  const findApp = async () => {
    const apps = await inventory(api, base + "/apps");
    const matches = apps.filter(app => publicDestinations(app).some(d => coversHost(d, hostname)));
    if (matches.length > 1 || matches.some(app => app.domain !== hostname))
      throw Error("Another Access application covers the Studio hostname or a path on it");
    return matches[0];
  };
  let app = await findApp();
  const operation = app ? "validate" : "create";
  if (!app && apply) {
    const created = await api.request(base + "/apps", { method: "POST", body: desired });
    app = await findApp();
    if (!app || !created.id || app.id !== created.id) throw Error("Could not verify the newly created Access application");
  }
  if (app) {
    if (!uuid.test(app.id)) throw Error("Invalid Access application identifier");
    const detail = await api.request(base + "/apps/" + app.id);
    const policies = await inventory(api, base + "/apps/" + app.id + "/policies");
    if (detail.id !== app.id || !Array.isArray(detail.policies) || detail.policies.length !== 1 ||
        policies.length !== 1 || detail.policies[0].id !== policies[0].id)
      throw Error("Could not verify the complete applied Studio Access policy list");
    verifyApplication(detail, policies, desired);
    return { operation, hostname, identityProviderId, emails, methods, bindings: {
      NATHAN_ADMIN_ORIGIN: "https://" + hostname, NATHAN_ACCESS_AUD: detail.aud, NATHAN_ACCESS_TEAM_DOMAIN: org.auth_domain
    } };
  }
  return { operation, hostname, identityProviderId, emails, methods };
}

/** Repeat discovery at publication. Wrangler also retains unspecified live variables on upload,
 * so a concurrent Access activation cannot lose its three bindings to a legacy manifest. */
export async function verifyIdentityUpload(api, cfg, previouslyPresent, databaseId, studio) {
  const current = await inspectDeployment(api, cfg);
  if (!current.zone || current.zone.status !== "active" || current.dnsConflicts.length ||
      current.existingAuthWorker !== previouslyPresent ||
      (current.existingDatabase?.uuid ?? current.existingDatabase?.id) !== databaseId)
    throw Error("Installation resources changed before upload; review the deployment plan");
  await inspectStudioInstallation(api, cfg, current);
  if (studio) await verifyStudioPolicy(api, cfg, studio);
  return current;
}

export async function verifyStudioPolicy(api, cfg, studio) {
  const verified = await reconcileStudioAccess(api, cfg);
  if (verified.bindings?.NATHAN_ACCESS_AUD !== studio.bindings.NATHAN_ACCESS_AUD ||
      verified.bindings.NATHAN_ACCESS_TEAM_DOMAIN !== studio.bindings.NATHAN_ACCESS_TEAM_DOMAIN)
    throw Error("Studio Access changed during installation; review the deployment plan");
}
