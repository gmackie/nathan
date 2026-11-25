export class CloudflareClient {
  constructor(token, accountId) {
    if (!token) throw Error("CLOUDFLARE_API_TOKEN required for Cloudflare discovery");
    this.token = token;
    this.accountId = accountId;
  }
  async request(path, options = {}) {
    if (!path.startsWith("/") || path.startsWith("//")) throw Error("Invalid API path");
    const headers = { Authorization: "Bearer " + this.token };
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch("https://api.cloudflare.com/client/v4" + path, {
      method: options.method || "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      redirect: "error",
      signal: AbortSignal.timeout(12000)
    });
    const json = await response.json();
    if (!response.ok || json.success === false) {
      const code = json.errors?.map(e => e.code + ": " + e.message).join("; ") || String(response.status);
      throw Error("Cloudflare API rejected request: " + code);
    }
    return json.result;
  }
  async accounts() { return this.request("/accounts?per_page=100"); }
  async zones() {
    if (!this.accountId) throw Error("Account ID required");
    return this.request("/zones?account.id=" + encodeURIComponent(this.accountId) + "&per_page=100");
  }
  async workers() {
    if (!this.accountId) throw Error("Account ID required");
    return this.request("/accounts/" + this.accountId + "/workers/scripts");
  }
  /** Exact-name D1 lookup; the list API pages at 100 and its name filter matches substrings. */
  async databaseNamed(name) {
    if (!this.accountId) throw Error("Account ID required");
    for (let page = 1; page <= 100; page++) {
      const rows = await this.request("/accounts/" + this.accountId + "/d1/database?name=" +
        encodeURIComponent(name) + "&per_page=100&page=" + page);
      if (!Array.isArray(rows)) throw Error("Unable to list D1 databases");
      const match = rows.find(d => d.name === name);
      if (match) return match;
      if (rows.length < 100) return null;
    }
    throw Error("D1 inventory exceeds the safe discovery limit");
  }
  async workerDomains() {
    if(!this.accountId)throw Error("Account ID required");
    const rows=await this.request("/accounts/"+this.accountId+"/workers/domains");
    if(!Array.isArray(rows))throw Error("Unexpected Worker custom-domain inventory");
    return rows;
  }
  async dnsRecordsForZone(zoneId) {
    if(!/^[a-f0-9]{32}$/.test(zoneId))throw Error("Invalid Cloudflare zone ID");
    const output=[];
    for(let page=1;page<=100;page++){
      const records=await this.request("/zones/"+zoneId+"/dns_records?per_page=100&page="+page);
      if(!Array.isArray(records))throw Error("Unable to enumerate DNS records");
      output.push(...records);
      if(records.length<100)return output;
    }
    throw Error("DNS inventory exceeds 10,000 records; cannot safely claim a complete discovery");
  }
  async dnsRecords(zoneId, hostname) {
    if (!/^[a-f0-9]{32}$/.test(zoneId)) throw Error("Invalid zone ID");
    return this.request("/zones/" + zoneId + "/dns_records?name=" + encodeURIComponent(hostname));
  }
  async workerExposure(workerName) {
    const unknown = [], publicEndpoints = [];
    // An upstream must not be callable through Workers.dev, preview URLs,
    // any custom domain, or any zone route the installer can observe.
    const encode = encodeURIComponent(workerName);
    try {
      const sub = await this.request("/accounts/" + this.accountId + "/workers/scripts/" + encode + "/subdomain");
      if (sub?.enabled === true) publicEndpoints.push({kind:"workers.dev",worker:workerName});
      if (sub?.previews_enabled === true) publicEndpoints.push({kind:"preview",worker:workerName});
      if (typeof sub?.enabled !== "boolean" || typeof sub?.previews_enabled !== "boolean")
        unknown.push("Unrecognized subdomain exposure response");
    } catch (error) { unknown.push("Unable to inspect workers.dev / preview routes: " + error.message); }
    try {
      const domains = await this.request("/accounts/" + this.accountId + "/workers/domains");
      if (!Array.isArray(domains)) unknown.push("Unexpected custom domain inventory response");
      else for (const d of domains) {
        if (d.service === workerName || d.script === workerName)
          publicEndpoints.push({kind:"custom-domain",hostname:d.hostname});
      }
    } catch (error) { unknown.push("Unable to inspect Worker custom domains: " + error.message); }
    try {
      const zones = await this.zones();
      if (!Array.isArray(zones)) unknown.push("Unexpected zones inventory response");
      else for (const z of zones) {
        try {
          const routes = await this.request("/zones/" + z.id + "/workers/routes");
          if (!Array.isArray(routes)) unknown.push("Cannot enumerate routes for " + z.name);
          else for (const r of routes) if (r.script === workerName)
            publicEndpoints.push({kind:"zone-route",pattern:r.pattern,zone:z.name});
        } catch (error) { unknown.push("Unable to inspect routes in " + z.name + ": " + error.message); }
      }
    } catch (error) { unknown.push("Unable to enumerate zones: " + error.message); }
    return { public: publicEndpoints, unknown };
  }
  async queryDatabase(id, sql, params = []) {
    if (!/^[a-f0-9-]{36}$/.test(id)) throw Error("Invalid D1 database UUID");
    if (typeof sql !== "string" || sql.length > 5000 || !Array.isArray(params) || params.length > 10)
      throw Error("Invalid parameterized D1 query");
    const result = await this.request("/accounts/" + this.accountId + "/d1/database/" + id + "/query",
      { method:"POST", body:{sql, params} });
    if (!Array.isArray(result) || result.some(r => r.success !== true))
      throw Error("Cloudflare D1 query failed");
    return result.flatMap(r => Array.isArray(r.results) ? r.results : []);
  }
  async batchDatabase(id, statements) {
    if (!/^[a-f0-9-]{36}$/.test(id) || !statements.length) throw Error("Invalid D1 batch");
    const result = await this.request("/accounts/" + this.accountId + "/d1/database/" + id + "/query",
      { method: "POST", body: { batch: statements } });
    if (!Array.isArray(result) || result.length !== statements.length ||
        result.some(row => row.success !== true || !Array.isArray(row.results))) {
      throw Error("Cloudflare D1 batch failed");
    }
    return result.map(row => row.results);
  }
  /** Names (never values) of the secrets bound to a Worker script. */
  async workerSecretNames(workerName) {
    if (!/^[a-z0-9-]{1,63}$/.test(workerName)) throw Error("Invalid Worker name");
    const rows = await this.request("/accounts/" + this.accountId + "/workers/scripts/" + workerName + "/secrets");
    if (!Array.isArray(rows)) throw Error("Unexpected Worker secret inventory");
    return rows.map(r => r.name);
  }
  async createDatabase(name) {
    if (!this.accountId) throw Error("Account ID required");
    return this.request("/accounts/" + this.accountId + "/d1/database", { method: "POST", body: { name } });
  }
}
export function zoneForHostname(zones, hostname) {
  return zones.filter(z => hostname === z.name || hostname.endsWith("." + z.name))
    .sort((a,b)=> b.name.length - a.name.length)[0] || null;
}
/** Secrets the identity Worker needs before any public route may point at it. */
export const REQUIRED_IDP_SECRETS = ["BETTER_AUTH_SECRET", "NATHAN_CONFIG_KEY"];
export function missingIdpSecrets(names) {
  return REQUIRED_IDP_SECRETS.filter(name => !names.includes(name));
}
/**
 * Installs each missing identity Worker secret (never replacing an existing one), then
 * re-reads the Worker's secret names and throws unless all are present. Callers publish
 * the public route only after this returns.
 * @param {{ workerSecretNames(name: string): Promise<string[]> }} client
 * @param {string} workerName
 * @param {(name: string) => Promise<void>} putSecret
 */
export async function ensureIdpSecrets(client, workerName, putSecret) {
  for (const name of missingIdpSecrets(await client.workerSecretNames(workerName))) await putSecret(name);
  const stillMissing = missingIdpSecrets(await client.workerSecretNames(workerName));
  if (stillMissing.length)
    throw Error("Refusing to publish the identity hostname: missing Worker secrets " + stillMissing.join(", "));
}
/**
 * DNS records at the identity hostname conflict unless they are the record Cloudflare
 * manages for this installation's own Worker custom domain (a re-run or upgrade).
 */
export function hostnameConflicts(records, domains, hostname, workerName) {
  const ownsHostname = domains.some(d => d.hostname === hostname && d.service === workerName);
  return ownsHostname ? [] : records;
}
export async function inspectDeployment(client, cfg) {
  const [zones, workers, existingDatabase] = await Promise.all([
    client.zones(), client.workers(), client.databaseNamed(cfg.database.name)
  ]);
  const zone = zoneForHostname(zones, cfg.hostname);
  const records = zone ? await client.dnsRecords(zone.id, cfg.hostname) : [];
  // Custom-domain inventory is read only when there is something to explain, so a
  // first install does not need Workers custom-domain read permission.
  const conflicts = records.length
    ? hostnameConflicts(records, await client.workerDomains(), cfg.hostname, cfg.name + "-auth")
    : [];
  return {
    accountId: client.accountId,
    zone: zone ? { id: zone.id, name: zone.name, status: zone.status } : null,
    existingAuthWorker: Array.isArray(workers) && workers.some(w => w.id === cfg.name + "-auth"),
    existingDatabase,
    dnsConflicts: conflicts.map(x => ({ type: x.type, name: x.name, id: x.id })),
    warning: !zone ? "No active Cloudflare zone for requested hostname" : null
  };
}
