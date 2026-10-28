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
  async databases() {
    if (!this.accountId) throw Error("Account ID required");
    return this.request("/accounts/" + this.accountId + "/d1/database");
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
  async createDatabase(name) {
    if (!this.accountId) throw Error("Account ID required");
    return this.request("/accounts/" + this.accountId + "/d1/database", { method: "POST", body: { name } });
  }
}
export function zoneForHostname(zones, hostname) {
  return zones.filter(z => hostname === z.name || hostname.endsWith("." + z.name))
    .sort((a,b)=> b.name.length - a.name.length)[0] || null;
}
export async function inspectDeployment(client, cfg) {
  const [zones, workers, databases] = await Promise.all([
    client.zones(), client.workers(), client.databases()
  ]);
  const zone = zoneForHostname(zones, cfg.hostname);
  const conflicts = zone ? await client.dnsRecords(zone.id, cfg.hostname) : [];
  return {
    accountId: client.accountId,
    zone: zone ? { id: zone.id, name: zone.name, status: zone.status } : null,
    existingAuthWorker: Array.isArray(workers) && workers.some(w => w.id === cfg.name + "-auth"),
    existingDatabase: Array.isArray(databases) ? databases.find(d => d.name === cfg.database.name) || null : null,
    dnsConflicts: conflicts.map(x => ({ type: x.type, name: x.name, id: x.id })),
    warning: !zone ? "No active Cloudflare zone for requested hostname" : null
  };
}
