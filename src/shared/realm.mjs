/**
 * Nathan domain-wide OIDC realm. Root and subdomains share an issuer, never a
 * wildcard redirect URI or a cross-subdomain authentication cookie.
 * Pure module shared by Node CLI and Cloudflare Workers.
 */
export const REALM_LOGIN_LABEL = "login";
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const CALLBACK = /^\/(?:[a-zA-Z0-9._~/-]+)$/;

export function validateDomainName(name) {
  if (typeof name !== "string" || !name || name.length > 253 || name !== name.toLowerCase() ||
      name.includes("*") || name.includes("..") || name.includes(":") || name.endsWith(".")) {
    throw new Error("Expected a lowercase, exact DNS hostname (no wildcard, port or trailing dot)");
  }
  const parts=name.split(".");
  if(parts.length<2 || parts.some(p=>p.length===0 || p.length>63 || !LABEL.test(p))) {
    throw new Error("Invalid DNS hostname");
  }
  return name;
}
export function realmIssuerHostname(apex) {
  return REALM_LOGIN_LABEL + "." + validateDomainName(apex);
}
export function realmForLoginHostname(hostname) {
  const host=validateDomainName(hostname);
  if(!host.startsWith(REALM_LOGIN_LABEL+"."))throw new Error("Domain-wide SSO requires login.<domain> as issuer");
  const apex=validateDomainName(host.slice((REALM_LOGIN_LABEL+".").length));
  if(realmIssuerHostname(apex)!==host)throw new Error("Invalid domain realm issuer");
  return {apex,issuerHostname:host,includeApex:true,includeSubdomains:true,registration:"approved-only"};
}
export function isHostnameWithinRealm(hostname,apex) {
  try {
    const host=validateDomainName(hostname), base=validateDomainName(apex);
    return host===base || host.endsWith("."+base);
  } catch { return false; }
}
export function assertRealmClientHost(hostname,apex,issuerHostname) {
  const host=validateDomainName(hostname);
  if(!isHostnameWithinRealm(host,apex))throw new Error("Hostname lies outside the verified realm");
  if(host===issuerHostname)throw new Error("Identity issuer hostname cannot be registered as a relying application");
  return host;
}
export function validateCallbackPath(value) {
  if(typeof value!=="string" || value.length>256 || !CALLBACK.test(value) ||
     value.startsWith("//") || value.includes("//") || value.includes("/../") ||
     value.endsWith("/..") || value.includes("/./") || value.endsWith("/.")) {
    throw new Error("Callback path must be an absolute literal path without wildcard, fragment, query or traversal");
  }
  return value;
}
export function realmCallback(hostname,apex,issuerHostname,kind="web",callbackPath) {
  const host=assertRealmClientHost(hostname,apex,issuerHostname);
  if(!["web","worker","gateway","external"].includes(kind))throw new Error("Unsupported relying party kind");
  const path=validateCallbackPath(callbackPath || (kind==="gateway"?"/__nathan/callback":"/auth/callback"));
  return "https://"+host+path;
}
/** A route preview, NOT a deployment. Default domain-wide SSO needs no wildcard routing. */
export function domainWideRoutingPreview(apex) {
  const base=validateDomainName(apex);
  return {
    ssoMode:"oidc-per-registered-host",
    issuer:"https://"+realmIssuerHostname(base)+"/api/auth",
    wildcardRedirects:false,
    sharedParentDomainCookies:false,
    protectsTrafficAutomatically:false,
    optionalGatewayRoutes:[base+"/*","*."+base+"/*"],
    warning:"Wildcard Worker Routes change live traffic routing and need explicit origin maps, DNS and login-host exclusions. Never apply automatically."
  };
}
function addCandidate(out,host,source,worker,apex,issuerHostname) {
  try{
    assertRealmClientHost(host,apex,issuerHostname);
    let existing=out.get(host);
    if(!existing) { existing={hostname:host,kind:host===apex?"apex":"subdomain",sources:[],workerName:null,
      oidcRedirectUri:realmCallback(host,apex,issuerHostname),approved:false};out.set(host,existing); }
    if(!existing.sources.includes(source))existing.sources.push(source);
    if(worker)existing.workerName=worker;
  }catch { /* Ignore wildcard, mail-only, unrelated or issuer host entries */ }
}
/**
 * Build a review-only inventory of exact, proxied HTTP DNS hostnames and Worker
 * Custom Domains. Don't infer that discovered hosts can be safely proxied.
 */
export function discoverRealmHostCandidates({apex,issuerHostname,dnsRecords=[],workerDomains=[]}) {
  const base=validateDomainName(apex);
  const issuer=validateDomainName(issuerHostname);
  if(issuer!==realmIssuerHostname(base))throw new Error("Issuer and realm mismatch");
  if(!Array.isArray(dnsRecords)||!Array.isArray(workerDomains))throw new Error("Invalid Cloudflare inventory");
  const out=new Map();
  for(const rec of dnsRecords) {
    if(!rec||typeof rec.name!=="string" || rec.proxied!==true ||
       !["A","AAAA","CNAME"].includes(rec.type))continue;
    addCandidate(out,rec.name,"cloudflare-proxied-dns",null,base,issuer);
  }
  for(const record of workerDomains) {
    if(!record||typeof record.hostname!=="string")continue;
    const worker=typeof record.service==="string"&&/^[a-z0-9][a-z0-9-]{0,62}$/.test(record.service)
      ?record.service:null;
    addCandidate(out,record.hostname,"worker-custom-domain",worker,base,issuer);
  }
  return [...out.values()].sort((a,b)=>a.hostname===base?-1:b.hostname===base?1:a.hostname.localeCompare(b.hostname));
}
