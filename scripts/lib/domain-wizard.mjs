import { loadConfig } from "./config.mjs";
import { CloudflareClient, zoneForHostname } from "./cloudflare.mjs";
import {
  realmCallback, discoverRealmHostCandidates,domainWideRoutingPreview,
  assertRealmClientHost
} from "../../src/shared/realm.mjs";

export async function domainCommand(args,file) {
  const cfg=await loadConfig(file);
  if(!cfg.realm)throw Error("No domain-wide realm configured. Run nathan init with login.<domain> first.");
  const action=args[0]||"overview";
  const base=cfg.realm.apex,issuer=cfg.hostname;
  if(action==="overview") {
    console.log(JSON.stringify({
      issuer:"https://"+issuer+"/api/auth",
      discovery:"https://"+issuer+"/.well-known/openid-configuration",
      coverage:[base,"*."+base],
      onboarding:"Each exact relying-party hostname needs its own approved OAuth client and callback",
      crossDomainCookies:false,automaticGateway:false
    },null,2));
    return;
  }
  if(action==="callback") {
    const host=assertRealmClientHost(args[1],base,issuer);
    console.log(JSON.stringify({hostname:host,callbackUri:realmCallback(host,base,issuer,args[2]||"web",args[3]),
      issuer:"https://"+issuer+"/api/auth",
      note:"Register this exact URI in Identity Studio; never add a wildcard redirect."},null,2));
    return;
  }
  if(action==="routes"){
    console.log(JSON.stringify(domainWideRoutingPreview(base),null,2));
    return;
  }
  if(action!=="discover")throw Error("Usage: nathan domains <overview|discover|callback hostname [kind] [callbackPath]|routes>");
  if(!cfg.accountId)throw Error("Cloudflare accountId required to inspect a verified zone");
  const cf=new CloudflareClient(process.env.CLOUDFLARE_API_TOKEN,cfg.accountId);
  const zones=await cf.zones();
  const zone=zoneForHostname(zones,base);
  if(!zone||zone.status!=="active")throw Error("No accessible active Cloudflare zone for realm");
  const [records,workers]=await Promise.all([cf.dnsRecordsForZone(zone.id),cf.workerDomains()]);
  const exact=workers.filter(d=>!d.zone_id||d.zone_id===zone.id);
  const candidates=discoverRealmHostCandidates({apex:base,issuerHostname:issuer,
    dnsRecords:records,workerDomains:exact});
  console.log(JSON.stringify({
    accountId:cfg.accountId,verifiedZone:zone.name,issuer:"https://"+issuer+"/api/auth",
    status:"review-only",candidates,
    warning:"DNS/Worker discovery does not authorize clients, prove origin isolation or automatically protect hostnames. Approve each application in Identity Studio."
  },null,2));
}
