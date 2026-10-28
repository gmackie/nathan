import test from "node:test";
import assert from "node:assert/strict";
import {
  realmForLoginHostname,realmIssuerHostname,isHostnameWithinRealm,
  assertRealmClientHost,realmCallback,validateDomainName,validateCallbackPath,
  discoverRealmHostCandidates,domainWideRoutingPreview,parseRealmHostSelection
} from "../src/shared/realm.mjs";

test("one login issuer covers root and nested subdomains",()=>{
  assert.deepEqual(realmForLoginHostname("login.example.com"),{
    apex:"example.com",issuerHostname:"login.example.com",includeApex:true,includeSubdomains:true,registration:"approved-only"
  });
  for(const host of ["example.com","www.example.com","app.example.com","org.team.example.com"])
    assert.ok(isHostnameWithinRealm(host,"example.com"));
});
test("rejects lookalikes, other zones, ports, wildcard and trailing dot",()=>{
  for(const host of ["evil-example.com","badexample.com","example.com.evil.org","example.com:443",
    "*.example.com","foo.example.com.","Example.com","test..example.com","-abc.example.com"]) {
    assert.equal(isHostnameWithinRealm(host,"example.com"),false,host);
  }
  assert.throws(()=>realmForLoginHostname("auth.example.com"),/login/);
  assert.throws(()=>validateDomainName("*.example.com"));
});
test("never allows central issuer itself to register as a relying-party client",()=>{
  assert.throws(()=>assertRealmClientHost("login.example.com","example.com","login.example.com"),/issuer/);
  assert.equal(assertRealmClientHost("example.com","example.com","login.example.com"),"example.com");
});
test("no wildcards, encoded traversal or open redirect callbacks",()=>{
  assert.equal(realmCallback("example.com","example.com","login.example.com"),"https://example.com/auth/callback");
  assert.equal(realmCallback("app.example.com","example.com","login.example.com","gateway"),"https://app.example.com/__nathan/callback");
  assert.equal(realmCallback("app.example.com","example.com","login.example.com","worker","/oauth/callback"),"https://app.example.com/oauth/callback");
  for(const bad of ["//evil.org","https://evil.org","/cb?redirect=x","/cb#fragment","/cb*","/a/../b","/%2e%2e","/a\\b"]) {
    assert.throws(()=>validateCallbackPath(bad));
  }
});
test("only HTTP-proxied DNS and exact Worker custom hosts become suggestions",()=>{
  const result=discoverRealmHostCandidates({
    apex:"example.com",issuerHostname:"login.example.com",
    dnsRecords:[
      {name:"example.com",proxied:true,type:"A"},
      {name:"api.example.com",proxied:true,type:"CNAME"},
      {name:"mail.example.com",proxied:false,type:"MX"},
      {name:"hidden.example.com",proxied:false,type:"A"},
      {name:"*.example.com",proxied:true,type:"A"},
      {name:"login.example.com",proxied:true,type:"A"},
      {name:"notexample.com",proxied:true,type:"A"}
    ],
    workerDomains:[{hostname:"app.example.com",service:"my-app"},{hostname:"api.example.com",service:"my-api"}]
  });
  assert.deepEqual(result.map(x=>x.hostname),["example.com","api.example.com","app.example.com"]);
  assert.equal(result[1].workerName,"my-api");
  assert.deepEqual(result[1].sources,["cloudflare-proxied-dns","worker-custom-domain"]);
  assert.ok(result.every(x=>x.approved===false));
});
test("wildcard routes are documented only, never silently deployed",()=>{
  const plan=domainWideRoutingPreview("example.com");
  assert.deepEqual(plan.optionalGatewayRoutes,["example.com/*","*.example.com/*"]);
  assert.equal(plan.protectsTrafficAutomatically,false);
  assert.equal(plan.sharedParentDomainCookies,false);
  assert.equal(plan.wildcardRedirects,false);
});

test("batch onboarding only accepts explicit, exact owned hostnames",()=>{
  const valid=parseRealmHostSelection("example.com\nwww.example.com,app.example.com\nwww.example.com","example.com","login.example.com");
  assert.deepEqual(valid,["example.com","www.example.com","app.example.com"]);
  assert.throws(()=>parseRealmHostSelection("*.example.com","example.com","login.example.com"));
  assert.throws(()=>parseRealmHostSelection("example.com.evil.net","example.com","login.example.com"));
  assert.throws(()=>parseRealmHostSelection("login.example.com","example.com","login.example.com"));
  assert.throws(()=>parseRealmHostSelection("a.example.com\nb.example.com","example.com","login.example.com",{max:1}));
});
