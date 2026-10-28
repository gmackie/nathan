import test from "node:test";
import assert from "node:assert/strict";
import { buildPlan, validateConfig } from "../scripts/lib/config.mjs";
import { zoneForHostname } from "../scripts/lib/cloudflare.mjs";
import { stripJsonc } from "../scripts/lib/wrangler.mjs";
const cfg = { name:"nathan", hostname:"auth.example.com", securityProfile:"business", database:{type:"d1",name:"nathan-db"}, applications:[{id:"app",kind:"worker",workerName:"demo",hostname:"app.example.com",protection:"gateway"}] };
test("validates example",()=>assert.deepEqual(validateConfig(cfg),[]));
test("rejects duplicate ids",()=>assert.match(validateConfig({...cfg,applications:[cfg.applications[0],cfg.applications[0]]}).join(" "),"Duplicate"));
test("rejects invalid hostnames",()=>{
  for (const hostname of ["bad name","evil.com.attacker.","*.example.com","foo..bar.com","-bad.example.com"]) {
    assert.match(validateConfig({...cfg,hostname}).join(" "),"hostname");
  }
});
test("requires a gateway hostname",()=>assert.match(validateConfig({...cfg,applications:[{id:"x",kind:"gateway",protection:"gateway"}]}).join(" "),"hostname"));
test("rejects non-HTTPS callbacks",()=>assert.match(validateConfig({...cfg,applications:[{id:"x",kind:"external",redirectUris:["http://evil.test/cb"]}]}).join(" "),"redirectUris"));
test("plan never implies mutation",()=>assert.ok(buildPlan(cfg).every(x=>x.operation==="propose")));
test("longest valid matching zone",()=>assert.equal(zoneForHostname([{name:"example.com"},{name:"deep.example.com"}],"auth.deep.example.com").name,"deep.example.com"));
test("zone boundary rules",()=>assert.equal(zoneForHostname([{name:"example.com"}],"myexample.com"),null));
test("JSONC parser retains URLs in quoted strings",()=>assert.deepEqual(JSON.parse(stripJsonc('{"url":"https://example.com", // note\n"x":1,}')),{url:"https://example.com",x:1}));
