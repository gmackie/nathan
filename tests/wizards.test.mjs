import test from "node:test";
import assert from "node:assert/strict";
import { providerGuide } from "../scripts/lib/provider-wizard.mjs";
import { gatewayChecklist } from "../scripts/lib/protect-wizard.mjs";
import { validateAdminPromotion } from "../scripts/lib/admin-wizard.mjs";

const cfg={hostname:"auth.example.com",adminEmails:["Admin@Example.com"]};
test("Google and GitHub callback guides derive from configured hostname",()=>{
  const g=providerGuide("google","login.example.com");
  const gh=providerGuide("github","login.example.com");
  assert.equal(g.callback,"https://login.example.com/api/auth/callback/google");
  assert.equal(gh.callback,"https://login.example.com/api/auth/callback/github");
  assert.equal(g.secretBindings[1],"GOOGLE_CLIENT_SECRET");
  assert.throws(()=>providerGuide("fake","login.example.com"));
});
test("gateway wizard uses exact callback and never targets the IdP itself",()=>{
  const good=gatewayChecklist(cfg,{id:"dash",kind:"worker",hostname:"app.example.com",workerName:"private-app"});
  assert.equal(good.callback,"https://app.example.com/__nathan/callback");
  assert.equal(good.backchannelLogout,"https://app.example.com/__nathan/backchannel");
  assert.throws(()=>gatewayChecklist(cfg,{id:"x",kind:"worker",hostname:"auth.example.com",workerName:"oops"}));
  assert.throws(()=>gatewayChecklist(cfg,{id:"x",kind:"external",hostname:"other.example.com"}));
});
test("administrator promotion requires verified allowlist membership",()=>{
  assert.equal(validateAdminPromotion("ADMIN@example.com",cfg),"admin@example.com");
  assert.throws(()=>validateAdminPromotion("stranger@example.com",cfg));
  assert.throws(()=>validateAdminPromotion("invalid",cfg));
});
