import test from "node:test";
import assert from "node:assert/strict";
import { buildPlan, validateConfig } from "../scripts/lib/config.mjs";
const cfg = { name:"nathan", hostname:"auth.example.com", securityProfile:"business", database:{type:"d1",name:"nathan-db"}, applications:[{id:"app",kind:"worker",workerName:"demo",hostname:"app.example.com",protection:"gateway"}] };
test("validates example",()=>assert.deepEqual(validateConfig(cfg),[]));
test("rejects duplicate ids",()=>assert.match(validateConfig({...cfg,applications:[cfg.applications[0],cfg.applications[0]]}).join(" "),"Duplicate"));
test("rejects bad hostname",()=>assert.match(validateConfig({...cfg,hostname:"bad name"}).join(" "),"hostname"));
test("plan is read-only description",()=>assert.deepEqual(buildPlan(cfg).map(x=>x.operation),["propose","propose","propose","propose"]));
