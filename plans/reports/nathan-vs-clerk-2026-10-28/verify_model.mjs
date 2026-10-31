import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createCostModel} from "./calculator.mjs";
const input = JSON.parse(readFileSync(new URL("./model-inputs.json", import.meta.url)));
const expected = JSON.parse(readFileSync(new URL("./model-results.json", import.meta.url)));
const {calculate, calculateCrud, clerkCost} = createCostModel(input);
let cases = 0;
function compare(want, actual, path = "") {
  for (const [key, value] of Object.entries(want)) {
    if (key === "incrementalWithoutAnyAllowances") continue;
    const name = path + "." + key;
    if (value && typeof value === "object") compare(value, actual[key], name);
    else if (typeof value === "number") assert.ok(Math.abs(value - actual[key]) < Math.max(0.0000001, Math.abs(value) * 1e-12), `${name}: expected ${value}, got ${actual[key]}`);
    else assert.equal(value, actual[key], name);
  }
}
for (const row of expected.baseline) {compare(row, calculate(row.registeredUsers)); cases++;}
for (const scenario of expected.scenarios) {
  for (const row of scenario.results) {compare(row, calculate(row.registeredUsers, scenario.overrides)); cases++;}
}
for (const row of expected.retentionAtOneMillionRegistered) {compare(row, calculate(1000000, {retainedFraction: row.retainedUsers / 1000000})); cases++;}
for (const row of expected.laborAtOneMillion) {compare(row, calculate(1000000, {incrementalOperatorHours: row.incrementalLabor / 100})); cases++;}
compare(expected.continuous5000RpsAt51000Registered, calculate(51000, {protectedRequestsPerRetainedUser: 5000 * 30 * 86400 / 51000, protectedLogFraction: 0.01})); cases++;
assert.equal(clerkCost(1000000), 17225);
assert.equal(clerkCost(51000, true), 40);
const identityCases=cases;
for(const row of expected.crudBaseline) {compare(row,calculateCrud(row.registeredUsers));cases++;}
for(const s of expected.crudScenarios) for(const row of s.results) {compare(row,calculateCrud(row.registeredUsers,{},s.overrides));cases++;}
for(const s of expected.crudAuthScenarios) for(const row of s.results) {compare(row,calculateCrud(row.registeredUsers,s.authOverrides));cases++;}
// Additional cross-language edge cases around shared allowance thresholds,
// separate populations, zero traffic, added costs, mail and refresh patterns.
const edges=[
  {users:0}, {users:1}, {users:5000}, {users:9999}, {users:10000}, {users:10001},
  {users:51000,app:{activeFraction:0.701},auth:{retainedFraction:0.701}},
  {users:123457,app:{activeFraction:0.337},auth:{retainedFraction:0.337,emailsPerRetainedUser:0.15}},
  {users:500000,app:{activeFraction:0.2},auth:{retainedFraction:0.1}},
  {users:1000000,app:{requestsPerActiveUser:0,bytesPerRegisteredUser:0}},
  {users:1000000,app:{readFraction:1}}, {users:1000000,app:{readFraction:0}},
  {users:1000000,app:{commonMonthlyCosts:123.45},auth:{incrementalOperatorHours:20,otherMonthlyCosts:1.11}},
  {users:1000000,auth:{refreshesPerRetainedUser:1920}},
  {users:1000000,auth:{protectedRequestsPerRetainedUser:1000}},
  {users:1000000,app:{activeFraction:0,commonMonthlyCosts:100}},
  {users:1000000,app:{logFraction:1,policyLogFraction:1}},
  {users:1000000,app:{requestsPerActiveUser:1,bytesPerRegisteredUser:0},auth:{retainedFraction:0}},
  {users:5000000,app:{bytesPerRegisteredUser:250000,readRowsPerRead:1000}}
];
const {execFileSync}=await import('node:child_process');
const python=execFileSync('python3',['-c',
  'import sys,json; from cost_model import calculate_crud; print(json.dumps([calculate_crud(c["users"],c.get("auth"),c.get("app")) for c in json.loads(sys.stdin.read())]))'],
  {cwd:new URL('.',import.meta.url),input:JSON.stringify(edges),encoding:'utf8'});
JSON.parse(python).forEach((row,index)=>{const c=edges[index];compare(row,calculateCrud(c.users,c.auth,c.app));cases++;});
console.log(`PASS: JavaScript agrees with Python Decimal across ${cases} cases (${identityCases} identity-only, ${cases-identityCases} CRUD/shared-account cases).`);
