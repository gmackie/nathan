#!/usr/bin/env node
/** Verify the publishable artifact and its selectable financial claims. */
import assert from 'node:assert/strict';
import {readFile, readdir, stat} from 'node:fs/promises';
import {resolve, join, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import vm from 'node:vm';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const run=spawnSync(process.execPath,[join(root,'scripts/build-site.mjs')],{cwd:root,encoding:'utf8'});
assert.equal(run.status,0,run.stderr||run.stdout);
const out=join(root,'dist/site');
const research=join(root,'plans/reports/nathan-vs-clerk-2026-10-28');
const input=JSON.parse(await readFile(join(research,'model-inputs.json'),'utf8'));
const {createCostModel}=await import(join(research,'calculator.mjs'));
const model=createCostModel(input);
const html=await readFile(join(out,'index.html'),'utf8');
assert.ok(html.startsWith('<!doctype html>'));
assert.ok(html.includes('lang="en"'));
assert.equal([...html.matchAll(/<h1\b/g)].length,1);
assert.ok(!/tasks\.gmac|NATH-\d|\/Users\/|\/Volumes\//.test(html),'internal metadata in marketing HTML');
assert.ok(!/<form\b|<iframe\b|<script[^>]+src=|<link[^>]+stylesheet/.test(html),'unexpected remote/runtime dependency');
assert.ok(!/javascript:|\sonclick=|\sonload=/.test(html),'executable URL/handler');
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
assert.equal(new Set(ids).size,ids.length,'duplicate IDs');
for(const [,fragment] of html.matchAll(/href="#([^"]+)"/g))assert.ok(ids.includes(fragment),'missing anchor '+fragment);
for(const match of html.matchAll(/<(?:img|input|select|button)\b[^>]*>/g)) {
  if(match[0].startsWith('<img'))assert.ok(/\balt="[^"]+"/.test(match[0]),'image without alt');
  if(match[0].startsWith('<button'))assert.ok(/\btype="button"/.test(match[0]),'implicit submit action');
}
for(const [,href] of html.matchAll(/(?:src|href)="(\/[^"#?]*)/g)) {
  if(href==='/')continue;
  const path=join(out,href.slice(1));
  assert.ok((await stat(path)).isFile(),'missing local asset '+href);
}
const script=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.equal(script.length,1);
new vm.Script(script[0][1]);
const headers=await readFile(join(out,'_headers'),'utf8');
for(const [,source] of script)assert.ok(headers.includes(createHash('sha256').update(source).digest('base64')),'CSP blocks marketing script');
const manifest=JSON.parse(await readFile(join(out,'build-manifest.json'),'utf8'));
for(const [name,hash] of Object.entries(manifest.files))assert.equal(createHash('sha256').update(await readFile(join(out,name))).digest('hex'),hash,'wrong artifact hash '+name);
for(const name of ['costs.html','report-static.html','report.html']) {
  const report=await readFile(join(out,'reports',name),'utf8');
  assert.ok(!/tasks\.gmac|NATH-\d|\/Users\/|\/Volumes\//.test(report),'internal metadata in report '+name);
  if(name!=='report.html')assert.ok(!/<script\b|<input\b|<select\b/.test(report),'static report requires JavaScript');
  for(const [,source] of report.matchAll(/<script>([\s\S]*?)<\/script>/g))assert.ok(headers.includes(createHash('sha256').update(source).digest('base64')),'CSP blocks report calculator');
  for(const [,href] of report.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const url=new URL(href,'https://nathan.example/reports/'+name);
    if(url.origin!=='https://nathan.example')continue;
    const target=join(out,url.pathname==='/'?'index.html':decodeURIComponent(url.pathname.slice(1)));
    assert.ok((await stat(target)).isFile(),'missing public report link '+href);
    if(url.hash&&target.endsWith('.html'))assert.ok((await readFile(target,'utf8')).includes('id="'+url.hash.slice(1)+'"'),'missing report fragment '+href);
  }
}
assert.ok(!(await readdir(out)).some(n=>n==='_worker.js'||n==='functions'),'runtime code in static deployment');

const million=model.calculateCrud(1000000);
const usd=n=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(n);
for(const [id,key] of [['nathan-total','nathanTotalCurrent'],['clerk-total','clerkTotalCurrent'],['nathan-app','commonAppCostCurrent'],['nathan-auth','nathanAuthIncrementCurrent']]) {
  const value=new RegExp('id="'+id+'">([^<]+)<').exec(html)?.[1];
  assert.equal(value,usd(million[key]),'stale no-JS fallback '+id);
}

// Same DOM interactions used in the page, with expected values independently
// calculated in Python Decimal. Covers every audience/activity/scope choice.
const cases=[];
for(const users of input.crud.scales)for(const requests of [100,1000,10000])for(const scope of ['crud','identity'])cases.push({users,requests,scope});
const py=spawnSync('python3',['-B','-c',
  'import sys,json; from cost_model import calculate,calculate_crud; print(json.dumps([calculate_crud(c["users"],app_overrides={"requestsPerActiveUser":c["requests"]}) if c["scope"]=="crud" else calculate(c["users"]) for c in json.loads(sys.stdin.read())]))'],
  {cwd:research,input:JSON.stringify(cases),encoding:'utf8'});
assert.equal(py.status,0,py.stderr);
const wants=JSON.parse(py.stdout);
const nodes=new Map();
const node=id=>{
  if(!nodes.has(id))nodes.set(id,{id,value:'',textContent:'',disabled:false,open:false,listeners:{},attrs:{},addEventListener(event,fn){this.listeners[event]=fn;},setAttribute(key,value){this.attrs[key]=value;}});
  return nodes.get(id);
};
node('audience').value='1000000';node('activity').value='1000';node('scope').value='crud';
node('agent-brief').textContent='Read README.md and AGENTS.md. Review staging evidence.';
const context={Intl,console,NATHAN_COST_INPUTS:input,createCostModel,
  document:{getElementById:node,querySelector(sel){if(sel==='input[name="scope"]:checked')return node('scope');return node(sel);},querySelectorAll(){return[node('audience'),node('activity'),node('scope')];}},navigator:{}};
vm.createContext(context);
vm.runInContext(await readFile(join(root,'site/site.mjs'),'utf8'),context);
for(let i=0;i<cases.length;i++) {
  const c=cases[i],w=wants[i];node('audience').value=String(c.users);node('activity').value=String(c.requests);node('scope').value=c.scope;
  node('audience').listeners.change();
  assert.equal(node('nathan-total').textContent,usd(c.scope==='crud'?w.nathanTotalCurrent:w.nathanCashCurrent));
  assert.equal(node('clerk-total').textContent,usd(c.scope==='crud'?w.clerkTotalCurrent:w.clerkPro));
  assert.equal(node('nathan-auth').textContent,usd(c.scope==='crud'?w.nathanAuthIncrementCurrent:w.nathanCashCurrent));
  assert.equal(node('nathan-share').textContent,(c.scope==='crud'?w.nathanAuthShareCurrentPercent:100).toFixed(1)+'%');
  assert.equal(node('clerk-share').textContent,(c.scope==='crud'?w.clerkAuthShareCurrentPercent:100).toFixed(1)+'%');
  assert.equal(node('activity').disabled,c.scope!=='crud');
}
await node('copy-brief').listeners.click();
assert.equal(node('agent-brief-fallback').open,true,'clipboard fallback inaccessible');
let copied='';context.navigator.clipboard={writeText:async value=>{copied=value;}};
await node('copy-brief').listeners.click();
assert.equal(copied,node('agent-brief').textContent);
assert.ok(node('copy-feedback').textContent.startsWith('Brief copied'));
console.log(`PASS: generated site, local links, public reports, script/CSP/asset integrity, ${cases.length} Python-backed UI scenarios, and clipboard success/fallback.`);
