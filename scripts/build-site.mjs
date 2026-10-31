#!/usr/bin/env node
/** Build only the static marketing site. No credentials, network or dependencies. */
import {readFile, writeFile, mkdir, copyFile, readdir, rm} from 'node:fs/promises';
import {resolve, join, dirname, relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const site = join(root, 'site');
const out = join(root, 'dist/site');
const research = join(root, 'plans/reports/nathan-vs-clerk-2026-10-28');
const inputs = JSON.parse(await readFile(join(research, 'model-inputs.json'), 'utf8'));
const results = JSON.parse(await readFile(join(research, 'model-results.json'), 'utf8'));
const {createCostModel} = await import(join(research, 'calculator.mjs'));
const model = createCostModel(inputs);

// A build must not publish a stale rate sheet or hand-edited headline amount.
for(const row of results.crudBaseline) {
  const fresh = model.calculateCrud(row.registeredUsers);
  for(const key of ['commonAppCostCurrent','nathanTotalCurrent','clerkTotalCurrent','nathanAuthIncrementCurrent']) {
    if(fresh[key] !== row[key]) throw new Error(`Stale report result: ${row.registeredUsers} ${key}`);
  }
}

const [template, css, interaction, calculator] = await Promise.all([
  readFile(join(site,'index.html'),'utf8'), readFile(join(site,'styles.css'),'utf8'),
  readFile(join(site,'site.mjs'),'utf8'), readFile(join(research,'calculator.mjs'),'utf8')
]);
const inlineScript = calculator.replace('export function createCostModel','function createCostModel')
  + '\nconst NATHAN_COST_INPUTS = ' + JSON.stringify(inputs).replaceAll('<','\\u003c') + ';\n' + interaction;
const inlineAsset = async name => (await readFile(join(site,'assets',name))).toString('base64');
const html = template.replace('/* SITE_STYLES */', css).replace('/* SITE_SCRIPT */', inlineScript)
  .replace('href="/assets/favicon.svg"', `href="data:image/svg+xml;base64,${await inlineAsset('favicon.svg')}"`)
  .replace('src="/assets/naming-origin.webp"', `src="data:image/webp;base64,${await inlineAsset('naming-origin.webp')}"`);
if(html.includes('/* SITE_')) throw new Error('Unresolved site template marker');
const headline=model.calculateCrud(1000000);
for(const amount of ['nathanTotalCurrent','clerkTotalCurrent','commonAppCostCurrent','nathanAuthIncrementCurrent']
  .map(key=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(headline[key]))) {
  if(!html.includes(amount)) throw new Error(`Missing default cost: ${amount}`);
}

// Output is confined to a dedicated ignored directory, never the auth bundle.
await rm(out,{recursive:true,force:true});
await mkdir(join(out,'assets'),{recursive:true});
await mkdir(join(out,'reports/sources'),{recursive:true});
await writeFile(join(out,'index.html'),html);
for(const asset of ['favicon.svg','naming-origin.webp']) await copyFile(join(site,'assets',asset),join(out,'assets',asset));

function publicReport(source) {
  const result = source
    .replace(/<p class="meta">Cost and ownership report[\s\S]*?<\/p>/,
      '<p class="meta">Cost and ownership report · prices captured 28 October 2026 · USD, before tax · <a href="/">Back to Nathan</a> · <a href="/reports/report.html">Interactive calculator</a> · <a href="/reports/model-inputs.json">Inputs</a> · <a href="/reports/source-ledger.json">Source ledger</a></p>')
    .replace(/<p class="meta">Prepared for Nathan launch planning[\s\S]*?<\/p>/,
      '<p class="meta">Published rates and illustrative workloads; capacity remains unverified. Recheck prices before relying on a projection. <a href="/">Back to Nathan</a>.</p>')
    .replaceAll('and the report bundle ZIP','and source/model downloads in this directory')
    .replaceAll('raw inputs and results are included in the report bundle','raw inputs and results are available beside this report')
    .replaceAll('\npython3 build_report.py','')
    .replace(/<code>((?:sources\/)?[a-z][a-z0-9-]*\.(?:json|csv|mjs|py|txt|html))<\/code>/g,
      '<a href="$1"><code>$1</code></a>');
  if(/tasks\.gmac|NATH-\d|\/Users\/|\/Volumes\//.test(result)) throw new Error('Internal metadata remains in public report');
  return result;
}
const staticReport = publicReport(await readFile(join(research,'report-static.html'),'utf8'));
await writeFile(join(out,'reports/costs.html'),staticReport);
await writeFile(join(out,'reports/report-static.html'),staticReport);
await writeFile(join(out,'reports/report.html'),publicReport(await readFile(join(research,'report.html'),'utf8')));

const publicData = [
  'model-inputs.json','model-results.json','source-ledger.json','baseline-costs.csv','sensitivity-costs.csv',
  'crud-total-costs.csv','crud-sensitivity-costs.csv','cost_model.py','calculator.mjs','verify_model.mjs',
  'make_charts.py','fetch_sources.py',
  ...['cost-at-scale','one-million-breakdown','crud-total-cost-at-scale','crud-cost-composition'].flatMap(name=>[name+'.png',name+'.svg'])
];
for(const name of publicData) await copyFile(join(research,name),join(out,'reports',name));
for(const entry of await readdir(join(research,'sources'),{withFileTypes:true})) {
  if(entry.isFile() && entry.name.endsWith('.txt')) await copyFile(join(research,'sources',entry.name),join(out,'reports/sources',entry.name));
}

await writeFile(join(out,'robots.txt'),'User-agent: *\nAllow: /\n');
await writeFile(join(out,'404.html'),'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Nathan — You cannot see this</title><style>body{font:18px/1.6 system-ui;max-width:650px;margin:80px auto;padding:24px;color:#1b1d19;background:#fffcf3}h1{font-size:44px;line-height:1.1;letter-spacing:-.05em}a{color:inherit}</style><h1>You cannot<br>see this.</h1><p>404. The page does not exist. Its absence has been documented.</p><a href="/">Return to the inspectable part</a></html>\n');

async function walk(path) {
  const entries = await readdir(path,{withFileTypes:true});
  const files=[];
  for(const entry of entries) {
    const full=join(path,entry.name);
    if(entry.isDirectory())files.push(...await walk(full));
    else if(entry.isFile())files.push(full);
  }
  return files.sort();
}
const scriptHashes = new Set();
for(const path of (await walk(out)).filter(name=>name.endsWith('.html'))) {
  const source=await readFile(path,'utf8');
  for(const match of source.matchAll(/<script>([\s\S]*?)<\/script>/g)) {
    scriptHashes.add("'sha256-"+createHash('sha256').update(match[1]).digest('base64')+"'");
  }
}
const csp = `default-src 'none'; script-src 'self' ${[...scriptHashes].sort().join(' ')}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`;
await writeFile(join(out,'_headers'),`/*
  Content-Security-Policy: ${csp}
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
/assets/*
  Cache-Control: public, max-age=3600
`);
const files = await walk(out);
const manifest = {};
for(const path of files) manifest[relative(out,path).replaceAll('\\','/')] = createHash('sha256').update(await readFile(path)).digest('hex');
await writeFile(join(out,'build-manifest.json'),JSON.stringify({version:1,priceSnapshot:inputs.asOf,files:manifest},null,2)+'\n');
console.log(`Built static Nathan site: ${relative(root,out)}/ (${files.length+1} files; no functions, credentials, network calls or external runtime assets).`);
