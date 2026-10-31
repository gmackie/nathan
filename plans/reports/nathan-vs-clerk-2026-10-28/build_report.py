"""Build self-contained interactive and static reports from the saved cost model."""
from pathlib import Path
from html import escape
import json
import math
import re

ROOT = Path(__file__).resolve().parent
I = json.loads((ROOT / "model-inputs.json").read_text())
R = json.loads((ROOT / "model-results.json").read_text())
S = json.loads((ROOT / "source-ledger.json").read_text())


def usd(value):
    return f"${value:,.2f}"


def count(value):
    return f"{value:,.0f}"


def source(key):
    n = next(n for n, item in enumerate(S, 1) if item["id"] == key)
    return f'<a href="#source-{n}" aria-label="Source {n}">[{n}]</a>'


def table(headers, rows, label):
    return '<div class="scroll" tabindex="0" role="region" aria-label="' + escape(label) + '"><table><thead><tr>' + ''.join('<th scope="col">' + x + '</th>' for x in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + str(x) + '</td>' for x in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def chart(crud=False):
    rows = R["crudBaseline"] if crud else [row for row in R["baseline"] if row["registeredUsers"] >= 50000]
    prefix = 'crud-' if crud else ''
    ceiling = 90000 if crud else 80000
    series = [("clerkTotalCurrent", "clerk-line", "App + Clerk"), ("nathanTotalCurrent", "nathan-line", "App + Nathan"), ("commonAppCostCurrent", "app-line", "App only")] if crud else [("clerkPro", "clerk-line", "Clerk Pro"), ("nathanCashCurrent", "nathan-line", "Nathan + email")]
    title = 'Modeled CRUD app plus authentication monthly costs through five million users' if crud else 'Clerk and modeled Nathan monthly identity costs through five million retained users'
    description = 'At one million active and retained users: app only 686.65 dollars, app plus Nathan 1278.57 dollars, app plus Clerk 17911.65 dollars. Shared account allowances apply once.' if crud else 'At one million retained users: Clerk Pro 17,225 dollars, Nathan Cloudflare plus email 483.65 dollars.'
    x = lambda n: 67 + (math.log10(n) - math.log10(50000)) / 2 * 593
    y = lambda cost: 284 - cost / ceiling * 236
    out = [f'<svg class="cost-chart" viewBox="0 0 700 350" role="img" aria-labelledby="{prefix}chart-title {prefix}chart-desc"><title id="{prefix}chart-title">{title}</title><desc id="{prefix}chart-desc">Logarithmic user axis, linear dollar axis. {description} Published prices and unmeasured workloads; incremental labor excluded.</desc>']
    for value in ([0, 30000, 60000, 90000] if crud else [0, 20000, 40000, 60000, 80000]):
        out.append(f'<line x1="67" x2="670" y1="{y(value):.2f}" y2="{y(value):.2f}" class="grid-line"/><text x="58" y="{y(value)+4:.2f}" text-anchor="end" class="axis-label">${value//1000}K</text>')
    for value, label in [(50000, "50K"), (100000, "100K"), (250000, "250K"), (1000000, "1M"), (2000000, "2M"), (5000000, "5M")]:
        out.append(f'<text x="{x(value):.2f}" y="307" text-anchor="middle" class="axis-label">{label}</text>')
    for key, cls, label in series:
        points = ' '.join(f'{x(row["registeredUsers"]):.2f},{y(row[key]):.2f}' for row in rows)
        out.append(f'<polyline points="{points}" class="{cls}"/>')
        for row in rows:
            out.append(f'<circle cx="{x(row["registeredUsers"]):.2f}" cy="{y(row[key]):.2f}" r="3.5" class="{cls}"><title>{label}, {count(row["registeredUsers"])} retained users: {usd(row[key])}/month</title></circle>')
    out.append('<text x="370" y="340" text-anchor="middle" class="axis-label">' + ('Active app users = retained users' if crud else 'Monthly retained users') + ' · log scale</text></svg>')
    return ''.join(out)


CSS = """
html,body{margin:0;padding:0}*{box-sizing:border-box}body{font-family:var(--font-sans,system-ui,sans-serif);font-size:14px;line-height:1.62;color:var(--foreground,#172033)}h1{font-size:24px;line-height:1.22;margin:0 0 9px;letter-spacing:-.025em}h2{font-size:19px;line-height:1.3;margin:28px 0 10px;letter-spacing:-.015em}h3{font-size:15px;line-height:1.4;margin:18px 0 7px}p{margin:9px 0}a{color:var(--accent,#2458b8);text-underline-offset:3px}code,pre{font-family:var(--font-mono,ui-monospace,monospace);font-size:12px}code{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:14px;background:var(--code-background,#eef2f8);color:var(--code-foreground,var(--foreground,#172033));border-radius:var(--radius,8px)}.meta,.muted,figcaption{font-size:12px;color:var(--muted-foreground,#58657a)}.badge{display:inline-block;padding:3px 8px;border:1px solid var(--border,#cbd3df);border-radius:5px;font-size:11px;line-height:1.5;margin:3px 5px 3px 0}.callout{margin:16px 0;padding:12px 16px;border-left:3px solid var(--accent,#2458b8);border-radius:0 var(--radius,8px) var(--radius,8px) 0;background:var(--secondary,#f0f4fa)}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:18px 0}.stat,.panel{padding:16px;border:1px solid var(--border,#cbd3df);border-radius:var(--radius,8px);background:var(--card,#f7f9fc)}.stat strong{display:block;font-size:23px;font-weight:700;line-height:1.25;letter-spacing:-.025em}.stat span{font-size:12px}.scroll{overflow-x:auto;margin:12px 0}table{width:100%;min-width:610px;border-collapse:collapse;font-size:12px;font-variant-numeric:tabular-nums}th,td{text-align:left;vertical-align:top;padding:10px 8px;border-bottom:1px solid var(--border,#cbd3df)}th{font-weight:650}td:first-child{font-weight:550}ul,ol{padding-left:22px}li{margin:7px 0}details{margin:13px 0;border:1px solid var(--border,#cbd3df);border-radius:var(--radius,8px);padding:13px 15px}summary{font-weight:650;cursor:pointer}summary::marker{color:var(--accent,#2458b8)}figure{margin:20px 0}figcaption{margin-top:10px}.legend{display:flex;flex-wrap:wrap;gap:16px;font-size:12px;margin:12px 0}.legend span{display:inline-flex;align-items:center;gap:6px}.dot{width:10px;height:10px;display:inline-block;border-radius:50%;background:var(--chart-1,#2563eb)}.dot.nathan{background:var(--chart-2,#15803d)}.cost-chart{display:block;width:100%;min-width:600px;height:350px;overflow:visible}.grid-line{stroke:var(--border,#cbd3df);stroke-dasharray:4 4;stroke-width:1}.axis-label{fill:var(--muted-foreground,#58657a);font-size:12px;font-family:var(--font-sans,system-ui,sans-serif)}.clerk-line{stroke:var(--chart-1,#2563eb);stroke-width:2.6;fill:none}.nathan-line{stroke:var(--chart-2,#15803d);stroke-width:2.6;fill:none}circle.clerk-line{fill:var(--chart-1,#2563eb)}circle.nathan-line{fill:var(--chart-2,#15803d)}.flow{display:grid;grid-template-columns:1fr auto 1fr auto 1fr;align-items:center;gap:7px;margin:16px 0}.flow span{border:1px solid var(--border,#cbd3df);border-radius:var(--radius,8px);padding:12px}.flow b{color:var(--accent,#2458b8)}.controls{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.field{display:block;font-size:12px;font-weight:600}.field input,.field select{display:block;width:100%;margin-top:5px;padding:9px;border:1px solid var(--border,#cbd3df);background:var(--background,#fff);color:var(--foreground,#172033);font:inherit;font-variant-numeric:tabular-nums;border-radius:5px}.output{margin-top:16px;padding:14px;border:1px solid var(--border,#cbd3df);border-radius:var(--radius,8px);background:var(--secondary,#f0f4fa)}.output p{margin:6px 0}.source-list{font-size:12px}.source-list li{margin:12px 0;overflow-wrap:anywhere}a:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,.scroll:focus-visible{outline:2px solid var(--ring,#2458b8);outline-offset:3px}.narrow-table table{min-width:450px}.toc{display:flex;flex-wrap:wrap;gap:7px 15px;font-size:12px;margin:18px 0}.recommendation{border-left:3px solid var(--chart-2,#15803d);padding:2px 0 2px 14px}.print-only{display:none}@media(max-width:500px){h1{font-size:22px}.stats{grid-template-columns:1fr}.stat strong{font-size:22px}.controls{grid-template-columns:1fr}.flow{grid-template-columns:1fr}.flow b{display:none}th,td{padding:9px 6px}}@media(prefers-reduced-motion:no-preference){.clerk-line,.nathan-line{animation:draw .55s ease-out both}@keyframes draw{from{stroke-dasharray:1000;stroke-dashoffset:1000}to{stroke-dasharray:1000;stroke-dashoffset:0}}}@media print{body{font-size:10pt;line-height:1.45}details{border:0;padding:0}details>summary{font-size:13pt;margin-top:18px}.calculator,.toc{display:none}.print-only{display:block}table{min-width:0!important;font-size:8pt}.scroll{overflow:visible}.cost-chart{min-width:0;height:auto}.stat,.panel{break-inside:avoid}h2,h3{break-after:avoid}.source-list{font-size:8pt}a{color:inherit}.clerk-line,.nathan-line{animation:none}}
"""

baseline = table(["Registered = retained users", "Cloudflare", "Auth email", "Nathan cash total", "Clerk Pro", "Cash reduction"], [
    [count(row["registeredUsers"]), usd(row["cloudflareCurrent"]), usd(row["emailCost"]), '<strong>' + usd(row["nathanCashCurrent"]) + '</strong>', usd(row["clerkPro"]), f'{row["cashSavingsPercent"]:.1f}%']
    for row in R["baseline"] if row["registeredUsers"] >= 50000
], "Monthly baseline cost table")

sensitivities = table(["Workload at 1M retained users", "Nathan/month", "Versus Clerk Pro $17,225"], [
    [scenario["label"], usd(scenario["results"][2]["nathanCashCurrent"]), f'{scenario["results"][2]["cashSavingsPercent"]:.1f}% lower' if scenario["results"][2]["cashSavingsPercent"] >= 0 else f'{abs(scenario["results"][2]["cashSavingsPercent"]):.1f}% higher'] for scenario in R["scenarios"]
], "One-million user cost sensitivities")

retention = table(["Registered users", "Monthly retained", "Clerk Pro/month", "Nathan/month"], [
    ["1,000,000", count(row["retainedUsers"]), usd(row["clerkPro"]), usd(row["nathanCashCurrent"])] for row in R["retentionAtOneMillionRegistered"]
], "Retained versus registered user costs")

rates = table(["Meter", "Published paid allowance", "Published overage"], [
    ["Workers Standard " + source("workers-pricing"), "$5/account/month minimum; 10M requests + 30M CPU-ms", "$0.30/M requests; $0.02/M CPU-ms"],
    ["D1 reads " + source("d1-pricing"), "25 billion rows/month", "$0.001/M rows read"],
    ["D1 writes " + source("d1-pricing"), "50 million rows/month", "$1/M billed rows written"],
    ["D1 storage " + source("d1-pricing"), "5 GB/account", "$0.75/GB-month"],
    ["Workers Logs, through Nov 30, 2026 " + source("workers-pricing"), "20M events/month; seven-day retention", "$0.60/M events"],
    ["Observability from Dec 1, 2026 " + source("observability-pricing"), "50 GB ingestion + 10 GB-month storage", "$0.25/GB ingested + $0.10/GB-month stored"],
    ["Resend Pro, selected example " + source("resend-pricing"), "$20/month; 50,000 transactional emails", "$0.90/1,000 extra emails, rounded up in buckets"],
], "Published vendor unit prices")

breakdown = table(["1M-user line item", "Usage and calculation", "USD/month"], [
    ["Workers plan", "One paid account", "$5.00"],
    ["Dynamic Worker requests", "(60M − 10M) × $0.30/M", "$15.00"],
    ["Workers CPU", "(500M CPU-ms − 30M) × $0.02/M", "$9.40"],
    ["D1 reads", "720M billed rows, within 25B allowance", "$0.00"],
    ["D1 writes", "(320M − 50M) × $1/M", "$270.00"],
    ["D1 storage", "(12 GB − 5 GB) × $0.75", "$5.25"],
    ["Diagnostic logs, current rates", "(60M events − 20M) × $0.60/M", "$24.00"],
    ["Cloudflare subtotal", "Workers + D1 + current logs", "<strong>$328.65</strong>"],
    ["Transactional email", "$20 + 150 × $0.90; 200,000 emails", "$155.00"],
    ["Nathan modeled cash total", "Infrastructure + email; labor excluded", "<strong>$483.65</strong>"],
    ["Clerk Pro, one app", "$25 + 50,000 × $0.02 + 900,000 × $0.018", "<strong>$17,225.00</strong>"],
], "Worked one-million-user cost breakdown")

assumptions = table(["Input", "Moderate scenario", "Why it matters"], [
    ["Billing population", "Every registered user returns after the first 24 hours that month", "Clerk bills MRU; dormant accounts do not trigger MRU overage."],
    ["Sign-ins", "4/user/month; 10 dynamic requests/sign-in", "40 requests/user includes the modeled ceremony, callback and supporting calls."],
    ["Sign-in CPU and D1", "100 CPU-ms, 80 read rows, 30 written rows per whole sign-in", "Budgets include indexes/cleanup/rate-limit effects; not measured Nathan behavior."],
    ["Refresh", "20/user/month; one request, 5 CPU-ms, 20 reads and 10 writes each", "Short tokens used all day can create hundreds or thousands of refreshes instead."],
    ["Stored data", "12 decimal kB per registered user", "Assumed aggregate identity/account/factor/group/session/index data with bounded retention."],
    ["Lifecycle email", "0.2 emails/retained user/month", "Uses paid Resend whenever nonzero; free daily delivery limits are not assumed away."],
    ["Logs", "100% of auth invocations; one 1 kB event/request", "Current config enables observability; more console events/traces increase cost."],
    ["Protected application requests", "Zero in core identity comparison", "External OIDC apps do not send every business request to the IdP; full gateway scenarios are separate."],
    ["Allowances", "Fresh account; allocations applied once across all Nathan services", "Other Workers/D1/apps on the account consume the same included usage."],
], "Unmeasured workload assumptions")

source_list = '<ol class="source-list">' + ''.join(
    f'<li id="source-{n}"><a href="{escape(item["url"])}">{escape(item["title"])}</a><br>Retrieved {escape(item["retrievedAt"][:10])} UTC; HTTP {item["httpStatus"]}'
    + (f'; page updated {escape(item["documentUpdated"])}' if item.get("documentUpdated") else '')
    + f'. Snapshot: <code>{escape(item["snapshot"])}</code>. SHA-256 recorded in <code>source-ledger.json</code>.</li>'
    for n, item in enumerate(S, 1)) + '</ol>'

CSS += """
.app-line{stroke:var(--muted-foreground,#64748b);stroke-width:2.2;stroke-dasharray:5 4;fill:none}circle.app-line{fill:var(--muted-foreground,#64748b)}.dot.app{background:var(--muted-foreground,#64748b)}.portion-row{margin:16px 0}.portion-row p{font-size:12px;margin:0 0 5px}.portion-bar{display:flex;overflow:hidden;height:18px;border-radius:4px;background:var(--secondary,#eef2f8)}.portion-app{background:var(--muted-foreground,#64748b)}.portion-auth{background:var(--chart-2,#15803d)}.portion-auth.clerk{background:var(--chart-1,#2563eb)}[hidden]{display:none!important}
"""

C = next(row for row in R['crudBaseline'] if row['registeredUsers'] == 1000000)
crud_table = table(['Registered = active = retained', 'Common app', 'App + Nathan', 'App + Clerk Pro', 'Total cash reduction'], [
    [count(r['registeredUsers']), usd(r['commonAppCostCurrent']), '<strong>' + usd(r['nathanTotalCurrent']) + '</strong><br>' + f'Auth {r["nathanAuthShareCurrentPercent"]:.1f}%',
     '<strong>' + usd(r['clerkTotalCurrent']) + '</strong><br>' + f'Auth {r["clerkAuthShareCurrentPercent"]:.1f}%', f'{r["totalSavingsCurrentPercent"]:.1f}%']
    for r in R['crudBaseline']], 'Monthly CRUD app plus authentication total costs')

crud_assumptions = table(['CRUD input', 'Illustrative baseline', 'Billing interpretation'], [
    ['Usage', '1,000 API requests/active user/month', '50/day on 20 active days; one business API request invokes one Worker.'],
    ['Operation mix', '90% indexed reads/lists; 10% creates/updates/deletes', 'A list scans 20 rows; a mutation reads 2 and bills 3 writes including table/index effects.'],
    ['App CPU', '3 CPU-ms/read; 5 CPU-ms/mutation', 'Whole app-handler budget includes local token verification on both sides; network wait is excluded.'],
    ['App storage', '100 decimal kB/registered user at rest', '50 bounded records × 1 kB × 2 total table/index/metadata overhead; additional growth and business audit storage need another budget.'],
    ['Public static assets', '2,000 requests/active user/month', 'Public SPA shell/JS/CSS/images go directly to Workers Static Assets. No Worker invocation or Workers Caching; private API data remains protected.'],
    ['App diagnostic logs', '1 event/API request, sampled at 1%; 1 kB/event', 'Auth keeps its original 100% log budget. Required security audits are retained separately, not sampled away.'],
    ['Nathan protected-Worker check', '1 same-account service-binding check/API request', 'Additional 2 CPU-ms, 10 row reads, zero writes and 1 diagnostic event sampled at 1%. No second public request fee.'],
    ['Populations', 'Registered = app-active = Clerk-retained in scale table', 'Calculator separates active app use from MRU; storage follows registered accounts.'],
], 'Illustrative CRUD workload assumptions')

crud_breakdown = table(['Meter at 1M users', 'App only → app + Nathan usage', 'App-only bill → combined bill'], [
    ['Workers plan', 'One paid account in either stack', '$5.00 → $5.00'],
    ['Dynamic requests', '1B API → 1.06B API + identity; policy subcalls add no request fee', '$297.00 → $315.00'],
    ['Workers CPU', '3.2B → 5.7B CPU-ms', '$63.40 → $113.40'],
    ['D1 reads', '18.2B → 28.92B rows; one 25B allowance', '$0.00 → $3.92'],
    ['D1 writes', '300M → 620M billed rows; one 50M allowance', '$250.00 → $570.00'],
    ['D1 storage', '100 → 112 GB aggregate; one 5 GB allowance', '$71.25 → $80.25'],
    ['Diagnostic logs', '10M → 80M retained events; current prices', '$0.00 → $36.00'],
    ['Public static assets', '2B direct static requests in either stack', '$0.00 → $0.00'],
    ['Cloudflare cash subtotal', 'All account meters combined', '<strong>$686.65 → $1,123.57</strong>'],
    ['Nathan lifecycle email', '200,000 emails; selected Resend formula', 'Add $155.00 to the Nathan stack'],
], 'CRUD app and combined Nathan account billing at one million users')

crud_sensitivities = table(['App workload at 1M users', 'App + Nathan', 'App + Clerk', 'Auth share: Nathan / Clerk'], [
    [s['label'], usd(s['results'][1]['nathanTotalCurrent']), usd(s['results'][1]['clerkTotalCurrent']),
     f'{s["results"][1]["nathanAuthShareCurrentPercent"]:.1f}% / {s["results"][1]["clerkAuthShareCurrentPercent"]:.1f}%'] for s in [*R['crudScenarios'],*R['crudAuthScenarios']]
], 'CRUD operating cost sensitivities')

CRUD_REPORT = f"""
<section id="crud"><h2>A simple CRUD app: the whole app + auth bill</h2>
<p>Use a read-heavy task or notes app as a concrete example. It serves 1,000 dynamic API requests per active user/month, with 90% reads, 10% mutations and bounded small records. The same Workers/D1 application runs in both alternatives. Nathan also budgets one live policy check on every API request. These are <strong>representative assumptions, not measured “typical” industry usage</strong>.</p>
<p><strong>At 1M active and retained users, the app alone is {usd(C['commonAppCostCurrent'])}/month.</strong> Add Nathan and the cash total is <strong>{usd(C['nathanTotalCurrent'])}</strong>; add Clerk Pro and it is <strong>{usd(C['clerkTotalCurrent'])}</strong>. The total modeled cash reduction is <strong>{C['totalSavingsCurrentPercent']:.1f}%</strong>. Prices are current through November 2026; labor and omitted services are discussed below. {source('workers-pricing')} {source('d1-pricing')} {source('clerk-pricing')} {source('resend-pricing')}</p>
{crud_table}
<figure><div class="legend"><span><i class="dot app" aria-hidden="true"></i>Common app only</span><span><i class="dot nathan" aria-hidden="true"></i>App + Nathan</span><span><i class="dot" aria-hidden="true"></i>App + Clerk Pro</span></div><div class="scroll" tabindex="0" role="region" aria-label="CRUD total cost chart">{chart(crud=True)}</div><figcaption>Published rates × modeled usage. Logarithmic user axis; linear dollar axis starts at zero. Both totals contain app hosting, D1 and diagnostic logs. Nathan includes identity work, policy checks and auth email; Clerk includes its Pro subscription. App and identity storage both require viable database partitioning at large sizes.</figcaption></figure>
<h3>How much of the operating bill is authentication?</h3>
<p>Allocate the common app bill first, then attribute the <em>incremental</em> bill to authentication. At 1M users, Nathan authentication adds <strong>{usd(C['nathanAuthIncrementCurrent'])}/month ({C['nathanAuthShareCurrentPercent']:.1f}% of its total)</strong>; Clerk adds <strong>{usd(C['clerkAuth'])} ({C['clerkAuthShareCurrentPercent']:.1f}% of its total)</strong>.</p>
<div class="portion-row"><p><strong>Nathan:</strong> common app {usd(C['commonAppCostCurrent'])} + auth {usd(C['nathanAuthIncrementCurrent'])} = {usd(C['nathanTotalCurrent'])}</p><div class="portion-bar" role="img" aria-label="Nathan: app 53.7 percent, authentication 46.3 percent"><span class="portion-app" style="width:{100-C['nathanAuthShareCurrentPercent']:.5f}%"></span><span class="portion-auth" style="width:{C['nathanAuthShareCurrentPercent']:.5f}%"></span></div></div>
<div class="portion-row"><p><strong>Clerk:</strong> common app {usd(C['commonAppCostCurrent'])} + auth {usd(C['clerkAuth'])} = {usd(C['clerkTotalCurrent'])}</p><div class="portion-bar" role="img" aria-label="Clerk: app 3.8 percent, authentication 96.2 percent"><span class="portion-app" style="width:{100-C['clerkAuthShareCurrentPercent']:.5f}%"></span><span class="portion-auth clerk" style="width:{C['clerkAuthShareCurrentPercent']:.5f}%"></span></div></div>
<p class="muted">The bars show proportions: each bar is 100% of its own stack’s total, not the same dollar amount. Gray is the common app; color is authentication.</p>
<details><summary>Exact workload and why account allowances cannot be counted twice</summary>
{crud_assumptions}
<pre>Common app = bill(app meters)
Nathan total = bill(app + identity + Nathan policy meters) + auth email
Clerk total = bill(app meters) + Clerk Pro
Nathan auth increment = Nathan total − Common app
Auth share = auth increment ÷ that stack’s total</pre>
<p>Apply one $5 Workers base and one set of request/CPU/D1/log allowances to each alternative’s Cloudflare account. Nathan’s auth share includes the extra bill when identity pushes an app meter over an allowance. Adding the old standalone $483.65 identity estimate to $686.65 app hosting would give $1,170.30 and understate this protected-Worker scenario. The correct combined figure is $1,278.57. Incremental attribution is a budgeting convention; another cost-center allocation can change the percentages without changing the invoice total.</p>
<p>The same-account app-policy subcall adds CPU, row reads and logs, <strong>no additional request fee</strong>. A gateway wrapper must count the public request once with combined CPU. An HTTP/cross-account implementation or additional session writes requires different inputs. The earlier identity-only gateway scenarios are never added on top of these already-counted CRUD API requests. {source('workers-pricing')} {source('service-bindings')}</p>
<p>The app CPU budget includes local token validation for both providers. Nathan’s extra live policy path is projected engineering work for Worker authorization; it is not proof of the agreed 60-second revocation guarantee. Clerk’s local-token path alone does not establish equivalent live group/deprovisioning behavior; any additional equivalent controls need implementation and cost evaluation. Feature parity is unverified.</p>
</details>
<details><summary>Worked 1M-user app + auth bill, line by line</summary>
<p>900M reads + 100M mutations create 18.2B app row reads and 300M billed writes. One billion Nathan policy checks add 2B CPU-ms and 10B reads. The original identity example adds 60M dynamic requests, 500M CPU-ms, 720M reads and 320M writes. All are assumptions.</p>
{crud_breakdown}
<p>Combined Cloudflare $1,123.57 + auth email $155 = $1,278.57. Subtract app-only $686.65 to attribute $591.92 to Nathan auth. Clerk’s equivalent cash sum is app-only $686.65 + Pro $17,225 = $17,911.65. This leaves <strong>$16,633.08/month</strong> before incremental labor/tooling/development, or about <strong>166.3 additional operator hours at $100/hour</strong>. At 51K users the $21.07 gap covers only about 12.6 minutes.</p>
<p>From December 1, with the same usage and announced log prices, the combined model becomes <strong>{usd(C['nathanTotalDecember'])} for app + Nathan</strong> and <strong>{usd(C['clerkTotalDecember'])} for app + Clerk</strong>. App + Nathan emits 80 GB/month of assumed logs, with 18.67 GB-month retained; the new log bill is about $8.37 instead of $36. {source('observability-pricing')}</p>
</details>
<details><summary>Lighter, busier and write-heavy CRUD apps change the proportions</summary>
{crud_sensitivities}
<p>A busier app raises hosting spend on both sides and lowers authentication’s share even if Clerk’s fee is unchanged. A write-heavy app can make business data the largest cost. Full diagnostic logging increases both stacks. None of these cases change vendor prices or prove capacity. Use your actual API traffic, billed rows and retained population rather than treating 1,000 requests as universal.</p>
<p>The adverse refresh case also survives the full-app comparison: 1,920 refreshes/user/month makes <strong>app + Nathan $22,216.57</strong> at 1M users, above app + Clerk’s $17,911.65. Including app hosting does not remove the need to measure session behavior and billed identity writes.</p>
<p>App activity and Clerk MRU are independent inputs. A signup-only visitor can consume CRUD resources without becoming an MRU; a dormant account retains app and identity storage. The calculator lets you separate them.</p>
</details>
<p><strong>Scope of “operating cost”:</strong> these are recurring platform cash totals for the specified small-record CRUD app plus authentication. File uploads/R2, background jobs, real-time features, app notification mail, domain fees, independent backup, external monitoring/support and development/operator labor are additional costs. The calculator can add common app costs equally and incremental Nathan effort separately.</p>
<p><strong>Capacity remains a separate question.</strong> At 1M stored accounts the app footprint is 100 GB, requiring at least ten D1 databases before headroom in either stack; Nathan adds 12 GB of auth data requiring at least two more. At 5M the modeled aggregate is 560 GB with Nathan, below the published 1 TB account storage limit but still requiring partitioning and viable query throughput. This cost model implements no such architecture and adds no 1M+ test requirement. {source('d1-limits')}</p>
</section>
"""

CALCULATOR = """
<section class="calculator" id="calculator"><h2>Try your own workload</h2>
<p>Choose app + auth or identity-only costs, then change traffic and incremental operator effort. Rates stay fixed to the captured price sheet; every usage input remains a projection.</p>
<div class="controls">
<label class="field">Comparison scope<select id="calc-scope"><option value="crud">CRUD app + authentication</option><option value="identity">Identity only</option></select></label>
<label class="field">Registered users<input id="calc-users" type="number" required min="0" max="100000000" step="1" value="1000000"></label>
<label class="field">Monthly retained share (%)<input id="calc-retained" type="number" required min="0" max="100" step="0.1" value="100"></label>
<label class="field">Authentication workload preset<select id="calc-preset">PRESET_OPTIONS</select></label>
<label class="field">Refresh exchanges per retained user/month<input id="calc-refresh" type="number" required min="0" max="100000" step="1" value="20"></label>
<label class="field">Auth emails per retained user/month<input id="calc-email" type="number" required min="0" max="100" step="0.01" value="0.2"></label>
<label class="field">Protected requests per retained user/month<input id="calc-protected" type="number" required min="0" max="1000000" step="1" value="0"></label>
<label class="field">Gateway diagnostic-log sampling (%)<input id="calc-sampling" type="number" required min="0" max="100" step="0.1" value="100"></label>
<label class="field">Billed database-write multiplier<input id="calc-writes" type="number" required min="0.1" max="100" step="0.1" value="1"></label>
<label class="field">Incremental operator hours/month<input id="calc-hours" type="number" required min="0" max="10000" step="0.1" value="0"></label>
<label class="field">Operator cost per hour (USD)<input id="calc-hourly" type="number" required min="0" max="10000" step="0.01" value="100"></label>
<label class="field">Other incremental Nathan costs (USD/month)<input id="calc-other" type="number" required min="0" max="1000000" step="0.01" value="0"></label>
<label class="field">Logging prices<select id="calc-period"><option value="current">Current, through November 2026</option><option value="december">Announced, from December 2026</option></select></label>
</div>
<details id="crud-controls"><summary>CRUD app workload and common costs</summary><p>The protected-Worker example includes one service-bound Nathan policy check/API request: 2 extra CPU-ms, 10 row reads and no writes. Static public assets use the documented free direct-serving path. All values are illustrative.</p><div class="controls">
<label class="field">CRUD workload preset<select id="crud-preset">CRUD_OPTIONS</select></label>
<label class="field">Active app users (% of registered)<input id="crud-active" type="number" required min="0" max="100" step="0.1" value="100"></label>
<label class="field">API requests per active user/month<input id="crud-requests" type="number" required min="0" max="1000000" step="1" value="1000"></label>
<label class="field">Read/list requests (%)<input id="crud-read" type="number" required min="0" max="100" step="0.1" value="90"></label>
<label class="field">CPU-ms per read/list<input id="crud-cpu-read" type="number" required min="0" max="10000" step="0.1" value="3"></label>
<label class="field">CPU-ms per mutation<input id="crud-cpu-mutation" type="number" required min="0" max="10000" step="0.1" value="5"></label>
<label class="field">Scanned rows per read/list<input id="crud-rows-read" type="number" required min="0" max="10000000" step="1" value="20"></label>
<label class="field">Scanned rows per mutation<input id="crud-rows-mutation" type="number" required min="0" max="10000000" step="1" value="2"></label>
<label class="field">Billed writes per mutation<input id="crud-writes" type="number" required min="0" max="10000" step="0.1" value="3"></label>
<label class="field">App storage per registered user (decimal kB)<input id="crud-storage" type="number" required min="0" max="1000000" step="0.1" value="100"></label>
<label class="field">App diagnostic-log sampling (%)<input id="crud-logs" type="number" required min="0" max="100" step="0.1" value="1"></label>
<label class="field">Nathan policy diagnostic sampling (%)<input id="crud-policy-logs" type="number" required min="0" max="100" step="0.1" value="1"></label>
<label class="field">Other common app costs (USD/month)<input id="crud-common" type="number" required min="0" max="10000000" step="0.01" value="0"></label>
</div></details>
<div class="output" id="calc-output" aria-live="polite" aria-atomic="true"><p><strong>Default app + auth: Nathan $1,278.57/month; Clerk $17,911.65/month.</strong></p><p>App-only common baseline $686.65. Excludes incremental labor and other costs until you enter them.</p></div>
<p class="muted">The calculator preserves Nathan security requirements. Sampling here applies to diagnostic gateway logs; complete security audits, revocation and required MFA still need their own correct storage and enforcement. Changing price scenarios does not establish capacity.</p></section>
""".replace('PRESET_OPTIONS', ''.join(f'<option value="{escape(s["id"])}"' + (' selected' if s['id'] == 'baseline' else '') + '>' + escape(s['label']) + '</option>' for s in I['scenarios'])).replace('CRUD_OPTIONS', ''.join(f'<option value="{escape(s["id"])}"' + (' selected' if s['id'] == 'baseline' else '') + '>' + escape(s['label']) + '</option>' for s in I['crud']['scenarios']))

BODY = f"""
<h1>Nathan on your own Cloudflare account vs Clerk</h1>
<p class="meta">Cost and ownership report · 28 October 2026 prices · USD, before tax · <a href="https://tasks.gmac.io/gmacko/issue/NATH-2">NATH-2</a> · CRUD extension <a href="https://tasks.gmac.io/gmacko/issue/NATH-3">NATH-3</a></p>
<span class="badge">Published prices verified</span><span class="badge">Usage and costs modeled</span><span class="badge">1M+ capacity unverified</span>
<p><strong>Include the application to see where authentication sits in the operating budget.</strong> For the illustrative read-heavy CRUD app at 1M active and retained users, app + Nathan is <strong>$1,278.57/month</strong>, versus <strong>$17,911.65 with Clerk Pro</strong>. Authentication accounts for <strong>46.3% versus 96.2%</strong> of these modeled totals. Common app hosting is $686.65; account allowances apply once. Incremental operator time and implementation costs are additional.</p>
<p><strong>Nathan can materially reduce the recurring authentication bill as retained usage grows.</strong> Cloudflare charges for small units of compute, requests and database work instead of each retained identity. In the moderate example below, one million monthly retained users cost an estimated <strong>$328.65/month on Cloudflare, or $483.65 including authentication email</strong>, compared with <strong>$17,225/month for Clerk Pro</strong> at published monthly rates. That is a modeled cash reduction of <strong>97.2%, or $16,741/month</strong>, before operator time and implementation costs. Annualizing unchanged prices and usage gives $200,896; this is not a twelve-month invoice forecast.</p>
<p>The identity-only advantage is much smaller near 50,000 users: Clerk Pro and that Nathan example both cost $25/month. The app + auth totals differ because shared allowances and per-request policy work change the bill. Clerk’s free plan is cheaper for basic authentication within its limits. The economic case for Nathan is strongest when many users return, the workload is efficient and the operator can maintain a security-sensitive identity service.</p>
<div class="callout"><strong>Evidence boundary:</strong> the prices below come from 12 captured official sources. Nathan consumption inputs are explicit engineering assumptions, not invoice data or a benchmark. Projections to 1M–5M users do not add a scale-test requirement to the launch plan. The confirmed launch population remains 51,000 users; large-scale capacity, partitioning and reliability remain unverified.</div>
<nav class="toc" aria-label="Report sections"><a href="#crud">CRUD app + auth totals</a><a href="#comparison">Identity-only costs</a><a href="#mechanics">Why Cloudflare is inexpensive</a><a href="#worked">Worked 1M identity example</a><a href="#sensitivity">What changes the result</a><a href="#ownership">Ownership and break-even</a><a href="#calculator">Calculator</a><a href="#sources">Sources and reproduction</a></nav>

{CRUD_REPORT}

<section id="comparison"><h2>Identity-only costs through 5 million users</h2>
<p>Compare one logical identity application with Clerk Pro, monthly billing, and no optional Clerk add-ons. Every registered account is assumed monthly retained in this table. Nathan uses Workers Standard, D1, diagnostic logs and paid Resend delivery. Application hosting and incremental labor are excluded on both sides.</p>
{baseline}
<figure><div class="legend"><span><i class="dot" aria-hidden="true"></i>Clerk Pro</span><span><i class="dot nathan" aria-hidden="true"></i>Nathan Cloudflare + email</span></div><div class="scroll" tabindex="0" role="region" aria-label="Scrollable cost projection chart">{chart()}</div><figcaption>Published rates × modeled steady-state usage. The horizontal scale is logarithmic; the dollar scale starts at zero. Nathan’s smaller line is nonzero: use the table for exact amounts. Sources: Clerk, Workers, D1 and Resend. {source('clerk-pricing')} {source('workers-pricing')} {source('d1-pricing')} {source('resend-pricing')}</figcaption></figure>
<p><strong>Why the supplied chart needed more detail:</strong> Clerk Pro starts at $25/month even below its 50,000-MRU allowance. At 51,000 retained users, the bill is $45; at 1M it is $17,225. A near-flat Nathan line must be supported by traffic, CPU, write, logging and email assumptions; it cannot mean free infrastructure or guaranteed capacity.</p></section>

<details><summary>Clerk’s actual billing unit and the fair comparison</summary>
<p>Clerk counts <strong>monthly retained users (MRUs)</strong>: users who return in a given month at least 24 hours after signup. A million stored accounts is not automatically a million billable MRUs. One-time users who never return after that first day do not create MRU overage, while their requests and email can still consume Nathan resources. {source('clerk-pricing')}</p>
<p>Clerk Hobby is free up to 50,000 MRUs per app. Pro is $25/month or $20/month billed annually. Pro includes the MFA, passkeys and one upstream enterprise SSO connection relevant to Nathan’s intended launch scope. The comparison uses Pro for those features, while showing why Hobby can win for a smaller basic-auth use case.</p>
<pre>Clerk Pro/month = $25
 + max(0, min(MRU, 100,000) − 50,000) × $0.020
 + max(0, min(MRU, 1,000,000) − 100,000) × $0.018
 + max(0, min(MRU, 10,000,000) − 1,000,000) × $0.015
 + max(0, MRU − 10,000,000) × $0.012</pre>
<p>The volume bands are applied incrementally. Annual billing lowers the base by $5/month, not the modeled usage overage. Enterprise quotes and committed-use discounts can reduce the comparison price and should replace list rates when available.</p>
<p>No separate authentication-email delivery bill is added for Clerk’s managed auth features in this comparison. Marketing mail, business notifications, SMS and unrelated application hosting are excluded from both sides. Nathan’s selected Resend expense covers the modeled authentication lifecycle mail.</p>
<p><strong>Apps and SSO connections are different.</strong> Clerk plans include unlimited applications and 50,000 MRUs per app. Nathan’s 500 planned downstream OIDC clients are not 500 upstream enterprise SSO connections. Do not multiply Clerk’s base price by 500, or add $75 for each Nathan-connected app. Clerk’s additional upstream SSO bands are $75/connection for connections 2–15 and $60 for 16–100; 101+ requires a quote. None are added to the headline comparison. Nathan’s local app groups are also not automatically equivalent to Clerk Organizations; an Organizations/B2B add-on needs its own feature comparison. {source('clerk-pricing')}</p>
<p>Nathan is intended to issue downstream OIDC tokens, protect private Workers and manage local grants. A complete Clerk replacement evaluation must verify the same required app journeys and app-side integration. This report compares the recurring economic model; it does not establish feature parity or production readiness.</p>
</details>

<section id="mechanics"><h2>How Cloudflare keeps the infrastructure bill small</h2>
<div class="flow" aria-label="Nathan billing flow"><span>Identity requests<br><strong>Workers CPU + requests</strong></span><b aria-hidden="true">→</b><span>Indexed identity state<br><strong>D1 rows + storage</strong></span><b aria-hidden="true">→</b><span>Lifecycle delivery<br><strong>Email + logs</strong></span></div>
<p><strong>There is no infrastructure line item for a retained user.</strong> Storing an extra identity adds bytes. Its sign-ins add small requests, active CPU and indexed database work. If that person does not return, their stored identity does not incur an active-user subscription fee. This changes the growth curve, although actual traffic still costs money.</p>
<p><strong>Workers share a lightweight runtime.</strong> Cloudflare uses V8 isolates within existing runtime processes rather than reserving a dedicated virtual machine for every Nathan deployment. The operator does not provision an always-on IdP web server or a database instance with a fixed capacity charge. D1 scales its query billing to zero when no queries run; the Workers paid account still has its $5 monthly minimum. {source('workers-runtime')} {source('workers-pricing')} {source('d1-pricing')}</p>
<p><strong>Active CPU is the expensive part of execution; waiting is not billed as duration.</strong> Waiting for Google, GitHub, Entra or D1 does not itself accumulate Workers CPU-ms. Signature verification, password hashing and JSON processing do. The model budgets whole sign-in CPU explicitly; a slow password hash or heavy plugin can exceed that budget. Workers Standard has no separate request-duration or bandwidth charge. {source('workers-pricing')}</p>
<p><strong>One paid account unlocks substantial included usage.</strong> Nathan’s IdP, gateway and databases share the account’s allowances; they do not each earn a new free allocation. Workers Paid is distinct from Cloudflare’s website Pro/Business plans. This model does not require buying a website-plan upgrade just to access Workers Standard pricing. {source('workers-pricing')}</p>
{rates}
<p><strong>Indexed reads are inexpensive, while writes deserve attention.</strong> D1 includes 25 billion scanned rows/month on Paid, but only 50 million billed writes. Reads are charged by rows scanned, not rows returned. Inserts, updates, deletes and index maintenance add writes. A full-table scan or unnecessary session/rate-limit update changes consumption; the identity’s existence is not the billing event. {source('d1-pricing')}</p>
<p><strong>Service bindings avoid double request fees.</strong> In Workers Standard, a same-account call from one Worker to another through a Service Binding adds no extra request fee; Cloudflare bills the initial request and combined CPU. Database and log usage still count. Public HTTP calls, cross-account routing and optional Workers Caching need their actual billing treatment checked. The identity-only gateway sensitivities count Nathan overhead; the CRUD model explicitly adds both business-app compute and Nathan policy overhead. {source('workers-pricing')} {source('service-bindings')}</p>
<p>Worker static assets can be served without dynamic invocation charges in the documented asset-serving configuration; routing those requests through gateway code is a different path. No savings here depend on skipping required policy checks, weakening MFA or extending the confirmed 60-second Worker revocation deadline.</p></section>

<details><summary>Why 50,000 users can need paid infrastructure while still costing very little</summary>
<p>The Free plan has daily ceilings, not a 50,000-identity entitlement: 100,000 Worker requests/day and 10 CPU-ms/invocation; D1 allows 5M read rows/day and 100,000 written rows/day. In the 51,000-user example, 3.06M dynamic requests/month average 102,000/day, and 16.32M billed writes average 544,000/day. Either can exceed Free, and bursts or password hashing can reach a limit earlier. Treat Free as a prototype budget, not a launch guarantee. {source('workers-pricing')} {source('d1-pricing')}</p>
<p>Moving to Workers Paid starts at <strong>$5/account/month</strong>. The same 3.06M requests, 25.5M CPU-ms, 16.32M writes, 36.72M reads and 0.612 GB of modeled state fit the Paid included allowances. That is why crossing Free limits does not automatically mean a large hosting bill.</p>
<p>Lifecycle mail is separate: 10,200 emails/month in this scenario uses the selected $20 Resend Pro plan. Resend Free allows 3,000/month and only 100/day. The report deliberately uses paid email whenever nonzero mail is modeled, so it does not rely on daily burst assumptions. With no mail, or a verified existing mail allocation, that $20 can change. {source('resend-pricing')}</p>
<p>The exact source currently has database-backed rate limiting in <code>src/auth/instance.ts:49</code>, D1-backed gateway sessions in <code>src/gateway/worker.ts:67–85</code>, Resend delivery in <code>src/auth/email.ts:3</code> and enabled observability in both Wrangler configurations. These establish billable categories, not measured per-user quantities.</p>
<p>KV, Queues, Durable Objects and independent backup/SIEM services are not automatically charged just because Nathan runs on Cloudflare; add their meters if the implementation uses them. The inspected Durable Object directory binding is staging functionality, and launch directory sync is deferred. No Clerk directory-sync surcharge is added either.</p>
</details>

<section id="worked"><h2>Worked identity-only example: 1 million retained users</h2>
<p>The moderate example produces 4M sign-ins, 20M refresh exchanges and 60M dynamic identity requests per month. Its 500M CPU-ms average about 8.3 CPU-ms/request. D1 performs 720M modeled row reads and 320M billed writes. Storage is 12 GB; lifecycle email is 200,000 messages.</p>
{breakdown}
<p><strong>Most of the Cloudflare subtotal is writes, not hosting compute.</strong> D1 writes are $270 of $328.65. The Workers plan, requests and CPU together are $29.40. This is the mechanism behind the potential savings: millions of identities can be represented by modest storage and inexpensive active work, while Clerk’s MRU meter continues to charge for returning identities.</p>
<p>Clerk’s $17,225 minus Nathan’s modeled $483.65 leaves <strong>$16,741.35/month</strong> for incremental operation, security maintenance, external tooling and implementation amortization before cash costs reach parity. That is a budget, not a claim that self-hosting is effortless.</p>
<details><summary>All baseline workload assumptions</summary>{assumptions}<p>These are steady-state assumptions. They exclude a mass import/signup wave, one-time invitations, SMS, directory sync, unrelated application data and unbounded audit retention. Billed rows include the assumed index/cleanup/rate-limit effects; a SQL query count cannot validate them. The reproducible JSON records every input.</p></details>
</section>

<section id="sensitivity"><h2>Identity-only costs: what can widen or erase the savings</h2>
<p>The table below changes workload, not vendor prices. The moderate example is one operating profile, not a forecast for every installation. Current October 2026 logging rates and the same conservative email plan apply throughout.</p>
{sensitivities}
<p><strong>Short-token refresh is the most important adverse case.</strong> A five-minute token refreshed during one hour/day over 20 days implies roughly 240 exchanges/user/month, costing $2,903.65 at 1M users in this model. Eight hours/day implies 1,920 exchanges and <strong>$21,397.37/month</strong>, exceeding the $17,225 Clerk Pro comparison. That calculation also creates 19.32B billed writes and would need a viable high-throughput database design. The same eight-hour pattern costs about $1,044.88 at 51,000 users, versus Clerk’s $45.</p>
<p>The moderate 20-refresh assumption is therefore a <strong>usage condition</strong>. Before making a savings promise, establish session duration, refresh behavior, active-client hours and billed writes/exchange. Reducing redundant writes or unnecessary refreshes may help; required MFA, token validation and revocation guarantees must remain intact. This report does not recommend extending token lifetimes to make the cost chart look better.</p>
<p><strong>Gateway traffic is a broader service than identity-only OIDC.</strong> Adding 1,000 protected requests/retained user/month means 1B extra requests at 1M users. With assumed two diagnostic events/request, full gateway logging lifts the Nathan estimate to $2,023.65. Sampling gateway diagnostics to 1%, while retaining required security audits, gives $835.65. Actual service-chain event counts and payload bytes must be measured. Clerk SDK/local JWT checks should not be treated as a billable Clerk API call for every app request.</p>
<p><strong>Peak traffic is not monthly traffic.</strong> The provisional 5,000 protected requests/second launch test is a peak acceptance scenario. Holding it continuously for 30 days produces 12.96B protected requests. At 51,000 identities, the separate 1%-diagnostic-log example costs about $4,679/month including mail. User count alone cannot price a gateway. This is arithmetic, not a throughput test.</p>
</section>

<details><summary>Registered accounts, retention, acquisition and email economics</summary>
<p>Hold one million registered accounts and their modeled 12 GB of storage fixed, then vary the monthly retained population:</p>
{retention}
<p>At 50,000 retained users, Clerk Pro is $25 while Nathan’s stored million-account population makes its model $30.25. Low retained usage can make Clerk the cheaper cash choice. A viral wave of non-returning signups is excluded from Clerk MRU billing but can still generate Nathan requests, account writes and verification emails. Add that acquisition workload separately.</p>
<p>The 0.2-email baseline suits an illustrative social/passkey/password/TOTP mix with occasional lifecycle messages. Four email-OTP logins/user/month create 4M emails at 1M retained users; the conservative selected Resend Pro+overage formula costs $3,575 for email, or $3,903.65 for Nathan including infrastructure. The current Nathan launch plan does not require email OTP; this is an optional sensitivity, not an implemented feature claim.</p>
<p>Resend publishes larger-volume plans and rates as well. The model retains the simple $20/50K + $0.90/1K formula throughout to make the comparison conservative and reproducible; choosing a lower eligible volume-plan total may reduce these email estimates. At 1M emails/month the captured Scale plan is $650, below the selected formula’s $875. Mail bursts, sending-rate approval, deliverability and a verified sender remain operational requirements. {source('resend-pricing')}</p>
<p>Bulk onboarding also has a one-time cost: one message for each of 51,000 users exceeds the selected 50K allowance by 1K, giving a $20.90 send-month estimate if no other email is sent. It must not be silently folded into the steady-state lifecycle assumption. SMS and upstream Microsoft/other IdP licensing, if required, need separate bills.</p>
</details>

<details><summary>Logging changes on December 1, 2026; account sharing and backups</summary>
<p>Cloudflare has announced new unified Observability prices effective <strong>December 1, 2026</strong>. Paid includes 50 GB ingestion and 10 GB-month stored data, then $0.25/GB ingested and $0.10/GB-month stored. The report’s primary table uses prices in force on October 28; it does not mix the two periods. {source('observability-pricing')}</p>
<p>At 1M users, 60M assumed 1 kB log events mean 60 GB ingestion and a steady seven-day retained footprint of 14 GB-month. New log charges would be $2.50 ingestion + $0.40 storage = $2.90, versus $24 currently. Nathan’s example becomes <strong>$462.55/month including mail</strong> from December, holding everything else fixed. Real enriched event bytes, traces and retention can change that amount. The calculator supports both periods.</p>
<p>Head sampling defaults to 100% when unspecified; current Nathan Wrangler configs enable observability without lowering it. Diagnostic sampling can reduce volume, but security audit and incident evidence policies need an explicit, complete design. Never log credentials, tokens or passwords to save engineering work. {source('workers-logs')}</p>
<p>All Cloudflare allowances are shared at account level. If another application has already consumed every inclusion, the 1M-user workload’s modeled incremental usage plus email is <strong>$548.72/month</strong>, excluding a new $5 base already paid by that account. The usual fresh-account total is $483.65. Do not give every Worker or database another copy of the allowance.</p>
<p>Paid D1 has 30 days of Time Travel recovery; that is useful built-in recovery, not a cross-account disaster-recovery plan. Optional R2 Standard storage is $0.015/GB-month with 10 GB included; its operations and storage use rounded billing units. Seven uncompressed 12 GB snapshots would average 84 GB if retained continuously, or about <strong>$1.11/month in R2 storage after its free 10 GB</strong>, before export work and operations. This is a storage example only: Nathan’s snapshot/export automation is not validated, and an independent backup must protect against loss of the Cloudflare account. {source('d1-limits')} {source('d1-time-travel')} {source('r2-pricing')}</p>
</details>

<section id="ownership"><h2>The total cost includes owning an identity provider</h2>
<p>Clerk’s subscription buys a managed authentication product, hosted UI/SDK integration, delivery/operations work, maintained protections and a support path. Nathan’s operator owns configuration, upgrades, recovery, credential rotation, monitoring and incident response. Cloudflare runs the underlying compute/storage; it does not take over responsibility for Nathan’s identity logic.</p>
<p>The assessed Nathan source is MIT-licensed at <code>90ebc43f6d19cf69049646a19a6f96f74de6975a</code>, so this model includes no software license fee. Future paid support or hosted offerings are separate commercial decisions. Nathan remains pre-public-beta in the launch plan; mandatory MFA, shared app-policy enforcement and end-to-end release gates are not yet verified. A low infrastructure estimate does not make the implementation ready to replace a production provider.</p>
<pre>Nathan ownership cost/month
 = Cloudflare + transactional delivery + external tooling
 + incremental operator hours × loaded hourly rate
 + amortized implementation, migration and independent review

Break-even incremental hours
 = (Clerk quote − Nathan cash − other monthly/amortized costs)
   ÷ loaded hourly rate</pre>
{table(['At 1M retained users', 'Incremental labor at $100/hour', 'Nathan total/month'], [[str(int(row['incrementalLabor']/100)) + ' hours', usd(row['incrementalLabor']), usd(row['ownershipTotal'])] for row in R['laborAtOneMillion']], 'Incremental labor sensitivity')}
<p>In the standalone identity-only 1M-user model, break-even is about <strong>167 incremental hours/month at $100/hour</strong>, before other omitted costs. At 51,000 MRUs the identity-only $20 cash difference pays for only <strong>12 minutes/month</strong> at the same rate. The CRUD totals have their own break-even calculation above and in the calculator. These are budgeting sensitivities; no claim is made that either effort level is sufficient. Include the one-time cost of building Nathan to release quality, then amortize it over the intended operating period.</p>
<p>Do not claim equivalent compliance or guarantees from a Cloudflare account alone. Clerk’s published Business/Enterprise plans add items such as audit features, compliance documentation and contractual support/SLA options. Required enterprise assurances need an actual quote and an equivalent Nathan operating design. Base Pro list pricing is deliberately the comparison floor here. {source('clerk-pricing')}</p>
</section>

<details><summary>Cost projections do not prove a 1M-user architecture</summary>
<p>D1 has a <strong>10 GB maximum per database</strong>, which cannot be raised, and a published 1 TB aggregate account storage limit. The modeled 12 GB at 1M users requires at least two databases even under ideal packing; 24 GB at 2M needs at least three, and 60 GB at 5M needs six, all before headroom. The inspected Nathan auth configuration binds one auth database. Partitioned identity/session/audit storage is an engineering requirement for these projected footprints, not a feature already implemented. {source('d1-limits')}</p>
<p>Each D1 database is inherently single-threaded. Cloudflare’s guidance relates throughput to query duration; a low per-row price is not a promise of unlimited concurrent queries. Read replication can help suitable reads without extra replica charges, but policy freshness and the confirmed 60-second Worker revocation bound constrain consistency and caching choices. More databases, backups and queueing also add development and operational effort. {source('d1-limits')} {source('d1-pricing')}</p>
<p>High refresh rates can need substantial write throughput even when the dollar formula is affordable. At a later scale milestone, use the real usage bill, storage growth, query durations, D1 row metrics and observed errors to select the architecture. This report adds no 1M-user load test to the agreed launch acceptance scope.</p>
<p>For bot defense, Turnstile’s Free plan includes unlimited challenges, subject to widget/hostname limits; enterprise functionality is quoted. That can reduce one defensive service bill, but is not full feature parity with Clerk Protect, a WAF subscription or a complete abuse-control design. Nathan must still bound CPU, rate-limit expensive routes and guard mail/DB writes against denial-of-wallet attacks. {source('turnstile-pricing')}</p>
</details>

{CALCULATOR}

<section><h2>Recommended public claim</h2>
<div class="recommendation"><p>“Nathan runs in your own Cloudflare account, so your authentication infrastructure bill follows compute, database activity and storage rather than a fee for every retained user. Using published October 2026 prices, the moderate example projects about $484/month including email for 1 million monthly retained users, compared with $17,225/month for Clerk Pro at list rates. Actual cost depends on sessions, refreshes, email, logs and operator effort; the 1M-user figure is a projection, not tested capacity.”</p></div>
<p>For a whole-app comparison, add: “With the illustrative read-heavy Workers/D1 CRUD workload, app + Nathan projects $1,279/month versus $17,912 with Clerk Pro at 1M active and retained users. Authentication is about 46% versus 96% of those cash totals. Both include the same app; development and incremental operations are extra.” Publish the detailed assumptions alongside either claim.</p>
<p>For a team with many retained users and the skills to operate Nathan, that is a credible reason to evaluate self-hosting. For low retained usage, short-token heavy sessions, limited operational capacity or a requirement for immediate managed support/compliance, Clerk can be the better economic choice. Publish the workload with the number, keep the source date, and update the report when rates or implementation change.</p>
</section>

<details id="sources"><summary>Sources, artifacts and how to reproduce the report</summary>
<p><strong>Data classification:</strong> vendor prices and limits are sourced facts; Nathan workload rates, storage, log volume and operator hours are assumptions; every dollar comparison is a calculation. No Nathan deployment invoice, usage trace, 1M+ benchmark, current CI result or live Clerk quote was supplied or generated.</p>
{source_list}
<p><strong>Repository evidence:</strong> <a href="https://github.com/gmackie/nathan/blob/90ebc43f6d19cf69049646a19a6f96f74de6975a/LICENSE">MIT license</a>; <a href="https://github.com/gmackie/nathan/blob/90ebc43f6d19cf69049646a19a6f96f74de6975a/src/auth/instance.ts#L49">database rate limiting</a>; <a href="https://github.com/gmackie/nathan/blob/90ebc43f6d19cf69049646a19a6f96f74de6975a/src/auth/email.ts#L3">Resend adapter</a>; <a href="https://github.com/gmackie/nathan/blob/90ebc43f6d19cf69049646a19a6f96f74de6975a/src/gateway/worker.ts#L67">gateway sessions</a>; <a href="https://github.com/gmackie/nathan/blob/90ebc43f6d19cf69049646a19a6f96f74de6975a/wrangler.auth.jsonc">auth observability/D1 config</a>; <a href="https://github.com/gmackie/nathan/blob/90ebc43f6d19cf69049646a19a6f96f74de6975a/wrangler.gateway.jsonc">gateway config</a>. Source establishes categories, not per-user unit counts.</p>
<p>Files: <code>model-inputs.json</code> (rates/assumptions), <code>source-ledger.json</code> and <code>sources/</code> (dated snapshots and hashes), <code>model-results.json</code>, <code>baseline-costs.csv</code>, <code>sensitivity-costs.csv</code>, <code>crud-total-costs.csv</code>, <code>crud-sensitivity-costs.csv</code>; figures <code>cost-at-scale.png/svg</code>, <code>one-million-breakdown.png/svg</code>, <code>crud-total-cost-at-scale.png/svg</code> and <code>crud-cost-composition.png/svg</code>; <code>report.html</code> (interactive), <code>report-static.html</code> (script-free/printable) and the report bundle ZIP.</p>
<pre>cd plans/reports/nathan-vs-clerk-2026-10-28
python3 cost_model.py
node verify_model.mjs
uv run --with matplotlib==3.10.7 python make_charts.py
python3 build_report.py</pre>
<p>The arithmetic is offline and standard-library-only. Python Decimal and the browser JavaScript implementation agree across 101 cases: 57 identity-only and 44 CRUD/shared-account cases, including zero activity, allowance boundaries, fractional populations, common costs and adverse refreshes. Independent checks reproduce Cloudflare’s published $8 and $45.40 Worker examples, verify Clerk band boundaries and reconcile the 1M CRUD line items. Figures use saved results rather than hand-entered points. Refreshing source snapshots requires internet and a deliberate review/update of the price inputs; scraping does not silently rewrite the rate sheet.</p>
<p>Currency is USD, before tax, in a 30-day model month. Display totals are rounded to cents; tiny invoice-rounding differences are possible. The email formula explicitly rounds excess mail into 1,000-message buckets. The optional R2 example respects its separate rounded storage units. Enterprise contracts, regional product choices, unrelated account consumption and future prices can differ.</p>
</details>
<p class="meta">Prepared for Nathan launch planning. Pricing captured 2026-10-28; refresh before public use. Planning/report artifacts only; no deployment or public publication performed.</p>
"""

JS = (ROOT / 'calculator.mjs').read_text().replace('export function createCostModel', 'function createCostModel') + '\n'
JS += 'const INPUTS = ' + json.dumps(I) + ';\nconst MODEL = createCostModel(INPUTS);\n'
JS += r"""
const fields = {scope:'calc-scope',users:'calc-users', retained:'calc-retained', preset:'calc-preset', refresh:'calc-refresh', email:'calc-email', protected:'calc-protected', sampling:'calc-sampling', writes:'calc-writes', hours:'calc-hours', hourly:'calc-hourly', other:'calc-other', period:'calc-period'};
const crudFields = [
  ['crud-active','activeFraction',0.01],['crud-requests','requestsPerActiveUser',1],['crud-read','readFraction',0.01],
  ['crud-cpu-read','cpuMsPerRead',1],['crud-cpu-mutation','cpuMsPerMutation',1],['crud-rows-read','readRowsPerRead',1],
  ['crud-rows-mutation','readRowsPerMutation',1],['crud-writes','writtenRowsPerMutation',1],['crud-storage','bytesPerRegisteredUser',1000],
  ['crud-logs','logFraction',0.01],['crud-policy-logs','policyLogFraction',0.01],['crud-common','commonMonthlyCosts',1]
];
const el = key => document.getElementById(fields[key]);
const usd = value => new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(value);
const num = value => new Intl.NumberFormat('en-US',{maximumFractionDigits:0}).format(value);
function applyAuthPreset() {
  const s=INPUTS.scenarios.find(s=>s.id===el('preset').value);
  const a={...INPUTS.assumptions,...s.overrides};
  for(const [field,key] of [['refresh','refreshesPerRetainedUser'],['email','emailsPerRetainedUser'],['protected','protectedRequestsPerRetainedUser'],['writes','writeMultiplier']])el(field).value=a[key];
  el('sampling').value=a.protectedLogFraction*100;
}
function recompute() {
  const appMode=el('scope').value==='crud';
  document.getElementById('crud-controls').hidden=!appMode;
  for(const k of ['protected','sampling'])el(k).closest('label').hidden=appMode;
  for(const option of el('preset').options)option.disabled=appMode&&option.value.startsWith('gateway-');
  if(appMode&&el('preset').value.startsWith('gateway-')) {el('preset').value='baseline';applyAuthPreset();}
  if ([...Object.values(fields),...crudFields.map(([id])=>id)].some(id => {const node=document.getElementById(id); return !node.closest('[hidden]') && node.type==='number' && !node.checkValidity();})) {
    document.getElementById('calc-output').textContent='Enter values within the labeled input ranges.'; return;
  }
  const scenario = INPUTS.scenarios.find(s => s.id === el('preset').value);
  const overrides = {...scenario.overrides,retainedFraction:Number(el('retained').value)/100,refreshesPerRetainedUser:Number(el('refresh').value),emailsPerRetainedUser:Number(el('email').value),protectedRequestsPerRetainedUser:Number(el('protected').value),protectedLogFraction:Number(el('sampling').value)/100,writeMultiplier:Number(el('writes').value),incrementalOperatorHours:Number(el('hours').value),operatorHourlyRate:Number(el('hourly').value),otherMonthlyCosts:Number(el('other').value)};
  const december = el('period').value==='december';
  const hourly=Number(el('hourly').value);
  if(appMode) {
    const appOverrides=Object.fromEntries(crudFields.map(([id,key,multiplier])=>[key,Number(document.getElementById(id).value)*multiplier]));
    const row=MODEL.calculateCrud(Number(el('users').value),overrides,appOverrides);
    const period=december?'December':'Current';
    const cash=row['nathanTotal'+period], clerk=row['clerkTotal'+period], owner=row['nathanOwnership'+period];
    const gap=clerk-owner;
    const laborBudget=clerk-cash-row.otherMonthlyCosts;
    const storage=row.combinedUsage.d1Gb;
    const capacity=storage>1000?'Modeled aggregate storage exceeds the published 1 TB account limit; this is not a viable one-account layout.':`App ${row.appUsage.d1Gb.toFixed(2)} GB + identity ${row.authD1Gb.toFixed(2)} GB. Per-database 10 GB limits and throughput still require a viable layout; capacity is unverified.`;
    document.getElementById('calc-output').innerHTML=`<p><strong>App + Nathan ${usd(cash)}/month · app + Clerk ${usd(clerk)}/month.</strong></p><p>Common app baseline ${usd(row['commonAppCost'+period])}; Nathan auth increment <strong>${usd(row['nathanAuthIncrement'+period])} (${row['nathanAuthShare'+period+'Percent'].toFixed(1)}%)</strong>; Clerk auth <strong>${usd(row.clerkAuth)} (${row['clerkAuthShare'+period+'Percent'].toFixed(1)}%)</strong>. Shares use each stack’s recurring cash total, before entered incremental labor.</p><p>Nathan account Cloudflare ${usd(row['nathanCloudflare'+period])} + auth email ${usd(row.emailCost)} + other common app costs ${usd(row.commonMonthlyCosts)}. With entered incremental labor/other Nathan costs: <strong>${usd(owner)}/month</strong>; ${gap>=0?'below':'above'} app + Clerk by ${usd(Math.abs(gap))}.</p><p>${num(row.activeAppUsers)} active app users; ${num(row.retainedUsers)} retained identities. ${num(row.appUsage.totalRequests)} API requests + ${num(row.authRequests)} identity requests. ${num(row.policyChecks)} service-bound policy checks add CPU/rows, no extra request fee. Combined writes: ${num(row.combinedUsage.d1WrittenRows)}. ${capacity}</p><p>${hourly>0&&laborBudget>0?`Cash gap pays for about ${(laborBudget/hourly).toFixed(1)} additional operator hours at the entered rate, before entered labor.`:laborBudget<=0?'No positive cash budget for incremental labor remains.':'Enter a positive hourly rate for break-even hours.'} ${december?'Announced December 2026 logging prices.':'Current logging prices through November 2026.'}</p>`;
    return;
  }
  const row = MODEL.calculate(Number(el('users').value), overrides);
  const cash = december ? row.nathanCashDecember : row.nathanCashCurrent;
  const cloudflare = december ? row.cloudflareDecember : row.cloudflareCurrent;
  const total = cash + row.incrementalLabor + row.otherMonthlyCosts;
  const gap = row.clerkPro-total;
  const beforeLaborGap = row.clerkPro-cash-row.otherMonthlyCosts;
  document.getElementById('calc-output').innerHTML=`<p><strong>${num(row.retainedUsers)} retained users · Nathan cash ${usd(cash)}/month · Clerk Pro ${usd(row.clerkPro)}/month.</strong></p><p>Cloudflare ${usd(cloudflare)} + auth email ${usd(row.emailCost)}. With entered incremental labor and other costs: <strong>${usd(total)}/month</strong>; ${gap>=0?'below':'above'} Clerk by ${usd(Math.abs(gap))}.</p><p>${num(row.authRequests)} auth requests; ${num(row.protectedRequests)} protected requests; ${num(row.d1WrittenRows)} billed writes; ${row.d1Gb.toFixed(2)} GB aggregate D1 storage. ${row.d1Gb>10?'The modeled footprint requires multiple D1 databases; partitioning is unverified.':'A total below 10 GB does not prove single-database throughput.'}</p><p>${hourly>0&&beforeLaborGap>0?`Cash gap pays for about ${(beforeLaborGap/hourly).toFixed(1)} incremental operator hours at the entered rate, before entered labor.`:beforeLaborGap<=0?'There is no positive cash budget for incremental labor in this scenario.':'Enter a positive hourly rate to calculate break-even hours.'} ${december?'Uses announced December 2026 logging prices.':'Uses current logging prices through November 2026.'}</p>`;
}
el('preset').addEventListener('change',()=>{applyAuthPreset();recompute();});
document.getElementById('crud-preset').addEventListener('change',()=>{
  const scenario=INPUTS.crud.scenarios.find(s=>s.id===document.getElementById('crud-preset').value);
  const a={...INPUTS.crud.assumptions,...scenario.overrides};
  for(const [id,key,multiplier] of crudFields)document.getElementById(id).value=Number((a[key]/multiplier).toFixed(8));
  recompute();
});
for(const [id] of crudFields)document.getElementById(id).addEventListener('input',recompute);
for(const [key,id] of Object.entries(fields))if(key!=='preset')document.getElementById(id).addEventListener('input',recompute);
recompute();
"""

def doc(body, script='', standalone=False):
    css = CSS
    if standalone:
        css += 'body{max-width:1000px;margin:0 auto;padding:38px 30px 70px;background:#fff;color:#172033}html{background:#fff}@media(max-width:540px){body{padding:22px 16px 45px}}'
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><meta name="description" content="Sourced Nathan versus Clerk authentication cost projections, Cloudflare billing mechanics and ownership tradeoffs through 5M users."><title>Nathan vs Clerk: Cloudflare cost and ownership report</title><style>' + css + '</style></head><body>' + body + (('<script>' + script + '</script>') if script else '') + '</body></html>\n'


interactive = doc(BODY, JS)
static_body = BODY.replace(CALCULATOR, '<section id="calculator"><h2>Calculator and data</h2><p>This script-free edition preserves the static results. The companion <code>report.html</code> contains the interactive workload calculator; raw inputs and results are included in the report bundle.</p></section>')
static_body = re.sub(r'<details(.*?)>', r'<details\1 open>', static_body)
(ROOT / 'report.html').write_text(interactive)
(ROOT / 'report-static.html').write_text(doc(static_body, standalone=True))
print('Saved report.html (interactive/T3) and report-static.html (self-contained, script-free, expanded for printing).')
