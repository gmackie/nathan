"""Publication figures from saved model results; matplotlib==3.10.7."""
from pathlib import Path
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

ROOT = Path(__file__).resolve().parent
R = json.loads((ROOT / "model-results.json").read_text())
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "text.parse_math": False, "svg.fonttype": "none", "axes.spines.top": False, "axes.spines.right": False})
rows = [row for row in R["baseline"] if row["registeredUsers"] >= 50000]
users = [row["registeredUsers"] for row in rows]
fig, ax = plt.subplots(figsize=(12.6, 7.0))
fig.subplots_adjust(left=.09, right=.98, bottom=.21, top=.84)
fig.suptitle("Monthly identity-service cost at published list rates", x=.065, y=.98, ha="left", fontsize=18, fontweight="bold")
ax.set_title("Every registered user is monthly retained in this scenario. Nathan usage is modeled, not measured.", loc="left", fontsize=11, pad=17)
series = [("Clerk Pro, monthly billing", "clerkPro", "#2563eb"), ("Nathan Cloudflare + auth email", "nathanCashCurrent", "#15803d"), ("Nathan Cloudflare only", "cloudflareCurrent", "#b45309")]
for label, key, color in series:
    ax.plot(users, [row[key] for row in rows], marker="o", markersize=5, linewidth=2.5, label=label, color=color)
ax.set_xscale("log")
ax.set_xticks([50000, 100000, 250000, 1000000, 2000000, 5000000], ["50K", "100K", "250K", "1M", "2M", "5M"])
ax.set_xlabel("Monthly retained users · logarithmic horizontal scale", labelpad=12)
ax.set_ylabel("USD per month")
ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"${v:,.0f}"))
ax.grid(axis="y", color="#d1d5db", linestyle="--", linewidth=.7)
ax.set_axisbelow(True)
ax.legend(loc="upper left", frameon=False)
ax.annotate("1M: Clerk $17,225\nNathan + email $483.65", xy=(1000000, 17225), xytext=(300000, 38000), arrowprops={"arrowstyle": "->", "color": "#475569"}, fontsize=11)
fig.text(.065, .025, "Rates checked 28 Oct 2026 · clerk.com/pricing · Cloudflare Workers/D1 pricing · resend.com/pricing\nOne app; 4 sign-ins + 20 refreshes/retained user/month; labor, development and app hosting excluded. 1M+ capacity unverified.", fontsize=9, color="#475569")
for suffix in ["png", "svg"]:
    fig.savefig(ROOT / ("cost-at-scale." + suffix), dpi=180, bbox_inches="tight", facecolor="white")
plt.close(fig)

row = next(row for row in R["baseline"] if row["registeredUsers"] == 1000000)
c = row["components"]
items = [("Workers plan", c["workersBase"]), ("Workers requests", c["workersRequests"]), ("Workers CPU", c["workersCpu"]), ("D1 writes", c["d1Writes"]), ("D1 storage", c["d1Storage"]), ("Diagnostic logs", c["diagnosticLogsCurrent"]), ("Auth email", row["emailCost"])]
fig, ax = plt.subplots(figsize=(10.5, 6.5))
fig.subplots_adjust(left=.18, right=.97, bottom=.21, top=.82)
fig.suptitle(f"What Nathan's modeled ${row['nathanCashCurrent']:,.2f}/month pays for at 1M", x=.07, y=.98, ha="left", fontsize=17, fontweight="bold")
ax.set_title("Moderate identity traffic; current logging rates; excludes labor and app hosting", loc="left", fontsize=10, pad=15)
labels, values = zip(*items)
colors = ["#2563eb"] * 3 + ["#b45309", "#b45309", "#7c3aed", "#15803d"]
bars = ax.barh(labels, values, color=colors, height=.64)
ax.invert_yaxis()
ax.bar_label(bars, labels=[f"${v:,.2f}" for v in values], padding=6, fontsize=11)
ax.set_xlim(0, 325)
ax.set_xlabel("USD per month")
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"${v:,.0f}"))
ax.grid(axis="x", color="#d1d5db", linestyle="--", linewidth=.7)
ax.set_axisbelow(True)
fig.text(.07, .025, "D1 reads: $0 within the 25B-row allowance. 320M modeled billed writes make writes the largest infrastructure item.\n12 GB modeled storage exceeds one D1 database's 10 GB ceiling; the economics assume a viable partitioned design.", fontsize=9, color="#475569")
for suffix in ["png", "svg"]:
    fig.savefig(ROOT / ("one-million-breakdown." + suffix), dpi=180, bbox_inches="tight", facecolor="white")
plt.close(fig)
rows = R['crudBaseline']
users = [r['registeredUsers'] for r in rows]
fig, ax = plt.subplots(figsize=(12.6, 7.0))
fig.subplots_adjust(left=.09, right=.98, bottom=.21, top=.84)
fig.suptitle('Monthly operating cost: a simple CRUD app plus authentication', x=.065, y=.98, ha='left', fontsize=17, fontweight='bold')
ax.set_title('Same Workers/D1 app in both stacks; explicit unmeasured workload; shared account allowances applied once.', loc='left', fontsize=10.5, pad=17)
for label, key, color, style in [
    ('App + Clerk Pro', 'clerkTotalCurrent', '#2563eb', '-'),
    ('App + Nathan', 'nathanTotalCurrent', '#15803d', '-'),
    ('Common app only', 'commonAppCostCurrent', '#64748b', '--')]:
    ax.plot(users, [r[key] for r in rows], marker='o', markersize=5, linewidth=2.5, label=label, color=color, linestyle=style)
ax.set_xscale('log')
ax.set_xticks([50000, 100000, 250000, 1000000, 2000000, 5000000], ['50K','100K','250K','1M','2M','5M'])
ax.set_xlabel('Active app users = retained identities · logarithmic horizontal scale', labelpad=12)
ax.set_ylabel('USD per month')
ax.set_ylim(0, 90000)
ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f'${v:,.0f}'))
ax.grid(axis='y', color='#d1d5db', linestyle='--', linewidth=.7)
ax.set_axisbelow(True)
ax.legend(loc='upper left', frameon=False)
c = next(r for r in rows if r['registeredUsers'] == 1000000)
ax.annotate(f"1M users: app + Clerk ${c['clerkTotalCurrent']:,.2f}\nApp + Nathan ${c['nathanTotalCurrent']:,.2f}",
            xy=(1000000,c['clerkTotalCurrent']), xytext=(250000,41000),
            arrowprops={'arrowstyle':'->','color':'#475569'}, fontsize=10.5)
fig.text(.065,.025,'1,000 API requests/active user/month; 90% reads; 100 kB app data/account; 1% app/policy diagnostics. Nathan adds live policy checks.\n28 Oct 2026 prices; USD before tax. Totals exclude labor, development and unspecified external services. 1M+ capacity is unverified.',fontsize=9,color='#475569')
for suffix in ['png','svg']:
    fig.savefig(ROOT / ('crud-total-cost-at-scale.'+suffix), dpi=180, bbox_inches='tight', facecolor='white')
plt.close(fig)

fig, axes = plt.subplots(2,1,figsize=(11.7,7.5))
fig.subplots_adjust(left=.13,right=.84,bottom=.19,top=.82,hspace=.95)
fig.suptitle('What share of the app operating bill is authentication?',x=.065,y=.98,ha='left',fontsize=17,fontweight='bold')
fig.text(.065,.90,'1M active and retained users · read-heavy CRUD app · modeled current-rate cash costs, before labor',fontsize=11)
labels=['App + Nathan','App + Clerk']
common=c['commonAppCostCurrent']
increments=[c['nathanAuthIncrementCurrent'],c['clerkAuth']]
totals=[c['nathanTotalCurrent'],c['clerkTotalCurrent']]
shares=[c['nathanAuthShareCurrentPercent'],c['clerkAuthShareCurrentPercent']]
colors=['#15803d','#2563eb']
ax=axes[0]
ax.barh(labels,[common,common],color='#64748b',height=.5,label='Common app')
ax.barh(labels,increments,left=common,color=colors,height=.5)
ax.invert_yaxis()
ax.set_xlim(0,max(totals)*1.12)
for y,total in enumerate(totals): ax.text(total+max(totals)*.012,y,f'${total:,.2f}',va='center',fontsize=10.5,fontweight='bold')
ax.set_xlabel('Actual modeled USD/month · both bars use the same dollar scale')
ax.xaxis.set_major_formatter(FuncFormatter(lambda v,_:f'${v:,.0f}'))
ax.grid(axis='x',color='#d1d5db',linestyle='--',linewidth=.7);ax.set_axisbelow(True)
ax.set_title(f'Common app ${common:,.2f} + incremental authentication',loc='left',fontsize=11,pad=12)
ax=axes[1]
app_shares=[100-v for v in shares]
ax.barh(labels,app_shares,color='#64748b',height=.5)
ax.barh(labels,shares,left=app_shares,color=colors,height=.5)
ax.invert_yaxis();ax.set_xlim(0,100)
for y,share in enumerate(shares):ax.text(101,y,f'{share:.1f}% auth',va='center',fontsize=11,fontweight='bold')
ax.set_xticks([0,25,50,75,100],['0%','25%','50%','75%','100%'])
ax.set_xlabel('Share of each stack’s own cash total · these bars have different dollar totals')
ax.set_title(f"Nathan auth increment ${increments[0]:,.2f}; Clerk Pro fee ${increments[1]:,.2f}",loc='left',fontsize=11,pad=12)
fig.text(.065,.025,'Gray = common app. Green = Nathan auth/policy/email increment. Blue = Clerk Pro subscription.\nIncrement = combined Cloudflare bill − app-only bill + Nathan auth email; allowances and the $5 base apply once.\nIllustrative workload, 28 Oct 2026 prices. No measured capacity claim; additional operations/development costs are excluded.',fontsize=9,color='#475569')
for suffix in ['png','svg']:
    fig.savefig(ROOT / ('crud-cost-composition.'+suffix),dpi=180,bbox_inches='tight',facecolor='white')
plt.close(fig)
print('Saved four PNG and four SVG figures from model-results.json.')
