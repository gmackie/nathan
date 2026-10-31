(() => {
  const model = createCostModel(NATHAN_COST_INPUTS);
  const byId = id => document.getElementById(id);
  const usd = n => new Intl.NumberFormat('en-US', {style:'currency', currency:'USD'}).format(n);
  const number = n => new Intl.NumberFormat('en-US').format(n);
  const text = (id, value) => { byId(id).textContent = value; };

  function updateCosts() {
    const users = Number(byId('audience').value);
    const requests = Number(byId('activity').value);
    const wholeApp = document.querySelector('input[name="scope"]:checked').value === 'crud';
    byId('activity').disabled = !wholeApp;
    const row = wholeApp ? model.calculateCrud(users, {}, {requestsPerActiveUser:requests}) : model.calculate(users);
    const app = wholeApp ? row.commonAppCostCurrent : 0;
    const nathan = wholeApp ? row.nathanTotalCurrent : row.nathanCashCurrent;
    const clerk = wholeApp ? row.clerkTotalCurrent : row.clerkPro;
    const auth = wholeApp ? row.nathanAuthIncrementCurrent : row.nathanCashCurrent;
    const clerkAuth = wholeApp ? row.clerkAuth : row.clerkPro;
    const nathanShare = wholeApp ? row.nathanAuthShareCurrentPercent : 100;
    const clerkShare = wholeApp ? row.clerkAuthShareCurrentPercent : 100;
    text('nathan-total', usd(nathan)); text('clerk-total', usd(clerk));
    text('nathan-app', usd(app)); text('clerk-app', usd(app));
    text('nathan-auth', usd(auth)); text('clerk-auth', usd(clerkAuth));
    text('nathan-share', nathanShare.toFixed(1)+'%'); text('clerk-share', clerkShare.toFixed(1)+'%');
    for(const [name, share] of [['nathan',nathanShare],['clerk',clerkShare]]) {
      byId(name+'-share-bar').setAttribute('x', String(100-share));
      byId(name+'-share-bar').setAttribute('width', String(share));
      text(name+'-share-title', `Authentication is ${share.toFixed(1)} percent of the ${name==='clerk'?'Clerk':'Nathan'} stack total`);
    }
    document.querySelector('.cost-clerk .cost-vendor').textContent = wholeApp?'APP + CLERK PRO':'CLERK PRO / IDENTITY ONLY';
    document.querySelector('.cost-nathan .cost-vendor').textContent = wholeApp?'APP + NATHAN / YOUR ACCOUNT':'NATHAN / IDENTITY ONLY';
    byId('cost-common').textContent = wholeApp ? `Same application in both stacks: ${usd(app)}/month before authentication.` : `${number(users)} monthly retained users. This view excludes application hosting.`;
    text('cost-savings', usd(Math.abs(clerk-nathan)));
    text('savings-copy', `${clerk>=nathan?'less':'more'} modeled cash spend per month, before incremental labor.`);
    text('workload-note', wholeApp ? `${number(requests)} API requests/person/month; 90% indexed reads; 100 kB stored app data/person; one Nathan policy check/API request. App and identity meters share one set of Cloudflare allowances.` : 'Authentication only: no protected business requests. The whole-app view adds identical CRUD hosting to both sides and includes Nathan policy overhead.');
  }

  for(const element of document.querySelectorAll('#audience, #activity, input[name="scope"]')) element.addEventListener('change', updateCosts);
  updateCosts();

  byId('copy-brief').addEventListener('click', async () => {
    const brief = byId('agent-brief').textContent.trim();
    try {
      if(!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(brief);
      text('copy-feedback', 'Brief copied. The agent has been informed that this is work.');
    } catch {
      byId('agent-brief-fallback').open = true;
      text('copy-feedback', 'Copy the brief below. The clipboard declined the assignment.');
    }
  });
})();
