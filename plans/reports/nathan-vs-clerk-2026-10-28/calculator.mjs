/** Report-only calculator. Cross-checked against the Decimal Python model. */
export function createCostModel(input) {
  const p = input.prices;
  // Restore half-cent ties lost to binary arithmetic (for example 5.1 - 5),
  // then round away from zero to match Decimal ROUND_HALF_UP.
  const cents = n => {
    const scaled = Math.abs(n) * 100;
    const half = Math.round(scaled * 2) / 2;
    const stable = Math.abs(scaled-half) <= 32*Number.EPSILON*Math.max(1,scaled) ? half : scaled;
    return (n < 0 ? -1 : 1) * Math.round(stable) / 100;
  };
  const extra = (n, included, rate, unit = 1e6) => Math.max(0, n - included) * rate / unit;
  const ceilCount = n => {
    const integer = Math.round(n);
    return Math.ceil(Math.abs(n-integer)<=32*Number.EPSILON*Math.max(1,Math.abs(n)) ? integer : n);
  };
  function cloudflareBill(u) {
    const stored = u.logIngestedGb * p.logsDecember.retentionDays / input.periodDays;
    const components = {
      workersBase: p.workers.base,
      workersRequests: extra(u.totalRequests, p.workers.includedRequests, p.workers.requestPerMillion),
      workersCpu: extra(u.cpuMs, p.workers.includedCpuMs, p.workers.cpuMsPerMillion),
      d1Reads: extra(u.d1ReadRows, p.d1.includedReadRows, p.d1.readPerMillion),
      d1Writes: extra(u.d1WrittenRows, p.d1.includedWrittenRows, p.d1.writePerMillion),
      d1Storage: extra(u.d1Gb, p.d1.includedGb, p.d1.gbMonth, 1),
      diagnosticLogsCurrent: extra(u.logEvents, p.logsCurrent.includedEvents, p.logsCurrent.eventsPerMillion),
      diagnosticLogsDecember: extra(u.logIngestedGb, p.logsDecember.includedIngestedGb, p.logsDecember.ingestionPerGb, 1)
        + extra(stored, p.logsDecember.includedStoredGbMonth, p.logsDecember.storagePerGbMonth, 1)
    };
    const common = Object.entries(components).filter(([key])=>!key.startsWith('diagnosticLogs')).reduce((sum,[,value])=>sum+value,0);
    return {components, bills:{Current:common+components.diagnosticLogsCurrent,December:common+components.diagnosticLogsDecember}};
  }
  function clerkCost(users, annual = false) {
    let cost = annual ? p.clerk.annualBasePerMonth : p.clerk.monthlyBase;
    let lower = p.clerk.includedMruPerApp;
    for (const tier of p.clerk.mruTiers) {
      const upper = tier.through ?? users;
      cost += Math.max(0, Math.min(users, upper) - lower) * tier.rate;
      lower = upper;
      if (users <= upper) break;
    }
    return cost;
  }
  function calculate(registeredUsers, overrides = {}, annual = false) {
    const a = {...input.assumptions, registeredUsers, ...overrides};
    const retainedUsers = ceilCount(a.registeredUsers * a.retainedFraction);
    const signins = retainedUsers * a.signinsPerRetainedUser;
    const refreshes = retainedUsers * a.refreshesPerRetainedUser;
    const authRequests = signins * a.requestsPerSignin + refreshes * a.requestsPerRefresh;
    const protectedRequests = retainedUsers * a.protectedRequestsPerRetainedUser;
    const totalRequests = authRequests + protectedRequests;
    const cpuMs = signins * a.cpuMsPerSignin + refreshes * a.cpuMsPerRefresh + protectedRequests * a.cpuMsPerProtectedRequest;
    const d1ReadRows = signins * a.readRowsPerSignin + refreshes * a.readRowsPerRefresh + protectedRequests * a.readRowsPerProtectedRequest;
    const d1WrittenRows = (signins * a.writtenRowsPerSignin + refreshes * a.writtenRowsPerRefresh + protectedRequests * a.writtenRowsPerProtectedRequest) * a.writeMultiplier;
    const d1Gb = a.registeredUsers * a.d1BytesPerRegisteredUser / 1e9;
    const logEvents = authRequests * a.authLogFraction * a.eventsPerAuthRequest + protectedRequests * a.protectedLogFraction * a.eventsPerProtectedRequest;
    const logIngestedGb = logEvents * a.bytesPerLogEvent / 1e9;
    const logStoredGbMonth = logIngestedGb * p.logsDecember.retentionDays / input.periodDays;
    const account = cloudflareBill({totalRequests,cpuMs,d1ReadRows,d1WrittenRows,d1Gb,logEvents,logIngestedGb});
    const raw = account.components;
    const cloudflareCurrent = account.bills.Current;
    const cloudflareDecember = account.bills.December;
    const emails = ceilCount(retainedUsers * a.emailsPerRetainedUser);
    const emailCost = emails === 0 ? 0 : p.resend.base + ceilCount(Math.max(0, emails - p.resend.includedEmails) / 1000) * p.resend.overagePer1000Bucket;
    const cash = cloudflareCurrent + emailCost;
    const clerkPro = clerkCost(retainedUsers, annual);
    const incrementalLabor = a.incrementalOperatorHours * a.operatorHourlyRate;
    return {
      registeredUsers: a.registeredUsers, retainedUsers, authRequests, protectedRequests, totalRequests, cpuMs,
      d1ReadRows, d1WrittenRows, d1Gb, logEvents, logIngestedGb, logStoredGbMonth, emails,
      minimum10GbDatabases: Math.ceil(d1Gb / p.d1.maximumGbPerDatabase),
      cloudflareCurrent: cents(cloudflareCurrent), cloudflareDecember: cents(cloudflareDecember), emailCost: cents(emailCost),
      nathanCashCurrent: cents(cash), nathanCashDecember: cents(cloudflareDecember + emailCost), clerkPro: cents(clerkPro),
      clerkAnnualEquivalent: cents(clerkCost(retainedUsers, true)), cashSavings: cents(clerkPro - cash),
      cashSavingsPercent: clerkPro ? (clerkPro - cash) / clerkPro * 100 : null,
      incrementalLabor: cents(incrementalLabor), otherMonthlyCosts: cents(a.otherMonthlyCosts),
      ownershipTotal: cents(cash + incrementalLabor + a.otherMonthlyCosts), breakEvenIncrementalHoursAt100: (clerkPro - cash) / 100,
      components: Object.fromEntries(Object.entries(raw).map(([key, value]) => [key, cents(value)]))
    };
  }
  function calculateCrud(registeredUsers, authOverrides = {}, appOverrides = {}) {
    const auth = calculate(registeredUsers, {...authOverrides,protectedRequestsPerRetainedUser:0});
    const a = {...input.crud.assumptions,...appOverrides};
    const activeAppUsers = ceilCount(registeredUsers * a.activeFraction);
    const requests = activeAppUsers * a.requestsPerActiveUser;
    const readRequests = requests * a.readFraction;
    const mutationRequests = requests-readRequests;
    const appUsage = {
      totalRequests:requests,cpuMs:readRequests*a.cpuMsPerRead+mutationRequests*a.cpuMsPerMutation,
      d1ReadRows:readRequests*a.readRowsPerRead+mutationRequests*a.readRowsPerMutation,
      d1WrittenRows:mutationRequests*a.writtenRowsPerMutation,d1Gb:registeredUsers*a.bytesPerRegisteredUser/1e9,
      logEvents:requests*a.eventsPerRequest*a.logFraction
    };
    appUsage.logIngestedGb=appUsage.logEvents*a.bytesPerLogEvent/1e9;
    const policyChecks=requests*a.policyChecksPerApiRequest;
    const policyUsage={totalRequests:0,cpuMs:policyChecks*a.cpuMsPerPolicyCheck,
      d1ReadRows:policyChecks*a.readRowsPerPolicyCheck,d1WrittenRows:policyChecks*a.writtenRowsPerPolicyCheck,
      d1Gb:0,logEvents:policyChecks*a.eventsPerPolicyCheck*a.policyLogFraction};
    policyUsage.logIngestedGb=policyUsage.logEvents*a.bytesPerLogEvent/1e9;
    const combinedUsage=Object.fromEntries(Object.keys(appUsage).map(key=>[key,appUsage[key]+policyUsage[key]+auth[key]]));
    const app=cloudflareBill(appUsage), combined=cloudflareBill(combinedUsage);
    const result={registeredUsers,retainedUsers:auth.retainedUsers,activeAppUsers,readRequests,mutationRequests,
      staticRequests:activeAppUsers*a.staticRequestsPerActiveUser,policyChecks,authRequests:auth.authRequests,
      authD1Gb:auth.d1Gb,emails:auth.emails,emailCost:auth.emailCost,clerkAuth:auth.clerkPro,
      commonMonthlyCosts:cents(a.commonMonthlyCosts),incrementalLabor:auth.incrementalLabor,otherMonthlyCosts:auth.otherMonthlyCosts,
      appUsage,policyUsage,combinedUsage,
      appComponents:Object.fromEntries(Object.entries(app.components).map(([k,v])=>[k,cents(v)])),
      combinedComponents:Object.fromEntries(Object.entries(combined.components).map(([k,v])=>[k,cents(v)]))};
    for(const period of ['Current','December']) {
      const common=app.bills[period]+a.commonMonthlyCosts;
      const increment=combined.bills[period]-app.bills[period]+auth.emailCost;
      const total=common+increment;
      const clerkTotal=common+auth.clerkPro;
      const gap=clerkTotal-total;
      Object.assign(result,{
        ['appCloudflare'+period]:cents(app.bills[period]),['commonAppCost'+period]:cents(common),
        ['nathanCloudflare'+period]:cents(combined.bills[period]),['nathanAuthIncrement'+period]:cents(increment),
        ['nathanTotal'+period]:cents(total),['clerkTotal'+period]:cents(clerkTotal),
        ['nathanAuthShare'+period+'Percent']:increment/total*100,['clerkAuthShare'+period+'Percent']:auth.clerkPro/clerkTotal*100,
        ['totalSavings'+period]:cents(gap),['totalSavings'+period+'Percent']:gap/clerkTotal*100,
        ['nathanOwnership'+period]:cents(total+auth.incrementalLabor+auth.otherMonthlyCosts)
      });
    }
    return result;
  }
  return {calculate, calculateCrud, clerkCost};
}
