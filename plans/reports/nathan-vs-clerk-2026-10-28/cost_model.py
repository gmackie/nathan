"""Offline, auditable pricing arithmetic. Standard library only; no Nathan benchmark."""
from copy import deepcopy
from decimal import Decimal, ROUND_HALF_UP, ROUND_CEILING
from pathlib import Path
import csv
import json

ROOT = Path(__file__).resolve().parent
INPUTS = json.loads((ROOT / "model-inputs.json").read_text())
D = lambda value: Decimal(str(value))
MILLION = D(1000000)


def money(value):
    return float(D(value).quantize(D("0.01"), rounding=ROUND_HALF_UP))


def overage(usage, included, rate, unit=1000000):
    return max(D(0), D(usage) - D(included)) / D(unit) * D(rate)


def cloudflare_bill(usage):
    """One account's combined meters; inclusions and minimum apply exactly once."""
    p = INPUTS["prices"]
    u = {key: D(value) for key, value in usage.items()}
    stored_logs = u["logIngestedGb"] * D(p["logsDecember"]["retentionDays"]) / D(INPUTS["periodDays"])
    c = {
        "workersBase": D(p["workers"]["base"]),
        "workersRequests": overage(u["totalRequests"], p["workers"]["includedRequests"], p["workers"]["requestPerMillion"]),
        "workersCpu": overage(u["cpuMs"], p["workers"]["includedCpuMs"], p["workers"]["cpuMsPerMillion"]),
        "d1Reads": overage(u["d1ReadRows"], p["d1"]["includedReadRows"], p["d1"]["readPerMillion"]),
        "d1Writes": overage(u["d1WrittenRows"], p["d1"]["includedWrittenRows"], p["d1"]["writePerMillion"]),
        "d1Storage": overage(u["d1Gb"], p["d1"]["includedGb"], p["d1"]["gbMonth"], 1),
        "diagnosticLogsCurrent": overage(u["logEvents"], p["logsCurrent"]["includedEvents"], p["logsCurrent"]["eventsPerMillion"]),
        "diagnosticLogsDecember": overage(u["logIngestedGb"], p["logsDecember"]["includedIngestedGb"], p["logsDecember"]["ingestionPerGb"], 1)
        + overage(stored_logs, p["logsDecember"]["includedStoredGbMonth"], p["logsDecember"]["storagePerGbMonth"], 1),
    }
    common = sum((v for k, v in c.items() if not k.startswith("diagnosticLogs")), D(0))
    return c, {"Current": common + c["diagnosticLogsCurrent"], "December": common + c["diagnosticLogsDecember"]}


def clerk_cost(retained_users, annual=False):
    prices = INPUTS["prices"]["clerk"]
    result = D(prices["annualBasePerMonth"] if annual else prices["monthlyBase"])
    lower = D(prices["includedMruPerApp"])
    users = D(retained_users)
    for tier in prices["mruTiers"]:
        upper = users if tier["through"] is None else D(tier["through"])
        result += max(D(0), min(users, upper) - lower) * D(tier["rate"])
        lower = upper
        if users <= upper:
            break
    return result


def calculate(registered_users, overrides=None, annual=False):
    a = {key: D(value) for key, value in INPUTS["assumptions"].items()}
    a["registeredUsers"] = D(registered_users)
    a.update({key: D(value) for key, value in (overrides or {}).items()})
    p = INPUTS["prices"]
    users = a["registeredUsers"]
    retained = (users * a["retainedFraction"]).to_integral_value(rounding=ROUND_CEILING)
    signins = retained * a["signinsPerRetainedUser"]
    refreshes = retained * a["refreshesPerRetainedUser"]
    auth_requests = signins * a["requestsPerSignin"] + refreshes * a["requestsPerRefresh"]
    protected = retained * a["protectedRequestsPerRetainedUser"]
    requests = auth_requests + protected
    cpu = signins * a["cpuMsPerSignin"] + refreshes * a["cpuMsPerRefresh"] + protected * a["cpuMsPerProtectedRequest"]
    reads = signins * a["readRowsPerSignin"] + refreshes * a["readRowsPerRefresh"] + protected * a["readRowsPerProtectedRequest"]
    writes = (signins * a["writtenRowsPerSignin"] + refreshes * a["writtenRowsPerRefresh"] + protected * a["writtenRowsPerProtectedRequest"]) * a["writeMultiplier"]
    storage_gb = users * a["d1BytesPerRegisteredUser"] / D(1000000000)
    log_events = auth_requests * a["authLogFraction"] * a["eventsPerAuthRequest"] + protected * a["protectedLogFraction"] * a["eventsPerProtectedRequest"]
    log_gb = log_events * a["bytesPerLogEvent"] / D(1000000000)
    log_stored = log_gb * D(p["logsDecember"]["retentionDays"]) / D(INPUTS["periodDays"])
    components, bills = cloudflare_bill({"totalRequests": requests, "cpuMs": cpu, "d1ReadRows": reads,
        "d1WrittenRows": writes, "d1Gb": storage_gb, "logEvents": log_events, "logIngestedGb": log_gb})
    current_core, december_core = bills["Current"], bills["December"]
    email_count = (retained * a["emailsPerRetainedUser"]).to_integral_value(rounding=ROUND_CEILING)
    email_overage = max(D(0), email_count - D(p["resend"]["includedEmails"]))
    email_buckets = (email_overage / D(1000)).to_integral_value(rounding=ROUND_CEILING)
    email = D(0) if email_count == 0 else D(p["resend"]["base"]) + email_buckets * D(p["resend"]["overagePer1000Bucket"])
    cash = current_core + email
    clerk = clerk_cost(retained, annual)
    labor = a["incrementalOperatorHours"] * a["operatorHourlyRate"]
    owner_total = cash + labor + a["otherMonthlyCosts"]
    result = {
        "registeredUsers": int(users), "retainedUsers": float(retained), "authRequests": float(auth_requests),
        "protectedRequests": float(protected), "totalRequests": float(requests), "cpuMs": float(cpu),
        "d1ReadRows": float(reads), "d1WrittenRows": float(writes), "d1Gb": float(storage_gb),
        "logEvents": float(log_events), "logIngestedGb": float(log_gb), "logStoredGbMonth": float(log_stored),
        "emails": int(email_count), "minimum10GbDatabases": int((storage_gb / D(p["d1"]["maximumGbPerDatabase"])).to_integral_value(rounding=ROUND_CEILING)),
        "cloudflareCurrent": money(current_core), "cloudflareDecember": money(december_core),
        "emailCost": money(email), "nathanCashCurrent": money(cash), "nathanCashDecember": money(december_core + email),
        "clerkPro": money(clerk), "clerkAnnualEquivalent": money(clerk_cost(retained, True)),
        "cashSavings": money(clerk - cash), "cashSavingsPercent": float((clerk - cash) / clerk * D(100)) if clerk else None,
        "incrementalLabor": money(labor), "otherMonthlyCosts": money(a["otherMonthlyCosts"]), "ownershipTotal": money(owner_total),
        "breakEvenIncrementalHoursAt100": float((clerk - cash) / D(100)),
        "components": {key: money(value) for key, value in components.items()},
    }
    return result


def calculate_crud(registered_users, auth_overrides=None, app_overrides=None):
    # CRUD requests already include the protected request path. Ignore the separate
    # identity-only gateway scenario so selecting it cannot double-count this traffic.
    auth = calculate(registered_users, {**(auth_overrides or {}), "protectedRequestsPerRetainedUser": 0})
    a = {k: D(v) for k, v in INPUTS["crud"]["assumptions"].items()}
    a.update({k: D(v) for k, v in (app_overrides or {}).items()})
    active = (D(registered_users) * a["activeFraction"]).to_integral_value(rounding=ROUND_CEILING)
    requests = active * a["requestsPerActiveUser"]
    read_requests = requests * a["readFraction"]
    mutations = requests - read_requests
    app = {
        "totalRequests": requests,
        "cpuMs": read_requests * a["cpuMsPerRead"] + mutations * a["cpuMsPerMutation"],
        "d1ReadRows": read_requests * a["readRowsPerRead"] + mutations * a["readRowsPerMutation"],
        "d1WrittenRows": mutations * a["writtenRowsPerMutation"],
        "d1Gb": D(registered_users) * a["bytesPerRegisteredUser"] / D(1000000000),
        "logEvents": requests * a["eventsPerRequest"] * a["logFraction"],
    }
    app["logIngestedGb"] = app["logEvents"] * a["bytesPerLogEvent"] / D(1000000000)
    checks = requests * a["policyChecksPerApiRequest"]
    policy = {"totalRequests": D(0), "cpuMs": checks * a["cpuMsPerPolicyCheck"],
        "d1ReadRows": checks * a["readRowsPerPolicyCheck"], "d1WrittenRows": checks * a["writtenRowsPerPolicyCheck"],
        "d1Gb": D(0), "logEvents": checks * a["eventsPerPolicyCheck"] * a["policyLogFraction"]}
    policy["logIngestedGb"] = policy["logEvents"] * a["bytesPerLogEvent"] / D(1000000000)
    combined = {k: app[k] + policy[k] + D(auth[k]) for k in app}
    app_components, app_bills = cloudflare_bill(app)
    combined_components, combined_bills = cloudflare_bill(combined)
    result = {"registeredUsers": int(registered_users), "retainedUsers": auth["retainedUsers"], "activeAppUsers": int(active),
        "readRequests": float(read_requests), "mutationRequests": float(mutations),
        "staticRequests": float(active * a["staticRequestsPerActiveUser"]), "policyChecks": float(checks),
        "authRequests": auth["authRequests"], "authD1Gb": auth["d1Gb"], "emails": auth["emails"],
        "emailCost": auth["emailCost"], "clerkAuth": auth["clerkPro"], "commonMonthlyCosts": money(a["commonMonthlyCosts"]),
        "incrementalLabor": auth["incrementalLabor"], "otherMonthlyCosts": auth["otherMonthlyCosts"],
        "appUsage": {k: float(v) for k, v in app.items()}, "policyUsage": {k: float(v) for k, v in policy.items()},
        "combinedUsage": {k: float(v) for k, v in combined.items()},
        "appComponents": {k: money(v) for k, v in app_components.items()},
        "combinedComponents": {k: money(v) for k, v in combined_components.items()}}
    for period in ("Current", "December"):
        common = app_bills[period] + a["commonMonthlyCosts"]
        increment = combined_bills[period] - app_bills[period] + D(auth["emailCost"])
        total = common + increment
        clerk_total = common + D(auth["clerkPro"])
        gap = clerk_total - total
        result.update({"appCloudflare" + period: money(app_bills[period]), "commonAppCost" + period: money(common),
            "nathanCloudflare" + period: money(combined_bills[period]), "nathanAuthIncrement" + period: money(increment),
            "nathanTotal" + period: money(total), "clerkTotal" + period: money(clerk_total),
            "nathanAuthShare" + period + "Percent": float(increment / total * D(100)),
            "clerkAuthShare" + period + "Percent": float(D(auth["clerkPro"]) / clerk_total * D(100)),
            "totalSavings" + period: money(gap), "totalSavings" + period + "Percent": float(gap / clerk_total * D(100)),
            "nathanOwnership" + period: money(total + D(auth["incrementalLabor"]) + D(auth["otherMonthlyCosts"]))})
    return result


def make_outputs():
    baseline = [calculate(users) for users in INPUTS["scales"]]
    scenarios = [{"id": scenario["id"], "label": scenario["label"], "overrides": scenario["overrides"],
                  "results": [calculate(users, scenario["overrides"]) for users in INPUTS["sensitivityScales"]]}
                 for scenario in INPUTS["scenarios"]]
    retention = [calculate(1000000, {"retainedFraction": fraction}) for fraction in [0.01, 0.05, 0.10, 0.25, 0.50, 1]]
    labor = [calculate(1000000, {"incrementalOperatorHours": hours}) for hours in [0, 6, 20, 80, 180]]
    no_allowances = calculate(1000000)
    # Separate upper-bound allocation example: all account inclusions already used elsewhere.
    no_allowances["incrementalWithoutAnyAllowances"] = money(
        D(no_allowances["totalRequests"]) / MILLION * D("0.30")
        + D(no_allowances["cpuMs"]) / MILLION * D("0.02")
        + D(no_allowances["d1ReadRows"]) / MILLION * D("0.001")
        + D(no_allowances["d1WrittenRows"]) / MILLION
        + D(no_allowances["d1Gb"]) * D("0.75")
        + D(no_allowances["logEvents"]) / MILLION * D("0.60")
        + D(no_allowances["emailCost"]))
    peak = calculate(51000, {"protectedRequestsPerRetainedUser": D(5000 * 30 * 24 * 3600) / D(51000), "protectedLogFraction": D("0.01")})
    crud = [calculate_crud(users) for users in INPUTS["crud"]["scales"]]
    crud_scenarios = [{**s, "results": [calculate_crud(users, app_overrides=s["overrides"]) for users in [51000, 1000000, 5000000]]}
                      for s in INPUTS["crud"]["scenarios"]]
    crud_auth_scenarios = [{"id": "refresh-1920", "label": "Same CRUD app; five-minute refresh, 8 hours/day, 20 days",
        "authOverrides": {"refreshesPerRetainedUser": 1920},
        "results": [calculate_crud(users, {"refreshesPerRetainedUser": 1920}) for users in [51000, 1000000, 5000000]]}]
    output = {"asOf": INPUTS["asOf"], "classification": INPUTS["classification"], "baseline": baseline,
              "scenarios": scenarios, "retentionAtOneMillionRegistered": retention, "laborAtOneMillion": labor,
              "allAllowancesUsedElsewhereAtOneMillion": no_allowances, "continuous5000RpsAt51000Registered": peak,
              "crudBaseline": crud, "crudScenarios": crud_scenarios, "crudAuthScenarios": crud_auth_scenarios}
    (ROOT / "model-results.json").write_text(json.dumps(output, indent=2) + "\n")
    fields = [key for key in baseline[0] if key != "components"]
    with (ROOT / "baseline-costs.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(baseline)
    with (ROOT / "sensitivity-costs.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["scenario", "label", *fields], extrasaction="ignore")
        writer.writeheader()
        for scenario in scenarios:
            for row in scenario["results"]:
                writer.writerow({"scenario": scenario["id"], "label": scenario["label"], **row})
    crud_fields = [k for k in crud[0] if not isinstance(crud[0][k], dict)]
    for filename, entries in [("crud-total-costs.csv", [{"scenario": "baseline", "label": "Read-heavy CRUD", **r} for r in crud]),
                              ("crud-sensitivity-costs.csv", [{"scenario": s["id"], "label": s["label"], **r} for s in [*crud_scenarios,*crud_auth_scenarios] for r in s["results"]])]:
        with (ROOT / filename).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["scenario", "label", *crud_fields], extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
    return output


def verify():
    # Boundary arithmetic is independently stated in published units.
    assert clerk_cost(50000) == D(25)
    assert clerk_cost(50001) == D("25.02")
    assert clerk_cost(51000) == D(45)
    assert clerk_cost(100000) == D(1025)
    assert clerk_cost(250000) == D(3725)
    assert clerk_cost(1000000) == D(17225)
    assert clerk_cost(2000000) == D(32225)
    assert clerk_cost(5000000) == D(77225)
    assert clerk_cost(10000001) == D("152225.012")
    assert D(5) + overage(15000000, 10000000, ".30") + overage(105000000, 30000000, ".02") == D(8)
    assert D(5) + overage(100000000, 10000000, ".30") + overage(700000000, 30000000, ".02") == D("45.40")
    million = calculate(1000000)
    assert million["authRequests"] == 60000000
    assert million["cpuMs"] == 500000000
    assert million["d1WrittenRows"] == 320000000
    assert million["cloudflareCurrent"] == 328.65
    assert million["nathanCashCurrent"] == 483.65
    assert million["nathanCashDecember"] == 462.55
    assert calculate(1000000, {"emailsPerRetainedUser": ".050001"})["emailCost"] == 20.90
    assert calculate(1000000, {"emailsPerRetainedUser": 0})["emailCost"] == 0
    assert calculate(1000000, {"retainedFraction": ".05"})["clerkPro"] == 25
    assert calculate(1000000, {"refreshesPerRetainedUser": 1920})["nathanCashCurrent"] > 17225
    assert calculate(1000000, {"protectedRequestsPerRetainedUser": 1000})["cloudflareCurrent"] > calculate(1000000, {"protectedRequestsPerRetainedUser": 1000, "protectedLogFraction": ".01"})["cloudflareCurrent"]
    # Independently stated CRUD arithmetic: 1B API requests, 900M reads,
    # 100M mutations; one service-bound check adds CPU/rows, no public request.
    crud = calculate_crud(1000000)
    assert crud["appUsage"]["totalRequests"] == 1000000000
    assert crud["appUsage"]["cpuMs"] == 3200000000
    assert crud["appUsage"]["d1ReadRows"] == 18200000000
    assert crud["appUsage"]["d1WrittenRows"] == 300000000
    assert crud["combinedUsage"]["totalRequests"] == 1060000000
    assert crud["combinedUsage"]["d1ReadRows"] == 28920000000
    assert crud["combinedUsage"]["d1WrittenRows"] == 620000000
    assert crud["appCloudflareCurrent"] == 686.65
    assert crud["nathanCloudflareCurrent"] == 1123.57
    assert crud["nathanAuthIncrementCurrent"] == 591.92
    assert crud["nathanTotalCurrent"] == 1278.57
    assert crud["clerkTotalCurrent"] == 17911.65
    assert crud["appComponents"]["workersBase"] == crud["combinedComponents"]["workersBase"] == 5
    assert crud["combinedComponents"]["d1Writes"] == 570  # one 50M allowance, not two
    no_app = calculate_crud(1000000, app_overrides={"requestsPerActiveUser": 0, "bytesPerRegisteredUser": 0})
    assert no_app["appCloudflareCurrent"] == 5
    assert no_app["nathanTotalCurrent"] == million["nathanCashCurrent"]
    assert calculate_crud(1000000, {"protectedRequestsPerRetainedUser": 1000})["nathanTotalCurrent"] == crud["nathanTotalCurrent"]
    extras = calculate_crud(1000000, app_overrides={"commonMonthlyCosts": 100})
    assert extras["totalSavingsCurrent"] == crud["totalSavingsCurrent"]
    assert extras["nathanAuthIncrementCurrent"] == crud["nathanAuthIncrementCurrent"]
    ledger = json.loads((ROOT / "source-ledger.json").read_text())
    for source in ledger:
        assert source.get("httpStatus") == 200, source
    print("PASS: identity arithmetic, Clerk boundaries, official Worker examples, CRUD worked example, shared allowances, service bindings, no-app reconciliation and common-cost allocation.")


if __name__ == "__main__":
    verify()
    results = make_outputs()
    for row in results["baseline"]:
        print(f"{row['registeredUsers']:>9,}: Clerk ${row['clerkPro']:,.2f}; Cloudflare ${row['cloudflareCurrent']:,.2f}; mail ${row['emailCost']:,.2f}; Nathan cash ${row['nathanCashCurrent']:,.2f}")
