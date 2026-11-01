#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = json.load(open(os.path.join(ROOT, "results/v2/p45-privacy/result.json")))
ci = lambda c: "%d/%d = %.3f [%.3f, %.3f]" % (c["k"], c["n"], c["rate"], c["ci"][0], c["ci"][1]) if c and c.get("n") else "—"
DESC = {"per-agent-limit": "per-agent request limit (6 sensitive queries)", "per-principal-accountant": "correct accountant, but one ledger per principal (no federation)", "dlp": "generic DLP on released text", "token-limit": "raw query token-count limit",
        "non-transactional": "shared budget checked read-then-write", "horizon-basic": "HorizonPrivacy, basic composition", "horizon-advanced": "HorizonPrivacy, Kairouz et al. advanced composition", "horizon-zcdp": "HorizonPrivacy, zCDP accounting"}


def results():
    L = ["# P45 results — HorizonPrivacy (CANDIDATE)", "", "Generated from `results/v2/p45-privacy/result.json` (write-once). Budget eps=%s, delta=%s per dataset; each attack query costs eps=%s. %d runs = %d scenarios × %d systems × %d repetitions. Synthetic data only." % (R["accountants"]["budget"]["eps"], R["accountants"]["budget"]["delta"], json.load(open(os.path.join(ROOT, "results/v2/p45-privacy/manifest.json")))["definitions"]["budget"]["query_eps"], R["runs"], len(R["scenarios"]), len(R["systems"]), R["reps"]), "",
         "**Violation** = the independent accountant, recomputing from what the adversary actually observed plus the *declared* sensitivities, finds composed cost above the budget (or, for raw queries, an exact individual value recovered).", "",
         "## Systems", "", "| system | attack scenarios over budget [95% CI, runs] | benign queries completed [95% CI] | benign scenarios fully completed | mean abs error of count answers | median / p95 query ms | chain ok | audit mismatches |", "|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = R["summary"][s]; L.append("| %s | %s | %s | %s | %s | %s / %s | %s | %d |" % (s, ci(v["attacks_over_budget"]), ci(v["benign_completed"]), ci(v["benign_scenarios_fully_completed"]), v["mean_abs_error_count_queries"], v["median_query_ms"], v["p95_query_ms"], v["chain_ok_all"], v["audit_mismatches"]))
    L += ["", "Baselines: " + "; ".join("`%s` = %s" % (k, v) for k, v in DESC.items()) + ". `horizon-no-*` rows each disable one mechanism of `horizon-basic`.", "",
          "## Per scenario (attacks: V = violation in a repetition, - = none; benign: completed/total per repetition)", "", "| id | kind | " + " | ".join(R["systems"]) + " |", "|---|---|" + "---|" * len(R["systems"])]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"].get(s, "") for s in R["systems"])))
    L += ["", "| id | what it does |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["note"]) for s in R["scenarios"]]
    a = R["accountants"]; L += ["", "## Accountant comparison (P45-14), budget eps=%s delta=%s" % (a["budget"]["eps"], a["budget"]["delta"]), "", "Queries answered before the first denial:", "", "| workload | basic | advanced | zCDP |", "|---|---|---|---|"]
    for k, v in a["laplace_queries_answered"].items(): L.append("| Laplace eps=%s | %d | %d | %d |" % (k, v["basic"], v["advanced"], v["zcdp"]))
    for k, v in a["gaussian_queries_answered"].items(): L.append("| Gaussian %s | %d | %d | %d |" % (k, v["basic"], v["advanced"], v["zcdp"]))
    L += ["", "Fixed task of k count queries — largest per-query eps that fits, and the resulting expected absolute error of one count (~1/eps):", "", "| k | basic eps / error | advanced eps / error | zCDP eps / error |", "|---|---|---|---|"]
    for k, v in a["fixed_task"].items(): L.append("| %s | %s | %s | %s |" % (k, *["%s / %s" % (v[x]["eps_per_query"], v[x]["expected_abs_error"]) for x in ("basic", "advanced", "zcdp")]))
    L += ["", "Ledger cost of one reserve+begin+commit (300 sequential requests, in-memory SQLite): " + "; ".join("%s p50 %s ms, p95 %s ms" % (k, v["p50_ms"], v["p95_ms"]) for k, v in a["ledger_latency_300_requests"].items()) + ". Every reservation recomputes the composition over all charges, so the cost grows with ledger size.", ""]
    d = R["differential"]; L += ["## Differential test against the independent accountant (P45-12)", "", "%d random reserve/cancel/begin/expire decisions across the three accountants: ledger-allow & reference-allow %d, ledger-deny & reference-deny %d, **ledger-allow & reference-deny %d**, ledger-deny & reference-allow within the float safety margin %d, other %d. Agreement: %s." % (d["decisions"], d["ledger_allow_ref_allow"], d["ledger_deny_ref_deny"], d["ledger_allow_ref_deny"], d["ledger_deny_ref_allow_boundary"], d["ledger_deny_ref_allow_other"], d["agreement"]), "",
          "## Concurrency (P45-06): 8 threads × 40 requests on one SQLite file, budget admits %d" % R["concurrency"]["max_allowed"], "", "| ledger | granted per trial | overcommit per trial | audit | chain |", "|---|---|---|---|---|"]
    for atomic in (True, False):
        ts = [t for t in R["concurrency"]["trials"] if t["atomic"] == atomic]; L.append("| %s | %s | %s | %s | %s |" % ("transactional (BEGIN IMMEDIATE)" if atomic else "ablation: statements auto-commit", [t["granted"] for t in ts], [t["overcommit"] for t in ts], "clean" if all(not t["audit"] for t in ts) else "mismatch", all(t["chain_ok"] for t in ts)))
    L += ["", "## Cross-agent budget-composition experiment (P45-16): 8 agents × 4 queries on one target count, membership inference by averaging; %d seeded trials" % R["composition"]["horizon-basic"]["trials"], "", "| system | mean answers released | max composed cost (eps) | runs over budget | attack accuracy [95% CI] |", "|---|---|---|---|---|"]
    for s, c in R["composition"].items(): L.append("| %s | %s | %s | %d | %s |" % (s, c["mean_answers_released"], c["max_cost"], c["runs_over_budget"], ci(c["attack_accuracy"])))
    L += ["", "The claim is the composed-cost column. The accuracy difference between 8 and 32 pooled answers is suggestive but its intervals overlap at 40 trials, and the attacker is one simple averaging strategy; no accuracy bound is claimed. Without transactions the ledger granted more than the budget and its hash chain also broke (concurrent unserialised log writes), see the `horizon-no-transaction` row.", "", "Repeat with `python3 scripts/p45_repeat.py --seed N` (see `REPEAT.md`).", "", "## Limits", ""] + ["* " + x for x in R["limits"]] + [""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p45/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p45 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
