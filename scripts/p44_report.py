#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = json.load(open(os.path.join(ROOT, "results/v2/p44-reach/result.json")))
ci = lambda c: "%d/%d = %.3f [%.3f, %.3f]" % (c["k"], c["n"], c["rate"], c["ci"][0], c["ci"][1]) if c and c.get("n") else "—"
NAMES = {"allowlist": "strict domain allowlist (checks every URL argument, resolves, follows redirects)", "pattern": "URL-pattern deny list", "declaration": "allowlist + trust in self-declared service description", "reach": "HorizonReach (full)"}


def results():
    L = ["# P44 results — HorizonReach (CANDIDATE)", "", "Generated from `results/v2/p44-reach/result.json` (write-once). Security outcomes come from the sink process journal (an independent process on the mock network); the broker never writes it. %d runs = %d scenarios × %d systems × %d repetitions. Loopback aliases only, synthetic canary only." % (R["runs"], len(R["scenarios"]), len(R["systems"]), R["reps"]), "",
         "## Systems (attack runs = 15 types × %d; benign = 12 types × %d)" % (R["reps"], R["reps"]), "", "| system | attacks with a real forbidden effect [95% CI] | attacks prevented | blocked as UNKNOWN | benign completed [95% CI] | false positives on approved redirects/variants | redirect + rebinding catches | p50 / p95 ms |", "|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = R["summary"][s]; L.append("| %s | %s | %s | %d | %s | %s | %s | %s / %s |" % (s, ci(v["attacks_with_forbidden_effect"]), ci(v["attacks_prevented"]).split(" = ")[1], v["unknown_blocked_attacks"], ci(v["benign_completed"]), ci(v["false_positives_on_approved_redirects_and_variants"]), ci(v["redirect_and_rebind_race_catches"]), v["ms_p50"], v["ms_p95"]))
    L += ["", "Baselines: " + "; ".join("`%s` = %s" % (k, v) for k, v in NAMES.items()) + ". Rows `reach-no-*` are ablations that disable one mechanism.", "", "## Per scenario (V = real forbidden effect at the sink journal, C = completed, x = not completed; then verdict A/D/U; across repetitions)", "", "| id | kind | " + " | ".join(R["systems"]) + " |", "|---|---|" + "---|" * len(R["systems"])]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"].get(s, "") for s in R["systems"])))
    L += ["", "| id | what it does |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["note"]) for s in R["scenarios"]]
    a = R["a03_followup"]["reach"]; L += ["", "## The honest failure: an attested external service that lies (A03)", "", "First call: forbidden effect in %d/%d runs for HorizonReach (attestation and signed receipts are claims; the receipts omitted the hidden request). Independent-observer audit detected it in %d/%d runs and revoked the manifest; the second call then violated in %d/%d runs. Prevention of the first effect is **not** claimed." % (a["first_call_violated"], a["runs"], a["audit_detected"], a["runs"], a["second_call_violated"], a["runs"]), "",
          "## Missing receipts and partial observability (HorizonReach, per repetition)", "", "| run | verdict at call time | verdict after the call | receipt | oracle |", "|---|---|---|---|---|"] + ["| %s | %s | %s | %s | %s |" % (k, v["verdict"], v["post_verdict"], v["receipt"], v["oracle"]) for k, v in R["observability"].items()]
    L += ["", "Unsupported success claims when a required receipt is absent (O01, ALLOW after the call): " + ", ".join("%s %d" % (k, v) for k, v in R["unsupported_success_claims_O01"].items() if v is not None) + ".", "", "## Budgeted reachability (P44-13)", "", "| graph | nodes | edges | budget | expanded | reached | ms | UNKNOWN | exhausted | reasons |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in R["reach_budget_study"]: L.append("| %s | %d | %d | %s | %d | %d | %s | %s | %s | %s |" % (r["graph"], r["n"], r["edges"], r["budget"] or "default", r["expanded"], r["reached"], r["ms"], r["unknown"], r["exhausted"], "; ".join(r["reasons"]) or "—"))
    ag = R["emergence_agreement"]; L += ["", "## Agreement with HorizonEmergence's concrete chain analysis (P44-08)", "", "%d world/URL combinations; exact agreement in %d; reach is a capability analysis, so it may be more conservative than a concrete request chain; soundness violations (Emergence DENY/UNKNOWN while reach says ALLOW): %d." % (len(ag), sum(1 for x in ag if x["agree"]), sum(1 for x in ag if not x["sound"])), "",
          "## Sandbox calibration for services that bypass the fabric (P44-02/09)", "", "```json", json.dumps(R["sandbox_bypass"]), "```", "", "## Limits", ""] + ["* " + x for x in R["limits"]] + [""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p44/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p44 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
