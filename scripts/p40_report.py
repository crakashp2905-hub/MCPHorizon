#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = json.load(open(os.path.join(ROOT, "results/v2/p40-obligation/result.json")))
ci = lambda c: "[%.3f, %.3f]" % tuple(c)


def results():
    S = R["summary"]; L = ["# P40 results — HorizonObligation (CANDIDATE)", "", "Generated from `results/v2/p40-obligation/result.json` (write-once). Commit counts come from the deploy target's journal (separate process); the engine's decisions are never used as outcomes.", "",
         "14 attack and 11 benign scenario types × 3 repetitions = 42 attack runs and 33 benign runs per system.", "", "| system | attacks with no unsafe commit [95% CI] | unsafe excess commits | benign completed correctly [95% CI] | benign blocked | benign duplicate commits | median ms | mean evidence HTTP calls |", "|---|---|---|---|---|---|---|---|"]
    for g in ("nogate", "static", "runtime"):
        v = S[g]; L.append("| %s | %d/%d = %.3f %s | %d | %d/%d = %.3f %s | %d | %d | %s | %s |" % (g, v["attacks_with_no_unsafe_commit"], v["attack_runs"], v["attack_block_rate"], ci(v["attack_block_ci"]), v["unsafe_excess_commits"], v["benign_completed_correctly"], v["benign_runs"], v["benign_completion_rate"], ci(v["benign_ci"]), v["benign_blocked"], v["benign_duplicate_commits"], v["median_ms"], v["mean_http_calls"]))
    L += ["", "`static` = presence/order check on the pipeline run record (needs steps `ci`, `approval`, `sign`, with `ci` before `approval`); it does not verify signatures, expiry, binding, replay, versions or cancellation, and does not recognise an alternative CI issuer. It is one plausible baseline, not every workflow analyser.", "",
          "**Reading the runtime row:** 42/42 and 33/33 are on scenarios written by the same author as the engine; they show the mechanisms work on the designed-for cases, not general security. The CI lower bound for blocking is 0.916 only under the assumption that these 14 types are representative.", "",
          "## Per scenario (commits observed in the journal, 3 runs each; expected in brackets)", "", "| id | kind | description | expected | no gate | static | runtime | runtime denial reasons |", "|---|---|---|---|---|---|---|---|"]
    for k, v in R["per_scenario"].items(): L.append("| %s | %s | %s | %d | %s | %s | %s | %s |" % (k, v["kind"], v["desc"], v["expected"], v["nogate"], v["static"], v["runtime"], ", ".join(v["runtime_reasons"]) or "—"))
    d = R["differential"]; L += ["", "## Differential test vs exhaustive reference (P40-14)", "", "%d event strings (length ≤ %d over T,A,S,X,K,C); reference ALLOW decisions: %d; **mismatches: %d**." % (d["sequences"], d["max_len"], d["allow_decisions_in_reference"], d["mismatches"]), "", "## Limits", ""] + ["* " + x for x in R["limits"]] + [""]
    return "\n".join(L)


def main():
    p = os.path.join(ROOT, "docs/evidence/p40/RESULTS.md"); t = results()
    if "--check" in sys.argv:
        ok = os.path.exists(p) and open(p).read() == t; print("p40 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
    open(p, "w").write(t); print("written")


main()
