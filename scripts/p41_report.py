#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = json.load(open(os.path.join(ROOT, "results/v2/p41-counterfactual/result.json")))
ci = lambda c: "[%.3f, %.3f]" % tuple(c)


def results():
    S = R["summary"]; L = ["# P41 results — HorizonCounterfactual (CANDIDATE)", "", "Generated from `results/v2/p41-counterfactual/result.json` (write-once). Effects are read from an independent receipt process and a registry journal, never from the system under test.", "",
         "14 attack and 10 benign scenario types × 3 repetitions per system (42 / 30 runs).", "", "| system | attacks with no out-of-intent effect [95% CI] | out-of-intent effects (total rows/files) | benign completed [95% CI] | benign refused | stale retries | row-count prediction exact | p50 / p95 / p99 ms | benign completions per s |", "|---|---|---|---|---|---|---|---|---|"]
    for g in ("acl", "dryrun", "llm_preview", "counterfactual"):
        v = S[g]; L.append("| %s | %d/%d = %.3f %s | %d | %d/%d = %.3f %s | %d | %d | %s | %s / %s / %s | %s |" % (g, v["attacks_without_unsafe_effect"], v["attack_runs"], v["safe_rate"], ci(v["safe_ci"]), v["unsafe_effects_total"], v["benign_completed"], v["benign_runs"], v["completion_rate"], ci(v["completion_ci"]), v["benign_refused"], v["benign_stale_retries"],
                   ("%d/%d" % (v["prediction_exact"], v["prediction_n"])) if v["prediction_n"] else "—", v["ms_p50"], v["ms_p95"], v["ms_p99"], v["benign_completions_per_s"]))
    L += ["", "* `acl`: the agent may write the table, so the operation is simply run. `dryrun`: a preview is computed and logged, then the operation runs unconditionally (no contract, binding, or commit-time check). `llm_preview`: a **scripted surface-form estimator, not a language model**, approves when its row estimate is within the threshold.",
          "* A09 (policy revision changed after preflight) and A10 (preflight expired) count as unsafe for systems that have no such concept; this is definitional, not a surprising finding.", "* The counterfactual system's 100% rows are on scenarios and contracts written by its author, with expected cardinality supplied. They show the mechanisms work on designed-for cases; they are not a general safety rate.",
          "* The one benign cost: %d legitimate same-row races needed a re-preview (stale retry); latency overhead is the extra clone + receipt work (p50 %s vs %s ms)." % (S["counterfactual"]["benign_stale_retries"], S["counterfactual"]["ms_p50"], S["acl"]["ms_p50"]), "",
          "## Per scenario (outcome across reps: `U<n>` = n out-of-intent effects; `done` = intended effect landed)", "", "| id | kind | adapter | ACL | dry-run | scripted LLM preview | counterfactual | counterfactual refusal |", "|---|---|---|---|---|---|---|---|"]
    for k, v in R["per_scenario"].items(): L.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (k, v["kind"], v["adapter"], ", ".join(v["acl"]), ", ".join(v["dryrun"]), ", ".join(v["llm_preview"]), ", ".join(v["counterfactual"]), "; ".join(v["cf_refusal"]) or "—"))
    L += ["", "## Limits", ""] + ["* " + x for x in R["limits"]] + [""]
    return "\n".join(L)


def main():
    p = os.path.join(ROOT, "docs/evidence/p41/RESULTS.md"); t = results()
    if "--check" in sys.argv:
        ok = os.path.exists(p) and open(p).read() == t; print("p41 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
    open(p, "w").write(t); print("written")


main()
