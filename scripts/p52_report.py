#!/usr/bin/env python3
"""Generate docs/evidence/p52/RESULTS.md from the write-once results. `--check` verifies the doc is current."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
D = os.path.join(ROOT, "results/v2/p52-temporal"); R = json.load(open(os.path.join(D, "result.json"))); I = json.load(open(os.path.join(D, "invariants.json")))
OUT = os.path.join(ROOT, "docs/evidence/p52/RESULTS.md")
ci = lambda c: "%d/%d [%.2f, %.2f]" % (c["k"], c["n"], c["ci"][0], c["ci"][1])
DESC = {"one-time-check": "authorized once when the approval was requested; the effect only needs the approval to exist", "jwt-expiry": "signature and expiry only, on the worker's own clock; no state binding, no single use",
        "op-token-no-object": "token bound to operation, actor and host, single use, authoritative expiry; not bound to the object, its version or the policy", "restrictive-rule": "hand-written: token at most 5 s old, single use, never for queued work",
        "last-write-wins": "the full gateway but object writes are unconditional", "temporal": "HorizonTemporal: state vector bound into a short-lived approval, revalidated at the effect boundary inside one transaction, destination re-resolved and pinned, redirects checked, fail closed"}

def results():
    S = R["summary"]
    L = ["# P52 results — HorizonTemporal (CANDIDATE)", "", "Generated from `results/v2/p52-temporal/result.json` (write-once). **Ground truth is the effect service's own record** (a snapshot of live state at the moment of each effect, the approval ledger and the ordered event log), judged by an independent oracle that never calls the gateway. Every scenario is run under **every interleaving** of its actors' steps, so a result is a statement about all orders of that scenario, not a sample. Verified effects (a prohibited effect really happened) and UNKNOWN (the gateway could not know) are reported separately.", "",
         "Intervals are Wilson over scenarios and descriptive: the suite is small, scripted and written by the same author as the gateway.", "", "## %d runs = %d scenarios × %d systems (all interleavings)" % (R["runs"], len(R["scenarios"]), len(R["systems"])), "",
         "| system | attacks with a violating interleaving [95% CI] | violating / all attack interleavings | benign completed in every interleaving [95% CI] | benign with a stale effect | benign not completed | unjustified re-approvals | unsupported paths violated | of those, flagged UNKNOWN | revoked approval + feed offline: effect | benign + feed offline |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = S[s]; L.append("| %s | %s | %d/%d | %s | %s | %s | %d | %s | %d | %s | %s |" % (s, ci(v["attacks_with_a_violating_interleaving"]), v["violating_interleavings"][0], v["violating_interleavings"][1], ci(v["benign_completed_in_every_interleaving"]), ", ".join(v["benign_with_a_stale_effect"]) or "none", ", ".join(v["benign_not_completed"]) or "none",
                                                                          v["benign_unjustified_reapprovals"], ci(v["unsupported_paths_violated"]), v["unsupported_paths_violated_and_flagged_unknown"], "yes" if v["telemetry_offline_attack_violated"] else "no", "completed" if v["telemetry_offline_benign_completed"] else "blocked"))
    L += ["", "| baseline / system | what it does |", "|---|---|"] + ["| %s | %s |" % kv for kv in DESC.items()] + ["| temporal-no-<mechanism> | full gateway with one mechanism disabled |", "",
          "Re-approvals are counted separately: a re-approval after a real change (B02, B10) is justified and expected; one on an unchanged state would be a false block (column `unjustified re-approvals`).", "",
          "## Per scenario (`V a/b` = a of b interleavings produce a violation; benign: ok / BLOCKED, `*` = a stale effect occurred in some order; `(UNKNOWN)` = the system flagged it)", "", "| id | kind | " + " | ".join(R["systems"][:6]) + " |", "|---|---|" + "---|" * 6]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"][s] for s in R["systems"][:6])))
    L += ["", "| id | what happens |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["desc"]) for s in R["scenarios"]]
    L += ["", "## Ablations: where the outcome changes against the full gateway", "", "| ablation | scenarios that change (outcome → outcome) |", "|---|---|"]
    for s in R["systems"]:
        if not s.startswith("temporal-no-"): continue
        ch = [x["id"] for x in R["scenarios"] if R["per_scenario"][x["id"]]["systems"][s] != R["per_scenario"][x["id"]]["systems"]["temporal"]]
        L.append("| %s | %s |" % (s, "; ".join("%s: %s→%s" % (i, R["per_scenario"][i]["systems"]["temporal"], R["per_scenario"][i]["systems"][s]) for i in ch) or "none (redundant in this suite)"))
    L += ["", "Redundant here: %s. Several mechanisms overlap: the object-version check subsumes class, content and id changes, the policy re-evaluation subsumes the slice digest and the grant check, and the principal check overlaps the grant check. Redundancy is the defence in depth the design intends, not evidence that a mechanism is unnecessary; `last-write-wins` is the ablation of compare-and-swap writes (A10)." % ", ".join(R["redundant"]), "",
          "## Machine-checkable invariants (`results/v2/p52-temporal/invariants.json`)", "", "| id | name | holds on the suite | scope |", "|---|---|---|---|"] + ["| %s | %s | %s | %s |" % (i["id"], i["name"], i["holds_on_suite"], i["scope"]) for i in I["invariants"]] + ["", "Statements:", ""] + ["- **%s** %s" % (i["id"], i["statement"]) for i in I["invariants"]]
    L += ["", "## Recorded counterexample interleavings (%d)" % len(R["counterexamples"]), "", "First violating interleaving per (attack, baseline), plus the unsupported-sink paths where even the full gateway cannot prevent the effect (it flags UNKNOWN). Full list in `invariants.json`.", "", "| scenario | system | interleaving | oracle reasons |", "|---|---|---|---|"]
    for c in R["counterexamples"][:40]: L.append("| %s | %s | %s | %s |" % (c["scenario"], c["system"], " → ".join(c["order"]), "; ".join(",".join(v["reasons"]) for v in c["violations"])))
    L += ["", "## What this does and does not show", "", "- The UNKNOWN flag on U01/U02 is produced by the sink interface (a sink that cannot be conditioned, or defers, reports UNKNOWN to every caller), so the baselines also carry it in this table; the claim for the gateway is only that it never reports such an effect as a verified success. Baselines differ in whether they would have prevented anything else.", "- Zero violating interleavings for the full gateway is a property of 13 attack scenarios, each with 1–4 interleavings, written by the same author. It is not a proof (the document `ASSUMPTIONS_AND_LIMITS.md` states the scoped theorem and its assumptions).",
          "- Where the effect cannot be made atomic with the check (U01) or is applied later by an external provider (U02), a violating interleaving exists even for the full gateway. It is reported UNKNOWN, not prevented. This is the constraint P52-15 asks to be reported.",
          "- Overhead: `scripts/p52_bench.py` (machine-specific, not recorded). Each decision costs a bounded number of local store reads and one signature verification; the model measures relative cost only.", "- Nothing here is promoted beyond CANDIDATE."]
    return "\n".join(L) + "\n"

if "--check" in sys.argv:
    cur = open(OUT).read() if os.path.exists(OUT) else ""; ok = cur == results(); print("RESULTS.md is current" if ok else "RESULTS.md is STALE"); sys.exit(0 if ok else 1)
open(OUT, "w").write(results()); print("written")
