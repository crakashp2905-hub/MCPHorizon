#!/usr/bin/env python3
"""Generate docs/evidence/p53/RESULTS.md from the write-once results. `--check` verifies the doc is current."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
D = os.path.join(ROOT, "results/v2/p53-continuity"); R = json.load(open(os.path.join(D, "result.json"))); T = json.load(open(os.path.join(D, "trust_gaps.json")))
OUT = os.path.join(ROOT, "docs/evidence/p53/RESULTS.md")
ci = lambda c: "%d/%d [%.2f, %.2f]" % (c["k"], c["n"], c["ci"][0], c["ci"][1])
from horizon.continuity.migrate import Baseline
DESC = {**Baseline.DESC, "continuity": "HorizonContinuity: signed single-use envelope (principal chain, labels, obligations, budget pointers, approvals with expiry, credential handles only), fresh identity-bound runtime attestation that must cover every mandatory control, no-widening check against the authoritative grant, revocation check (fail closed), freeze, in-flight drain, broker re-issuance, rollback or safe-stop"}

def results():
    S = R["summary"]
    L = ["# P53 results — HorizonContinuity (CANDIDATE)", "", "Generated from `results/v2/p53-continuity/result.json` (write-once). **Ground truth is the independent operation receiver's log** (every effect that really left a runtime, with the true time) judged by an oracle that reads only that log, the authoritative grants and label truth, the approval and revocation records, and the immutable source contract K_A. No system's decision is read by the oracle. Verified prohibited effects and UNKNOWN (the module could not establish the receiving environment) are reported separately.", "",
         "Intervals are Wilson over scenarios and descriptive: the suite is small, scripted and written by the same author as the module and the baselines.", "", "## %d runs = %d scenarios × %d systems" % (R["runs"], len(R["scenarios"]), len(R["systems"])), "",
         "| system | attacks with a prohibited effect [95% CI] | benign completed [95% CI] | benign migrated | benign migrations denied that were not justified | policy-continuity coverage (final runtime covers K_A) | lost obligation / label | revocation not propagated | unsupported paths with an effect | flagged UNKNOWN | unflagged with an effect | revoked + feed offline: effect | benign + feed offline |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = S[s]; L.append("| %s | %s | %s | %d/%d | %s | %d/%d | %s | %s | %s | %d | %s | %s | %s |" % (s, ci(v["attacks_with_a_prohibited_effect"]), ci(v["benign_completed"]), v["benign_migrated"]["k"], v["benign_migrated"]["n"], ", ".join(v["benign_unjustified_denials"]) or "none", v["policy_continuity_coverage"]["k"], v["policy_continuity_coverage"]["n"], ", ".join(v["lost_obligation_or_label"]) or "none", ", ".join(v["revocation_not_propagated"]) or "none",
                                                                          ci(v["unsupported_paths_with_a_prohibited_effect"]), v["unsupported_flagged_unknown"], ", ".join(v["unsupported_unflagged_with_effect"]) or "none", "yes" if v["telemetry_offline_attack_violated"] else "no", "completed" if v["telemetry_offline_benign_completed"] else "blocked"))
    L += ["", "| baseline / system | what it does |", "|---|---|"] + ["| %s | %s |" % kv for kv in DESC.items()] + ["| continuity-no-<mechanism> | full module with one mechanism disabled |", "",
          "`restrictive-rule` completes most benign tasks only because the task stays at the source: it migrates to a different-vendor runtime never. `benign migrated` and `unjustified denials` show that cost. B07 is a justified denial (the target really cannot meet the contract); the task continues at the source with unchanged authority.", "",
          "## Per scenario (`V:` = prohibited effect kinds that reached the receiver; benign: ok / BLOCKED; parentheses = migration outcome when it was not MIGRATED)", "", "| id | kind | " + " | ".join(R["systems"][:7]) + " |", "|---|---|" + "---|" * 7]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"][s] for s in R["systems"][:7])))
    L += ["", "| id | target | what happens |", "|---|---|---|"] + ["| %s | %s | %s |" % (s["id"], s["target"], s["desc"]) for s in R["scenarios"]]
    L += ["", "## Ablations: where the outcome changes against the full module", "", "| ablation | scenarios that change (outcome → outcome) |", "|---|---|"]
    for s in R["systems"]:
        if not s.startswith("continuity-no-"): continue
        ch = [x["id"] for x in R["scenarios"] if R["per_scenario"][x["id"]]["systems"][s] != R["per_scenario"][x["id"]]["systems"]["continuity"]]
        L.append("| %s | %s |" % (s, "; ".join("%s: %s→%s" % (i, R["per_scenario"][i]["systems"]["continuity"], R["per_scenario"][i]["systems"][s]) for i in ch) or "none (redundant in this suite)"))
    L += ["", "Redundant here: %s. Overlaps are real: the signature, the schema and the no-widening check each catch A06/A07; the nonce and the shared ledger each stop A08; the target's own revocation, approval and budget checks back up the admission checks; broker re-issuance and freezing each stop A14 on their own. Redundancy is defence in depth, not evidence that a mechanism is unnecessary. `tests.p53.test_continuity.EachMechanismAlone` exercises each with its overlapping mechanisms off." % ", ".join(R["redundant"]), "",
          "## Verified continuity properties and supported targets (`results/v2/p53-continuity/trust_gaps.json`)", "", "| id | property | holds on the suite |", "|---|---|---|"] + ["| %s | %s | %s |" % (p["id"], p["statement"], p["holds_on_suite"]) for p in T["properties"]] + ["", "| runtime kind | admitted for the task contract | attestable | sinks mediated | carrier |", "|---|---|---|---|---|"] + \
         ["| %s | %s | %s | %s | %s |" % (k, v["admitted_for_the_task_contract"], v["attestable"], v["sinks_mediated"], v["carrier"]) for k, v in sorted(T["supported_targets"].items())] + ["", "## Known trust gaps", "", "| id | gap | evidence |", "|---|---|---|"] + ["| %s | %s | %s |" % (g["id"], g["gap"], g["evidence"]) for g in T["trust_gaps"]]
    L += ["", "## Recorded counterexamples (%d)" % len(R["counterexamples"]), "", "| scenario | system | oracle kinds |", "|---|---|---|"] + ["| %s | %s | %s |" % (c["scenario"], c["system"], "; ".join(",".join(v["kinds"]) for v in c["violations"])) for c in R["counterexamples"]][:70]
    L += ["", "## What this does and does not show", "", "- Zero prohibited effects for the full module is a property of 14 attacks written by the same author, against baselines modelled by the same author. It is not a proof; `ASSUMPTIONS_AND_LIMITS.md` states the scoped theorem.",
          "- U02 (the attestor is deceived) is a prohibited effect that the module does not prevent and does not flag. It is the trust gap G1, outside the assumption that attestation is trustworthy, and is shown rather than hidden.",
          "- U01 and U03 are denied and reported UNKNOWN; the baselines migrate anyway and the agent's next step reaches the receiver.",
          "- Handoff latency: `scripts/p53_bench.py` (machine-specific, not recorded); model-only, no real runtime start-up.", "- Nothing here is promoted beyond CANDIDATE."]
    return "\n".join(L) + "\n"

if "--check" in sys.argv:
    cur = open(OUT).read() if os.path.exists(OUT) else ""; ok = cur == results(); print("RESULTS.md is current" if ok else "RESULTS.md is STALE"); sys.exit(0 if ok else 1)
open(OUT, "w").write(results()); print("written")
