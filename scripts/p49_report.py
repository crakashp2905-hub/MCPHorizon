#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT); R = json.load(open(os.path.join(ROOT, "results/v2/p49-evalint/result.json")))
from horizon.evalint import world as W
ci = lambda c: "%d/%d [%.2f, %.2f]" % (c["k"], c["n"], c["ci"][0], c["ci"][1])
DESC = {"self-report": "the agent's own pass/fail claim", "app-logging": "grades from the agent-writable application log / transcript", "shared-grader": "ordinary grader in the agent's workspace: compares the submitted answer with a label file the agent can read and write",
        "audit-no-root-sep": "hash-chained audit log of tool events kept where the agent can write (no signatures, no seal, no second source)", "evalint": "HorizonEvalIntegrity: separated zones, three independently signed collector streams, manifest, reconciliation, seals"}


def results():
    rows = {(r["scenario"], r["system"]): r for r in R["rows"]}; S = R["summary"]
    L = ["# P49 results — HorizonEvalIntegrity (CANDIDATE)", "", "Generated from `results/v2/p49-evalint/result.json` (write-once). %d runs = %d scenarios × %d systems. Deterministic, so intervals are Wilson over scenarios and descriptive. **Ground truth is the mock service's own record of what happened** (what the receiver actually did), which no evaluator or collector reads; `*` in the matrix marks runs where a prohibited effect really occurred." % (R["runs"], len(R["scenarios"]), len(R["systems"])), "",
         "**Verdicts.** PASS only when every critical dependency verifies. FAIL = a verified prohibited effect. UNVERIFIABLE = a required dependency lacks integrity or contradicts another; PASS is never substituted. *False PASS* = PASS on a run where the prohibited effect occurred. Verified effects and unknowns are counted separately in `result.json` (`rows`) and in the tests.", "",
         "## Systems (P49-14, 15)", "", "| system | false PASS under compromise [95% CI] | UNVERIFIABLE under compromise | tamper discovery | benign (clean) PASS | benign UNVERIFIABLE | benign false FAIL | honest violation reported | label-compromise successes | all-collectors-compromised (boundary) | benign evidence records / bytes |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = S[s]; L.append("| %s | %s | %d/%d | %s | %s | %d | %d | %s | %d | %s | %s / %s |" % (s, ci(v["false_pass_under_compromise"]), v["unverifiable_under_compromise"]["k"], v["unverifiable_under_compromise"]["n"], ci(v["tamper_discovery"]), ci(v["benign_pass"]), v["benign_unverifiable"], v["benign_false_fail"], ",".join(v["honest_violation_reported_fail"]), v["label_cheat_successes"], ",".join(v["boundary_verdict"]), v["mean_records"], v["mean_bytes"]))
    L += ["", "| baseline / system | what it does |", "|---|---|"] + ["| %s | %s |" % kv for kv in DESC.items()] + ["| evalint-no-<mechanism> | full system with one mechanism disabled |", "| evalint-no-label-acl, evalint-no-os-audit | full system with the label store inside the agent workspace / with file-and-channel auditing off |", "",
          "*Compromise* runs are the attack and trusted-collector-failure scenarios in which a prohibited effect really occurred. *Tamper discovery* = the run was not PASS or carried a tamper flag, over attack scenarios that declare a tamper. Overhead is deterministic evidence volume (records and bytes per benign run), not wall time.", "",
          "## Per scenario (verdict; `*` = prohibited effect really occurred)", "", "| id | kind | " + " | ".join(R["systems"]) + " |", "|---|---|" + "---|" * len(R["systems"])]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"][s] for s in R["systems"])))
    L += ["", "| id | what happens |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["desc"]) for s in R["scenarios"]]
    L += ["", "## Ablations: where the verdict changes against the full system", "", "| ablation | scenarios whose verdict differs from `evalint` |", "|---|---|"]
    redundant = []
    for s in R["systems"]:
        if not s.startswith("evalint-"): continue
        top = lambda f: {x for x in f if ":" not in x}
        diff = []
        for sc in R["scenarios"]:
            a, b = rows[(sc["id"], "evalint")], rows[(sc["id"], s)]
            if a["verdict"] != b["verdict"]: diff.append("%s: %s→%s" % (sc["id"], a["verdict"], b["verdict"]))
            elif top(a["flags"]) != top(b["flags"]): diff.append("%s: %s unchanged, flags %s" % (sc["id"], a["verdict"], "lost " + ",".join(sorted(top(a["flags"]) - top(b["flags"]))) if top(a["flags"]) - top(b["flags"]) else "gained " + ",".join(sorted(top(b["flags"]) - top(a["flags"])))))
        L.append("| %s | %s |" % (s, "; ".join(diff) or "none (redundant in this suite)")); redundant += [s] if not diff else []
    L += ["", "Mechanisms with no verdict or flag change here: %s. They are layered defences with unit tests, not shown necessary by the experiment." % (", ".join(redundant) or "none"), "",
          "## Self-reported versus independently verified (P49-14)", "", "| scenario | kind | agent self-report | HorizonEvalIntegrity | prohibited effect really occurred |", "|---|---|---|---|---|"]
    for sc in R["scenarios"]: r1, r2 = rows[(sc["id"], "self-report")], rows[(sc["id"], "evalint")]; L.append("| %s | %s | %s | %s | %s |" % (sc["id"], sc["kind"], r1["verdict"], r2["verdict"], "yes" if r2["violation"] else "no"))
    L += ["", "## Trust zones (P49-01)", "", "```", "EVALUATOR  (labels, scoring state, manifest key, verdict)  <- reads only: signed manifest + 3 signed streams", "   ^ verifies with public keys only", "COLLECTORS  tool (enforcer side) | sink (receiver side) | os (kernel side)   each: own key, own stream, hash-chain, seal", "   ^ observe", "ENFORCER (broker) --mediates--> MOCK SERVICE        AGENT(S): workspace + own transcript only; distinct uids", "```", "",
          "| zone | holds | agent access |", "|---|---|---|"] + ["| %s | %s | %s |" % (k, ", ".join(v["holds"]), v["agent_access"]) for k, v in W.TRUST_ZONES.items()]
    L += ["", "Threats modelled: " + "; ".join(W.THREATS) + ". Outside the stated assumptions: " + "; ".join(W.OUT_OF_SCOPE) + ".", "",
          "## What this does and does not show", "", "- Zero false PASS for the full system is a property of these 17 compromise/failure scenarios; the boundary scenario X01 is a **false PASS by design**: if all three collectors lie consistently the evaluator cannot know. That is the stated limit of the trust root.",
          "- Zones are modelled by explicit access rules (`Deploy`); the claim that the evaluator zone is unreachable from a sandboxed agent is checked against the real kernel only in `KernelSeparation` tests, which are skipped (and reported unsupported) on hosts without root and Landlock.",
          "- Agents are scripted; collectors are one author's code. Storage-write attacks (E06–E08, E13) assume the storage ACL has already failed, to test the cryptographic layer separately from the ACL layer.", ""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p49/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p49 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
