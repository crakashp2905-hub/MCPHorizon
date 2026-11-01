#!/usr/bin/env python3
"""Generate docs/evidence/p50/RESULTS.md from the write-once results/v2/p50-budget/result.json. `--check` verifies the doc is current."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT); R = json.load(open(os.path.join(ROOT, "results/v2/p50-budget/result.json")))
ci = lambda c: "%d/%d [%.2f, %.2f]" % (c["k"], c["n"], c["ci"][0], c["ci"][1])
DESC = {"none": "no accounting", "per-agent-cap": "each agent has its own counter (a spawned or second agent gets a fresh one)", "eventual-counter": "replicated counter whose view is refreshed every 5 calls", "post-hoc-alert": "effects happen first, an alert fires when a counter passes the cap",
        "single-protocol-limiter": "one counter per carrier (MCP, UTCP, Code Mode, OS)", "per-tool-cap": "one counter per tool name (atomic, but unvalidated cost)", "budget": "HorizonBudget: signed assignment, one SQLite ledger, scope tree with ancestor checks, reservation state machine, idempotency, sink-side cap, reconciliation"}


def results():
    rows = {(r["scenario"], r["system"]): r for r in R["rows"]}; S = R["summary"]
    L = ["# P50 results — HorizonBudget (CANDIDATE)", "", "Generated from `results/v2/p50-budget/result.json` (write-once). %d runs = %d scenarios × %d systems. **Ground truth is the mock receiver's own counters** (units its effects really applied); the ledger, broker and agents are never read by the oracle. `V<n>` marks a run where a task's real total exceeded its signed cap by n units." % (R["runs"], len(R["scenarios"]), len(R["systems"])), "",
         "Intervals are Wilson over scenarios and descriptive: the suite is small and scripted, so they show how little 11 attacks can bound, not a population rate.", "",
         "## Systems", "", "| system | attacks over budget [95% CI] | mean excess units | benign completed | benign over budget | failure scenario over budget | failure: reservations left UNKNOWN | ledger invariant violations |", "|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = S[s]; L.append("| %s | %s | %s | %s | %d | %d | %d | %d |" % (s, ci(v["attack_over_budget"]), v["mean_excess_units"], ci(v["benign_completed"]), v["benign_over_budget"], v["failure_over_budget"], v["failure_unknown_reservations"], v["invariant_violations"]))
    L += ["", "| baseline | what it does |", "|---|---|"] + ["| %s | %s |" % kv for kv in DESC.items()] + ["| budget-no-<mechanism> | full system with one mechanism disabled |", "", "## Per scenario (`ok`, or `V<excess>` over budget; benign: ok / BLOCKED / OVER)", "", "| id | kind | " + " | ".join(R["systems"]) + " |", "|---|---|" + "---|" * len(R["systems"])]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"][s] for s in R["systems"])))
    L += ["", "| id | what happens |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["desc"]) for s in R["scenarios"]]
    L += ["", "## Ablations", "", "| ablation | scenarios that go over budget (excess units) |", "|---|---|"]
    for s in R["systems"]:
        if s.startswith("budget-no-"): L.append("| %s | %s |" % (s, ", ".join("%s (%d)" % (x["id"], rows[(x["id"], s)]["excess"]) for x in R["scenarios"] if rows[(x["id"], s)]["over"]) or "none (redundant in this suite)"))
    L += ["", "Mechanisms with no loss here: %s. `attenuation` is redundant with the ancestor check: a child can hold a larger nominal cap, but every charge is still checked at every ancestor. `budget-no-reconcile` also turns the sink cap off, so it is not an isolated ablation of reconciliation." % (", ".join(R["redundant"]) or "none"), "",
          "## What this does and does not show", "", "- Zero over-budget runs for the full system is a property of these 11 attacks, one failure and 8 benign scenarios, written by the same author as the system. It is not a proof of a hard budget.",
          "- The F01 failure scenario deliberately leaves one reservation UNKNOWN: a request whose response was lost is charged, not refunded, until the receiver confirms what happened. Over-charging is the price of never under-counting.",
          "- The four carriers are codecs that normalise to one (context, tool, args) form; they are not wired into the real MCP, UTCP or Code Mode adapters.",
          "- Costs come from a tool registry, so a tool absent from it is refused. Real external services (LLM tokens, payments) report usage late and sometimes wrongly; see ASSUMPTIONS_AND_LIMITS.md.", ""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p50/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p50 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
