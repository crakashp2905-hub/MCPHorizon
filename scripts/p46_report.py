#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = json.load(open(os.path.join(ROOT, "results/v2/p46-downgrade/result.json")))
ci = lambda c: "%d/%d = %.3f [%.3f, %.3f]" % (c["k"], c["n"], c["rate"], c["ci"][0], c["ci"][1]) if c and c.get("n") else "—"
DESC = {"fixed-order": "try the planner's candidates in order (no guarantee check)", "static-allowlist": "design-time endpoint allowlist (includes endpoints approved for other tasks; a newly added upgraded endpoint is not on it)", "tool-name-only": "any endpoint offering the same tool name",
        "scripted-suggest": "deterministic stand-in for an LLM suggester: ranks by claimed similarity, no guarantee check (no LLM was run)", "guard": "HorizonDowngrade: attested profiles, partial-order floor check, bound floor, bound approvals, clamped credentials, invalidating cache",
        "guard-no-attestation": "ablation: trusts unattested profile claims", "guard-no-cache-invalidation": "ablation: cached verdicts keyed by endpoint+floor, never invalidated", "guard-no-floor-binding": "ablation: delegated floor accepted as presented",
        "guard-no-credential-controls": "ablation: credentials not clamped to the floor's scope", "guard-unknown-as-satisfied": "ablation: UNKNOWN treated as meeting the requirement", "guard-scalar-score": "ablation: single numeric score instead of the partial order",
        "guard-no-incomparable-review": "ablation: incomparable trade-offs admitted", "guard-no-approval-binding": "ablation: approval not bound to the exact action"}


def results():
    L = ["# P46 results — HorizonDowngrade (CANDIDATE)", "", "Generated from `results/v2/p46-downgrade/result.json` (write-once). %d runs = %d scenarios × %d systems × %d repetitions, against live loopback endpoints (separate process; TLS 1.2/1.3 and plaintext listeners, enforced authn, audit sink, side sink). The primary endpoint is failed by a deterministic injector (timeout / 5xx / dropped connection, seed in the manifest)." % (R["runs"], len(R["scenarios"]), len(R["systems"]), R["reps"]), "",
         "**Unauthorized effect** = the independent oracle, reading only the endpoint/audit/side-sink journals and probe-calibrated authentication, finds a request that carried the test canary to an endpoint weaker than the TRUE task floor (transport, region, scope, authentication, audit entry, egress). Approved actions are excluded. Verified effects and unknowns are reported separately: the `UNKNOWN dims` column counts guarantee dimensions the guard could not verify.", "",
         "## Systems", "", "| system | attack runs with an unauthorized effect [95% CI] | attack runs completed safely | attack runs stopped or sent to review | benign runs completed [95% CI] | benign false blocks | benign runs with a violation | median / p95 recovery ms | reviews requested | UNKNOWN dims |", "|---|---|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = R["summary"][s]; L.append("| %s | %s | %s | %s | %s | %s | %s | %s / %s | %d | %d |" % (s, ci(v["attack_runs_with_unauthorized_effect"]), ci(v["attack_runs_completed_safely"]), ci(v["attack_runs_stopped_without_completion"]), ci(v["benign_completed"]), ci(v["benign_false_blocks"]), ci(v["benign_with_violation"]), v["median_recovery_ms"], v["p95_recovery_ms"], v["review_requested"], v["unknown_dims_seen"]))
    L += ["", "| system | what it does |", "|---|---|"] + ["| %s | %s |" % (k, v) for k, v in DESC.items()]
    L += ["", "## Per scenario (attacks: V<n> = runs, of %d, with an unauthorized effect, then the endpoint actually used; benign: completed without violation / runs)" % R["reps"], "", "| id | kind | " + " | ".join(R["systems"]) + " |", "|---|---|" + "---|" * len(R["systems"])]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"].get(s, "") for s in R["systems"])))
    L += ["", "| id | what it does |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["note"]) for s in R["scenarios"]]
    L += ["", "## Cache invalidation (P46-12)", "", "A verdict is cached warm, then the trigger happens, then the same candidate is re-evaluated. `stale ADMIT` = the cached admit survived a change that should have removed it.", "", "| system | trigger | before | warm cache | after | stale ADMIT |", "|---|---|---|---|---|---|"]
    for sy, d in R["cache"].items():
        for t, v in d.items(): L.append("| %s | %s | %s | %s | %s | %s |" % (sy, t, v["before"], v["warm_cache"], v["after"], v["stale_admit"]))
    L += ["", "The ablation's cache is keyed by endpoint, policy version, floor and scope, so a policy-version change still misses it (shown as not stale); profile changes and revocations do not.", ""]
    p = R["parity"]; L += ["## Adapter parity (P46-07)", "", "The same scenario, system and seed through the UTCP transport, MCP `tools/call` JSON-RPC and Code Mode (generated code that calls `call(id)` for each fallback; every call re-checks the guard). Identical outcome and oracle verdict across adapters in every one of %d cells: **%s**." % (p["cells"], p["identical_across_adapters"]), "", "| scenario | system | utcp | mcp | codemode |", "|---|---|---|---|---|"]
    cells = {}
    for r in p["rows"]: cells.setdefault((r["id"], r["system"]), {})[r["adapter"]] = "%s%s" % (r["used"] or "stopped", " ⚠ violation" if r["violated"] else "")
    for (i, s), v in cells.items(): L.append("| %s | %s | %s | %s | %s |" % (i, s, v["utcp"], v["mcp"], v["codemode"]))
    L += ["", "## What this does and does not show", "", "- Every attack has a safe alternative or a stop available; the guard's zero is a property of these twelve scenarios, not a bound. The oracle, endpoints, profiles and baselines are the same author's.",
          "- `guard-no-credential-controls` shows no difference: the engine's own requested-scope check already stops scope escalation in these scenarios, so the broker clamp is defence in depth (unit-tested directly).",
          "- Attested profiles can be wrong. The guard trusts an attestation as evidence of what the endpoint claims; a lying but attested endpoint is outside the model (see `ASSUMPTIONS_AND_LIMITS.md`).",
          "- `scripted-suggest` is a deterministic stand-in, not an LLM. No live model was run (L3 not met).", ""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p46/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p46 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
