#!/usr/bin/env python3
"""Generate docs/evidence/p83/RESULTS.md from results/v2/p83-plan/result.json; --check verifies it is current."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = json.load(open(os.path.join(ROOT, "results/v2/p83-plan/result.json"))); OUT = os.path.join(ROOT, "docs/evidence/p83/RESULTS.md")
L = ["# P83 results — plan extensions (CANDIDATE)", "", "Generated from `results/v2/p83-plan/result.json`. Extends the existing compiler (`scripts/compile_plan.py`).", "",
     "- Tasks compiled: **%d** across **%d** phases; pinned source-span map `spec/source_spans.json` matches the spec: **%s** (sha256 `%s`)." % (R["tasks"], R["phases"], R["span_map_matches_spec"], R["span_map_sha"]),
     "- Tasks naming repository paths: %d; of which with at least one MISSING referenced path: **%d** (listed honestly, not hidden)." % (R["tasks_with_path_refs"], R["tasks_with_missing_refs"]),
     "- Work classes: " + ", ".join("%s=%d" % kv for kv in sorted(R["work_classes"].items())) + " (classification is heuristic, low confidence, from compile_plan).",
     "- High-risk tasks: %d; with exact acceptance commands: %d; with a **named effect oracle: %d**; gaps: **%d**. P83-13 is therefore NOT claimed." % (R["high_risk"], R["high_risk_with_commands"], R["high_risk_with_named_oracle"], R["high_risk_gap_count"]),
     "", "Not done here (need people): P83-06 cryptographically signed dependency review, P83-16 independent maintainer review, P83-18 CG-01–04 sign-off."]
t = "\n".join(L) + "\n"
if "--check" in sys.argv:
    ok = os.path.exists(OUT) and open(OUT).read() == t; print("current" if ok else "STALE"); sys.exit(0 if ok else 1)
open(OUT, "w").write(t); print("written")
