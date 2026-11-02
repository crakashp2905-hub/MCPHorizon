#!/usr/bin/env python3
"""Generate docs/implementation/P55_P94_STATUS.md: per-phase mapped/unmapped counts and unmapped tasks by (heuristic) work class. --check verifies currency."""
import json, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); OUT = os.path.join(ROOT, "docs/implementation/P55_P94_STATUS.md")
rows = [json.loads(l) for l in open(os.path.join(ROOT, "spec/task_compiled.jsonl"))]
A = {k for k in json.load(open(os.path.join(ROOT, "spec/acceptance.json"))) if re.match(r"^P\d+-\d\d$", k)}
L = ["# P55–P94 status (generated; CANDIDATE only, nothing VERIFIED)", "",
     "`mapped` = a task has a command in `spec/acceptance.json` that exercises the candidate implementation. It is NOT verification. `unmapped` tasks are not claimed; the work-class split is the compiler's low-confidence heuristic.", "",
     "| phase | tasks | mapped | unmapped | unmapped CODE | unmapped EXPERIMENT | unmapped EXTERNAL | unmapped DECISION | unmapped LIVE_EFFECT |", "|---|---|---|---|---|---|---|---|---|"]
tot = [0, 0]
for p in range(55, 95):
    rs = [r for r in rows if r["phase"] == p]; m = [r for r in rs if r["task_id"] in A]; u = [r for r in rs if r["task_id"] not in A]
    c = lambda k: sum(1 for r in u if r["work_class"] == k)
    tot[0] += len(rs); tot[1] += len(m)
    L.append("| P%d | %d | %d | %d | %d | %d | %d | %d | %d |" % (p, len(rs), len(m), len(u), c("CODE"), c("EXPERIMENT"), c("EXTERNAL"), c("DECISION"), c("LIVE_EFFECT")))
L += ["", "**Total P55–P94: %d tasks, %d mapped, %d unmapped.**" % (tot[0], tot[1], tot[0] - tot[1]), "",
      "P55–P74 (product) are gated on a signed RC-R research handoff, customers, legal terms, pricing validation and pilots that do not exist; they are intentionally not started. Unmapped CODE-class tasks in P75–P94 are not done yet or need real providers, reviewers or sign-offs even if classified CODE."]
t = "\n".join(L) + "\n"
if "--check" in sys.argv: ok = os.path.exists(OUT) and open(OUT).read() == t; print("current" if ok else "STALE"); sys.exit(0 if ok else 1)
open(OUT, "w").write(t); print(t)
