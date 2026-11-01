#!/usr/bin/env python3
"""Write example evidence bundles (JSON) for inspection: a clean run and a run with an omitted receiver-side record. Tokens are random per run, so these files are examples, not reproducible bytes. `--check` only verifies that the generator still runs."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.evalint import experiment as X, scenarios as SC, evaluator as EV, world as W
OUT = os.path.join(ROOT, "docs/evidence/p49/bundles")
def make(sid):
    sc = next(s for s in SC.SCENARIOS if s["id"] == sid); svc = W.Services(); r = W.Run(W.Deploy(), svc, breach=sc["breach"]); sc["fn"](r); r.finish(); b = r.bundle()
    v = EV.evaluate(b, {"verifier": svc.verifier, "now": r.clock.now() + 1, "label": r.eval_label}); return {"scenario": sid, "bundle": {**b, "streams": {n: [r_ for _, r_ in a] for n, a in b["streams"].items()}}, "verdict": v, "ground_truth": {"violation": r.violation(), "service_record": r.truth}}
if "--check" in sys.argv: [make(s) for s in ("B01", "E09")]; print("ok"); sys.exit(0)
os.makedirs(OUT, exist_ok=True)
for sid in ("B01", "E09"): json.dump(make(sid), open(os.path.join(OUT, sid + ".json"), "w"), indent=1, sort_keys=True, default=list)
print("written")
