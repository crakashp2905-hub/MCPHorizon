#!/usr/bin/env python3
"""P38-09: live reproduction of one blocked forbidden effect and its permitted matching workflow, judged ONLY by the independent receiver process's own byte counters (horizon/runtime/receiver.py).
For every scenario in SELECT: B0 (no guard) must show bytes at the unauthorized sink; B6 must show zero there while the permitted workflow still reaches its authorized sink. Needs root (kernel sandbox). Writes docs/evidence/p38/SINK_REPRO.json. Exit 1 if any expectation fails."""
import json, os, sys, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."); sys.path.insert(0, ROOT)
from bench.haa import haa as H, scenarios as SC
SELECT = ["HAA-01", "HAA-02", "HAA-05", "HAA-08"]      # scenarios whose effect oracle IS the receiver process byte counters (not every HAA scenario is: e.g. HAA-03 is judged by another oracle)
def main():
    out = {"schema": "p38-sink-repro-1", "created_unix": int(time.time()), "scenarios": {}}; bad = []
    with H.World() as w:
        for sid in SELECT:
            fn = SC.SCENARIOS[sid]; out["scenarios"][sid] = {}
            for b in ("B0", "B6"):
                c = H.Ctx(b, w); a, k = fn(c); out["scenarios"][sid][b] = {"attack_receiver_delta": a.get("delta"), "attack_effect": a.get("effect"), "attack_denied": a.get("denied"), "control_receiver_delta": k.get("delta"), "control_ok": k.get("ok")}
            r = out["scenarios"][sid]
            if not (r["B0"]["attack_effect"] and not r["B6"]["attack_effect"] and r["B0"]["control_ok"] and r["B6"]["control_ok"]): bad.append(sid)
    out["all_expectations_met"] = not bad; out["failed"] = bad
    json.dump(out, open(os.path.join(ROOT, "docs", "evidence", "p38", "SINK_REPRO.json"), "w"), indent=1, sort_keys=True); print(json.dumps({"met": not bad, "failed": bad}))
    sys.exit(1 if bad else 0)
main()
