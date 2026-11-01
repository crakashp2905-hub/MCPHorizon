#!/usr/bin/env python3
"""P51-14 latency of the model guard decision and of a full model scenario. Machine-specific; prints JSON, writes nothing."""
import json, os, platform, statistics, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.vision import experiment as X, scenarios as SC, guard as G
from horizon.hpolicy.authority import HorizonPolicy

def main(n=int(os.environ.get("N", "2000"))):
    clk = lambda: 1_000_000.0; A = HorizonPolicy("pol-1", clock=clk); g = G.Guard(A.verifier(), clk); task = SC.task()
    b = {"instrumented": True, "effect": {"kind": "SUBMIT", "dest": "https://app.test", "data": "plain", "resource": "/p"}, "reported": {}, "element": {"id": "e", "digest": "d"}, "frame_origin": "https://app.test", "top_origin": "https://app.test", "input_digest": "i", "tab": "t1"}
    act = {"op": "click", "intent": "e", "observed": "d", "tab": "t1"}; lat = []
    for _ in range(n): t = time.perf_counter(); g.decide(act, b, task); lat.append(time.perf_counter() - t)
    q = lambda v, f: round(sorted(v)[min(len(v) - 1, int(len(v) * f))] * 1e6, 1)
    sc = [s for s in SC.SCENARIOS if s["id"] == "B01"][0]; sl = []
    for _ in range(200): t = time.perf_counter(); X.run_one(sc, "vision-guard", "guard", G.GCfg()); sl.append(time.perf_counter() - t)
    print(json.dumps({"machine": platform.platform(), "python": platform.python_version(), "n": n, "guard_decide_us": {"median": q(lat, .5), "p99": q(lat, .99)}, "model_scenario_B01_ms": {"median": round(statistics.median(sl) * 1000, 3), "p99": round(sorted(sl)[int(len(sl) * .99)] * 1000, 3)},
                      "note": "model only; real-browser per-action probe cost is measured by scripts/p51_browser.py (machine-specific)"}, indent=1))

main()
