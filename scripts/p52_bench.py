#!/usr/bin/env python3
"""P52-14 overhead: store lookups per operation and wall time of a gateway decision vs the authorize-once baseline. Machine-specific; prints JSON, writes nothing."""
import json, os, platform, statistics, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.temporal import experiment as X, scenarios as SC
from horizon.temporal.world import run_order, explore, World, expand, interleavings

def main(n=int(os.environ.get("N", "300"))):
    S = {e.name: e for e in X.systems()}; sc = [s for s in SC.SCENARIOS if s["id"] == "B01"][0]; out = {}
    for name in ("one-time-check", "op-token-no-object", "temporal"):
        w0 = World(S[name], sc); order = interleavings({k: expand(p, S[name], w0) for k, p in sc["actors"].items()}, [])[0]; lat = []
        for _ in range(n): t = time.perf_counter(); run_order(sc, S[name], order); lat.append(time.perf_counter() - t)
        out[name] = {"scenario_B01_ms": {"median": round(statistics.median(lat) * 1000, 3), "p99": round(sorted(lat)[int(len(lat) * .99)] * 1000, 3)}}
    print(json.dumps({"machine": platform.platform(), "python": platform.python_version(), "n": n, "systems": out, "note": "includes in-memory SQLite world construction and the approval; compare systems with each other, not as absolute gateway cost"}, indent=1))

main()
