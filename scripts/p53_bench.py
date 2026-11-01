#!/usr/bin/env python3
"""P53 handoff latency (migration admission + resume, model only). Machine-specific; prints JSON, writes nothing."""
import json, os, platform, statistics, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.continuity import experiment as X, scenarios as SC
from horizon.continuity.world import World

def main(n=int(os.environ.get("N", "200"))):
    S = {e.name: e for e in X.systems()}; sc = [s for s in SC.SCENARIOS if s["id"] == "B01"][0]; out = {}
    for name in ("state-serialization", "container-snapshot", "continuity"):
        lat = []
        for _ in range(n): w = World(S[name], sc); t = time.perf_counter(); S[name].migrate(w); lat.append(time.perf_counter() - t)
        out[name] = {"migrate_ms": {"median": round(statistics.median(lat) * 1000, 3), "p99": round(sorted(lat)[int(len(lat) * .99)] * 1000, 3)}}
    print(json.dumps({"machine": platform.platform(), "python": platform.python_version(), "n": n, "systems": out, "note": "model only: checkpoint, signature and attestation verification, admission checks and state load; no network, no real runtime start-up"}, indent=1))

main()
