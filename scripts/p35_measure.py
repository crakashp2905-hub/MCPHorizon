#!/usr/bin/env python3
"""P35-12: measure collector throughput, drop rate and clock uncertainty under concurrent agents (local, single VM; numbers are machine-specific). Writes docs/evidence/p35/MEASUREMENTS.json (overwrites; it is a measurement, not a result record)."""
import json, os, sys, tempfile, threading, time, platform
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.telemetry import collector as C
def ev(n, run): return C.make_event(principal="agent", tool="http_post", args={"u": n}, decision="allow", policy_hash="sha256:p", execution_id=f"x{n}", run_id=run, status="done")
def one(N, M):
    with tempfile.TemporaryDirectory() as d, C.CollectorProcess(d) as cp:
        sent = [0] * N; fail = [0] * N
        def agent(a):
            cl = cp.client()
            for i in range(M):
                try: cl.emit(ev(f"{a}-{i}", f"r{a}")); sent[a] += 1
                except C.CollectorDown: fail[a] += 1
        t0 = time.time(); th = [threading.Thread(target=agent, args=(a,)) for a in range(N)]; [t.start() for t in th]; [t.join() for t in th]; dt = time.time() - t0
        log = cp.client().export(); v = C.verify_chain(log, cp.pub); rs = log["records"]
        drift = max(abs((rs[i + 1]["event"]["wall"] - rs[i]["event"]["wall"]) - (rs[i + 1]["event"]["mono_ns"] - rs[i]["event"]["mono_ns"]) / 1e9) for i in range(len(rs) - 1))
        return {"agents": N, "events_each": M, "attempted": N * M, "recorded": v["records"], "send_failures": sum(fail), "drop_rate": round(1 - v["records"] / (N * M), 6), "chain_ok": v["ok"], "events_per_s": round(N * M / dt, 1), "max_wall_vs_mono_drift_s": round(drift, 6)}
res = {"machine": platform.platform(), "python": platform.python_version(), "note": "single VM, unix-socket collector in a separate process, ack-before-effect; not a capacity claim", "runs": [one(n, 200) for n in (1, 4, 8, 16)]}
json.dump(res, open(os.path.join(ROOT, "docs/evidence/p35/MEASUREMENTS.json"), "w"), indent=1); print(json.dumps(res["runs"]))
