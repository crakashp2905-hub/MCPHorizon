"""P30 latency / utility benchmark (haa-latency). Per-baseline launch latency for a benign task, plus brokered-request task success. Raw timings kept; percentiles derived from raw only."""
from __future__ import annotations
import json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from bench.haa import haa as H, scenarios as SC, run as R

TASKS = {"compute": "print(json.dumps({'v': sum(range(1000))}))", "brokered_get": "print(json.dumps(send('POST','http://approved.test:@OK@/u','hello-approved')))"}

def pct(xs, p):
    xs = sorted(xs); return round(xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))], 4) if xs else None

def summarize(rows):
    out = {}
    for b in sorted({r["baseline"] for r in rows}):
        for t in sorted({r["task"] for r in rows}):
            xs = [r["seconds"] for r in rows if r["baseline"] == b and r["task"] == t]; ok = [r["success"] for r in rows if r["baseline"] == b and r["task"] == t]
            if xs: out[f"{b}/{t}"] = {"n": len(xs), "p50": pct(xs, 50), "p95": pct(xs, 95), "p99": pct(xs, 99), "success": sum(ok), "success_rate": round(sum(ok) / len(ok), 4)}
    return out

def run(n=15):
    d = R.outdir("latency"); rows = []
    with H.World() as w:
        env = R.env_info(w)
        for b in ("B0", "B4", "B5", "B6"):
            for t, code in TASKS.items():
                for i in range(n):
                    c = H.Ctx(b, w); a = w.counts(); t0 = time.perf_counter(); r = c.launch(SC.fmt(code), timeout=12); dt = time.perf_counter() - t0; dl = H.delta(a, w.counts())
                    ok = (r.get("exit") == 0) and (t == "compute" or dl["ok"] > 0)
                    rows.append({"baseline": b, "task": t, "i": i, "seconds": round(dt, 4), "success": bool(ok)})
                print("latency", b, t, flush=True)
    R.write(d, rows, {"per_cell": summarize(rows), "n_per_cell": n, "note": "wall-clock of launch() incl. sandbox setup + (B6) managed executor; single VM, no load"}, {"environment": env}, [])
    print("wrote", d)

if __name__ == "__main__": run()
