#!/usr/bin/env python3
"""Synthetic campaign (P81-01/02): 60 tasks, DAG, EXTERNAL tasks, RC-R-gated tasks, transient failures, budget cap.
SYNTHETIC: tests orchestration policy only; says nothing about live providers. Write-once; --check re-derives."""
import hashlib, json, os, random, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from orchestrator import campaign as C
OUT = os.path.join(ROOT, "results/v2/p84x-campaign")
def simulate(seed=7):
    r = random.Random(seed); tasks = {}
    for i in range(60):
        tid = "S%02d" % i; deps = [("S%02d" % j) for j in r.sample(range(i), min(i, r.randint(0, 2)))] if i else []
        tasks[tid] = {"status": "PENDING", "depends_on": deps, "klass": "EXTERNAL" if i % 15 == 14 else "CODE", "gates": ["GATE:RC-R"] if i >= 50 else []}
    b = C.Budget(5.0, 120.0); rounds = 0; log = {"retries": 0, "budget_refusals": 0, "external_refused": 0}; results = {}
    clk = [0.0]; br = C.Breaker(3, 5.0, lambda: clk[0])
    while rounds < 500:
        rounds += 1; clk[0] += 1.0; rs = C.ready_set(tasks, rcr_signed=False)
        if not rs: break
        tid = rs[0]; t = tasks[tid]
        if t["klass"] == "EXTERNAL":
            ok, _ = C.external_gate("EXTERNAL", None); log["external_refused"] += 1; t["status"] = "WAITING_EXTERNAL"; continue
        if not br.allow(): continue
        if r.random() < 0.2:
            cls = C.classify_failure("timeout"); br.failure()
            if C.retry_delay(cls, 0, rng=r) is not None: log["retries"] += 1
            continue
        br.success()
        if not b.charge(tid, 1.0): log["budget_refusals"] += 1; t["status"] = "NEEDS_APPROVAL"; continue
        t["status"] = "VERIFIED"  # stands in for an independent verifier: SYNTHETIC
    cnt = C.counts(tasks)
    return {"seed": seed, "rounds": rounds, "log": log, "counts": cnt, "spent": b.total,
            "rcr_gated_started": sum(1 for t in tasks.values() if t["gates"] and t["status"] != "PENDING"),
            "note": "SYNTHETIC: 'VERIFIED' here is a simulated verifier outcome inside a policy test, not a real task verdict"}
def main():
    R = simulate(); rf = os.path.join(OUT, "result.json")
    if "--check" in sys.argv:
        old = json.load(open(rf)); print("matches recorded run" if old == R else "MISMATCH"); sys.exit(0 if old == R else 1)
    if os.path.exists(rf): print("write-once: refusing"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); json.dump(R, open(rf, "w"), indent=1, sort_keys=True)
    json.dump({"result_sha256": hashlib.sha256(open(rf, "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print(json.dumps(R, indent=1))
main()
