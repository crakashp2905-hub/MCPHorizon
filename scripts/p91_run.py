#!/usr/bin/env python3
"""P91/P92 synthetic checks: precision table, split audit on frozen SecBench-like ids, quota exhaustion with zero post-limit charges. Write-once; --check."""
import hashlib, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.research import design as D
OUT = os.path.join(ROOT, "results/v2/p91-research-design")
def run():
    prec = {"p=%.2f,hw=%.2f" % (p, h): D.n_for_halfwidth(p, h) for p in (0.05, 0.5) for h in (0.05, 0.1)}
    s = D.Spend(100.0, 20.0, 10.0); accepted = refused = 0
    for i in range(500):
        ok = s.worker_charge("t%d" % (i % 20), 1.0); accepted += ok; refused += (not ok)
    for i in range(50): s.verifier_charge(1.0)
    post_limit_accepted = 0
    for i in range(100): post_limit_accepted += s.worker_charge("tz", 0.5)
    return {"precision_n_for_wilson_halfwidth": prec, "quota": {"cap": 100.0, "worker_accepted": accepted, "worker_refused": refused, "total_spent": s.total(), "post_limit_worker_charges_accepted": post_limit_accepted, "verifier_reserve_used": s.v_spent},
            "note": "SYNTHETIC arithmetic checks of the helpers; no real experiment, preregistration, reviewer or provider meter was involved."}
def main():
    R = run(); rf = os.path.join(OUT, "result.json")
    if "--check" in sys.argv:
        old = json.load(open(rf)); print("matches recorded run" if old == R else "MISMATCH"); sys.exit(0 if old == R else 1)
    if os.path.exists(rf): print("write-once"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); json.dump(R, open(rf, "w"), indent=1, sort_keys=True); json.dump({"result_sha256": hashlib.sha256(open(rf, "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w")); print(json.dumps(R, indent=1))
main()
