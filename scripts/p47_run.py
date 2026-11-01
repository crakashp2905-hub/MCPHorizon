#!/usr/bin/env python3
"""P47 runner: write-once results/v2/p47-incentive/. `--check` verifies the definitions (hard constraints, effect registry, reward constants, scenarios and their plans, systems) match the recorded run."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.incentive import experiment as EX, scenarios as SC, agents as A, contract as C
OUT = os.path.join(ROOT, "results/v2/p47-incentive")


def defs():
    plans = {sid: [[s.ident, s.iota, s.reward, list(s.goal), s.deadline, s.target, [[p.id, p.unaware, p.steps] for p in s.plans]] for s in SC.get(sid, 0)["specs"]] for sid in SC.IDS}
    return {"hard": C.HARD, "effects": C.EFFECTS, "durations": C.DUR, "budgets": [C.ROW_BUDGET, C.CALL_BUDGET], "aliases": [sorted(C.PROD), sorted(C.STAGE)], "systems": list(A.SYSTEMS), "iotas": list(EX.IOTAS), "variants": EX.VARIANTS, "plans": plans,
            "constants": {"W_INSTR": A.W_INSTR, "PENALTY": A.PENALTY, "AUDIT_Q": A.AUDIT_Q, "W_ADV": A.W_ADV, "REPLAN_COST": A.REPLAN_COST, "MAX_ATTEMPTS": A.MAX_ATTEMPTS}, "monitor_cfgs": {k: sorted(v.__dict__.items()) for k, v in A.MCFGS.items()}}


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs(), default=str, sort_keys=True)); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); res = EX.run()
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True, default=str)
    json.dump({"definitions": json.loads(json.dumps(defs(), default=str, sort_keys=True)), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
