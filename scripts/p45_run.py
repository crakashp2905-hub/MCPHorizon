#!/usr/bin/env python3
"""P45 runner: write-once results/v2/p45-privacy/. `--check` verifies the definitions (scenarios, systems, budgets, mechanism constants) match the recorded run."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.privacy import experiment as EX, scenarios as SC, service as SV, accountant as AC
OUT = os.path.join(ROOT, "results/v2/p45-privacy")
dig = lambda x: hashlib.sha256(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()


def defs():
    return {"scenarios": [(s[0], s[1], s[3]) for s in SC.SCENARIOS], "systems": list(SC.SYSTEMS), "reps": SC.REPS, "budget": {"eps": SC.EPS_B, "delta": SC.DELTA_B, "query_eps": SC.Q_EPS}, "accountants": list(AC.ACCOUNTANTS), "margin": AC.MARGIN, "cap": SV.CAP,
            "dataset_digest": dig([[d.name, d.public, d.bounds, d.min_cell, d.rows[:5]] for d in SC.Env("horizon-basic", 0, __import__("tempfile").mkdtemp()).datasets])}


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs(), default=str)); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); res = EX.run()
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": json.loads(json.dumps(defs(), default=str)), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
