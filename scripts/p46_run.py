#!/usr/bin/env python3
"""P46 runner: write-once results/v2/p46-downgrade/. `--check` verifies that the definitions (scenarios, systems, floors, endpoint behaviour, profiles, order constants) match the recorded run."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.downgrade import experiment as EX, scenarios as SC, order as O
OUT = os.path.join(ROOT, "results/v2/p46-downgrade")


def defs():
    return {"scenarios": [(s[0], s[1], s[3], O.to_json(s[4])) for s in SC.SCENARIOS], "systems": list(SC.SYSTEMS), "reps": SC.REPS, "endpoints": SC.EPS, "profiles": {k: [v[0], v[1]] for k, v in SC.PROFILES.items()},
            "chains": {k: list(v) for k, v in O.CHAINS.items()}, "nonwaivable": sorted(SC.NONWAIVABLE), "allowlist": sorted(SC.ALLOW_ENDPOINTS), "fail_modes": list(SC.FAIL_MODES), "injector_seed": SC.Run(None, "x", 0, "x").injector.seed}


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
