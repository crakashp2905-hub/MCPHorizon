#!/usr/bin/env python3
"""P48 runner: write-once results/v2/p48-consent/. `--check` verifies the definitions (policy, systems, scenario ids, flags) match the recorded run."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.consent import experiment as EX, scenarios as SC, harness as H, core as K
OUT = os.path.join(ROOT, "results/v2/p48-consent")


def defs():
    return {"policy": K.POLICY, "systems": [[s.name, s.gate, s.mode, s.style, sorted(s.cfg.__dict__.items()) if s.cfg else None] for s in H.systems()], "scenarios": [[s["id"], s["kind"], s["desc"]] for s in SC.SCENARIOS], "flags": H.FLAGS, "guard_names": sorted(H.GUARD_NAMES)}


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
