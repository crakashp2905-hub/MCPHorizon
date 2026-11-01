#!/usr/bin/env python3
"""P51 runner: write-once results/v2/p51-vision/. `--check` verifies the definitions (systems, flags, scenario ids, schemas) match the recorded run match the recorded run."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.vision import experiment as EX, scenarios as SC, core as C
OUT = os.path.join(ROOT, "results/v2/p51-vision")


def defs():
    return {"systems": [[n, k, sorted(c.__dict__.items()) if c else None] for n, k, c in EX.systems()], "scenarios": [[x["id"], x["kind"], x["desc"], x["justified_confirm"], x["ax"], x["unsupported_ok"], x["authorized"], x["expected"]] for x in SC.SCENARIOS],
            "schemas": {"action": C.ACTION_SCHEMA, "binding": C.BINDING_SCHEMA, "effect": C.EFFECT_SCHEMA}, "effect_kinds": list(C.EFFECT_KINDS)}


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
