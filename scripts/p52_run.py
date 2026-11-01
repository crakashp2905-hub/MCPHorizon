#!/usr/bin/env python3
"""P52 runner: write-once results/v2/p52-temporal/. `--check` verifies the definitions (systems, flags, scenario ids, invariants) match the recorded run."""
import hashlib, json, os, platform, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.temporal import experiment as EX, scenarios as SC, core as C, gate as G
OUT = os.path.join(ROOT, "results/v2/p52-temporal")


def defs():
    return {"systems": [[e.name, e.kind, sorted(e.cfg.__dict__.items()) if hasattr(e, "cfg") else None] for e in EX.systems()], "scenarios": [[x["id"], x["kind"], x["desc"], x["expect"], x.get("single", False), x.get("justified_reapproval", False)] for x in SC.SCENARIOS],
            "rules0": C.RULES0, "classes": list(C.CLASSES), "invariants": [list(i) for i in EX.INVARIANTS]}


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs(), default=str, sort_keys=True)); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); res = EX.run()
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True, default=str)
    json.dump({"invariants": EX.check_invariants(res), "counterexamples": res["counterexamples"], "note": "machine-checkable: scripts/p52_run.py recomputes holds_on_suite from the same code; a counterexample is an interleaving (ordered step labels) that makes the named system violate the oracle"}, open(os.path.join(OUT, "invariants.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": json.loads(json.dumps(defs(), default=str, sort_keys=True)), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
