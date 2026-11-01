#!/usr/bin/env python3
"""P43 runner: write-once results/v2/p43-mutation/. `--check` verifies definitions (operators, seeds, detectors, guardrails) match the recorded run AND that the release manifest regenerates byte-identically."""
import json, os, sys, platform, hashlib, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.mutation import experiment as EX, pipeline as PL, operators as OP, seeds as SD, detectors as DT, ir
OUT = os.path.join(ROOT, "results/v2/p43-mutation")


def defs():
    return {"operators_digest": OP.operators_digest(), "seeds_digest": ir.digest(SD.seeds()), "detectors": sorted(DT.STATIC) + ["D4-learned-signature"], "families": list(SD.FAMILIES), "dev_families": list(SD.DEV_FAMILIES), "test_families": list(SD.TEST_FAMILIES), "guardrails": PL.GUARDRAILS, "pipeline_version": PL.PIPELINE_VERSION, "rng_seed": 43, "depth2": 160}


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json"))); cur = json.loads(json.dumps(defs())); bad = [k for k in cur if rec["definitions"].get(k) != cur[k]]
        again = PL.release_manifest(); stored = json.load(open(os.path.join(OUT, "release_manifest.json")))
        if again != stored: bad.append("release_manifest not reproducible")
        print("definitions match recorded run; release manifest reproduces byte-identically" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); res = EX.run(43, 160); rel = PL.release_manifest()
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True); json.dump(rel, open(os.path.join(OUT, "release_manifest.json"), "w"), indent=1, sort_keys=True)
    G = PL.generate(43, 160)
    from horizon.mutation.oracle import Oracle
    with Oracle() as o: PL.label(o, G["roots"]); PL.label(o, G["mutants"])
    json.dump({"graphs": {m["id"]: {"graph": m["graph"], "oracle": m["oracle"]} for m in G["roots"] + G["mutants"]}}, open(os.path.join(OUT, "dataset.json"), "w"), indent=0, sort_keys=True)
    json.dump({"definitions": defs(), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(), "code_digest": PL.code_digest(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest(), "release_manifest_digest": rel["manifest_digest"]}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
