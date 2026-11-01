#!/usr/bin/env python3
"""P33 driver (needs root + Landlock for the artifact oracle). `prereg` writes benchmarks/hccb/PREREGISTRATION.json BEFORE `run`; `run` writes results/v2/p33-hccb/ (write-once). Subjects are scripted toy generators."""
import hashlib, json, os, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.codeassur import hccb as H
TASKS = sorted(H.TASKS); MODS = sorted(H.MODIFIERS); SEEDS = list(range(20))
PAIRS = [("persona_a", "persona_b"), ("persona_a", "neutral"), ("persona_b", "neutral"), ("irrelevant_a", "irrelevant_b")]
def prereg():
    p = os.path.join(ROOT, "benchmarks/hccb/PREREGISTRATION.json")
    if os.path.exists(p): sys.exit("prereg exists; never overwrite")
    json.dump(H.preregistration(TASKS, MODS, SEEDS), open(p, "w"), indent=1, sort_keys=True); print("prereg written")
def run():
    d = os.path.join(ROOT, "results/v2/p33-hccb")
    if os.path.exists(os.path.join(d, "result.json")): sys.exit("refusing to overwrite " + d)
    pr = json.load(open(os.path.join(ROOT, "benchmarks/hccb/PREREGISTRATION.json")))
    if pr["plan_digest"] != H.sha(H.plan(TASKS, MODS, SEEDS)): sys.exit("plan differs from preregistration")
    os.makedirs(d, exist_ok=True); cells = H.plan(TASKS, MODS, SEEDS); rows = []; t0 = time.time()
    for name, model in H.toy_models().items():
        for c in cells: rows.append(H.run_cell(model, c))
    out = {"subjects": "scripted toy generators (NOT real models); 'context_sensitive' has a PLANTED gap, 'invariant' has none", "prereg_digest": pr["digest"], "n_cells": len(rows), "seconds": round(time.time() - t0, 1), "models": {}}
    for name in H.toy_models():
        rs = [r for r in rows if r["model"] == name]; out["models"][name] = {"groups": H.group_table(rs), "contrasts": H.contrasts(rs, PAIRS), "truth_check": {"toy_variant_vulnerable_and_functional": sum(r["truth_variant"] == "vulnerable" for r in rs), "oracle_confirmed": sum(r["label"] == "confirmed_vulnerable" for r in rs)}}
    open(os.path.join(d, "raw_runs.jsonl"), "w").write("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)); json.dump(out, open(os.path.join(d, "result.json"), "w"), indent=1, sort_keys=True)
    json.dump({"write_once": True, "files": {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in ("raw_runs.jsonl", "result.json")}}, open(os.path.join(d, "manifest.json"), "w"), indent=1, sort_keys=True); print(out["seconds"], "s")
if __name__ == "__main__": {"prereg": prereg, "run": run}[sys.argv[1]]()
