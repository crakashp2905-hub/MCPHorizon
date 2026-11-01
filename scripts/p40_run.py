#!/usr/bin/env python3
"""P40 runner: write-once results/v2/p40-obligation/. `--check` verifies definitions (scenario ids, catalog digest, reference semantics) match the recorded run."""
import json, os, sys, platform, hashlib, subprocess, statistics
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.obligation import scenarios as SC, diff, terms
from horizon.obligation.catalog import catalog
from horizon.emergence.experiment import wilson
OUT = os.path.join(ROOT, "results/v2/p40-obligation")


def defs():
    cat = sorted(o.digest() for o in catalog("pol-1")); return {"scenarios": [(s[0], s[1], s[2]) for s in SC.SCEN], "catalog_digest": hashlib.sha256(json.dumps(cat).encode()).hexdigest(), "operators": sorted(terms.OPERATORS), "systems": list(SC.SYSTEMS), "reps": 3, "diff_max_len": 6}


def summarize(rows):
    out = {}
    for g in SC.SYSTEMS:
        R = [r for r in rows if r["system"] == g]; A = [r for r in R if r["kind"] == "attack"]; B = [r for r in R if r["kind"] == "benign"]
        blocked = sum(1 for r in A if r["excess"] == 0); done = sum(1 for r in B if r["missing"] == 0 and r["excess"] == 0)
        out[g] = {"attack_runs": len(A), "attacks_with_no_unsafe_commit": blocked, "attack_block_rate": round(blocked / len(A), 4), "attack_block_ci": wilson(blocked, len(A)), "unsafe_excess_commits": sum(r["excess"] for r in A),
                  "benign_runs": len(B), "benign_completed_correctly": done, "benign_completion_rate": round(done / len(B), 4), "benign_ci": wilson(done, len(B)), "benign_blocked": sum(1 for r in B if r["missing"] > 0), "benign_duplicate_commits": sum(r["excess"] for r in B),
                  "median_ms": round(statistics.median(r["ms"] for r in R), 2), "mean_http_calls": round(statistics.mean(r["http_calls"] for r in R), 2), "errors": sum(1 for r in R if r["error"])}
    return out


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs())); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); rows = SC.run_all(reps=3); d = diff.differential(6)
    per = {}
    for sid, kind, exp, desc, _ in SC.SCEN:
        per[sid] = {"kind": kind, "desc": desc, "expected": exp, **{g: [r["observed_commits"] for r in rows if r["scenario"] == sid and r["system"] == g] for g in SC.SYSTEMS}, "runtime_reasons": sorted({x for r in rows if r["scenario"] == sid and r["system"] == "runtime" for x in r["reasons"]})}
    res = {"summary": summarize(rows), "per_scenario": per, "differential": d, "rows": rows,
           "limits": ["scenario scripts and the obligation catalog were written by the same author as the engine", "'static' is a presence/order check on a run record: one plausible CI-lint baseline, not every workflow analyser", "evidence services are in-process threads with their own keys; only the deploy target is a separate process",
                      "ground truth for expected commits is by construction; commits are read from the deploy journal", "reference model is exhaustive only up to length 6 over a 6-letter alphabet and encodes the same stated semantics (latest counted approval)", "no real CI/approval systems; timing is wall-clock on one VM"]}
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": defs(), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
