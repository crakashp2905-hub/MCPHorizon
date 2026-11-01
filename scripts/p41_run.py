#!/usr/bin/env python3
"""P41 runner: write-once results/v2/p41-counterfactual/. `--check` verifies scenario/contract definitions match the recorded run."""
import json, os, sys, platform, hashlib, subprocess, statistics
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.counterfactual import scenarios as SC
from horizon.counterfactual.core import SCHEMA_V
from horizon.emergence.experiment import wilson
OUT = os.path.join(ROOT, "results/v2/p41-counterfactual")


def defs(): return {"schema": SCHEMA_V, "scenarios": [(s["id"], s["kind"], s["adapter"], s["contract"].d()) for s in SC.SCEN], "systems": list(SC.SYSTEMS), "reps": 3}


def pct(xs, q): xs = sorted(xs); return round(xs[min(len(xs) - 1, int(q * len(xs)))], 2)


def summarize(rows):
    out = {}
    for g in SC.SYSTEMS:
        R = [r for r in rows if r["system"] == g]; A = [r for r in R if r["kind"] == "attack"]; B = [r for r in R if r["kind"] == "benign"]
        safe = sum(1 for r in A if r["unsafe_effects"] == 0); done = sum(1 for r in B if r["completed"]); pr = [r for r in R if r.get("predicted_rows") is not None and not r.get("refused")]
        exact = sum(1 for r in pr if r["predicted_rows"] == r["actual_rows"])
        out[g] = {"attack_runs": len(A), "attacks_without_unsafe_effect": safe, "safe_rate": round(safe / len(A), 4), "safe_ci": wilson(safe, len(A)), "unsafe_effects_total": sum(r["unsafe_effects"] for r in A),
                  "benign_runs": len(B), "benign_completed": done, "completion_rate": round(done / len(B), 4), "completion_ci": wilson(done, len(B)), "benign_refused": sum(1 for r in B if r.get("refused")), "benign_stale_retries": sum(1 for r in B if r.get("stale_retry")),
                  "prediction_exact": exact, "prediction_n": len(pr), "prediction_exact_rate": round(exact / len(pr), 4) if pr else None, "ms_p50": pct([r["ms"] for r in R], .5), "ms_p95": pct([r["ms"] for r in R], .95), "ms_p99": pct([r["ms"] for r in R], .99),
                  "benign_completions_per_s": round(done / (sum(r["ms"] for r in B) / 1000), 2), "errors": sum(1 for r in R if r.get("error"))}
    return out


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = json.loads(json.dumps(defs())); bad = [k for k in cur if rec.get(k) != cur[k]]
        print("definitions match recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("write-once: refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); rows = SC.run_all(reps=3)
    per = {s["id"]: {"kind": s["kind"], "adapter": s["adapter"], **{g: sorted({("U%d" % r["unsafe_effects"]) if r["kind"] == "attack" else ("done" if r["completed"] else "NOT-DONE") for r in rows if r["scenario"] == s["id"] and r["system"] == g}) for g in SC.SYSTEMS},
                      "cf_refusal": sorted({r["refused"] for r in rows if r["scenario"] == s["id"] and r["system"] == "counterfactual" and r.get("refused")})} for s in SC.SCEN}
    res = {"summary": summarize(rows), "per_scenario": per, "rows": rows,
           "limits": ["scenarios, contracts and adapters share an author; contracts were written knowing the attacks (expected cardinality is the main signal)", "'llm_preview' is a scripted surface-form estimator, NOT a language model", "SQLite synthetic data and a local directory; one machine; no concurrent-writer stress beyond one injected race",
                      "A09/A10 (authority revision, expired preflight) are attacks only relative to a system that has such concepts; the baselines commit by definition", "expected effects are declared per scenario (by construction); outcomes come from the independent receipt process / registry journal", "publication is to a local mock registry; real registries add asynchronous and irreversible behavior this does not model"]}
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": defs(), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1); print("written")


main()
