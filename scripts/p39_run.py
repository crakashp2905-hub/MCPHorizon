#!/usr/bin/env python3
"""P39 experiment runner. Writes results/v2/p39-emergence/ ONCE (write-once: refuses to overwrite). `--check` verifies the recorded run's definitions (not outcomes) against the code."""
import json, os, sys, platform, hashlib, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.emergence.experiment import *
from horizon.emergence.model import serialize_model, Endpoints
from horizon.emergence.summaries import library_summaries, ABSTRACTION_VERSION, digest
OUT = os.path.join(ROOT, "results/v2/p39-emergence")


def definitions():
    e = Endpoints(1, 2, 3); s = library_summaries()
    return {"abstraction": ABSTRACTION_VERSION, "model_digest": digest(serialize_model(s, e)), "worlds_digest": digest(make_worlds()), "budgets": list(BUDGETS), "sinks": [list(x) for x in SINKS], "corpus_size": len(chains(s))}


def main():
    if "--check" in sys.argv:
        rec = json.load(open(os.path.join(OUT, "manifest.json")))["definitions"]; cur = definitions(); bad = {k: (rec.get(k), cur[k]) for k in cur if rec.get(k) != cur[k]}
        print("definitions match recorded run" if not bad else "MISMATCH " + json.dumps(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(os.path.join(OUT, "result.json")): print("results/v2/p39-emergence/result.json exists: write-once, refusing to overwrite"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); ps = free_ports(); eps = Endpoints(*ps); sums = library_summaries()
    with Oracle(eps) as orc:
        rows = label_corpus(eps, sums, orc); cmp_ = compare_baselines(rows, eps, sums); cur = curves(eps, sums, orc, rows)
        # P39-16 witness: one discovered, verified, non-trivial path + matched safe control
        r = search(sums, eps, budget=200); wit = None
        for c in r["candidates"]:
            if [s.op for s in c.steps] == ["read_secret", "b64", "get"]:
                wit = {"candidate": c.d(), "oracle": orc.execute(c.steps)}
                ctrl = [type(s)(**{**s.__dict__}) for s in c.steps]
                for s in ctrl:
                    if s.op == "b64": s.op = "hash"
                wit["control_same_endpoint_with_hash"] = {"steps": [s.op for s in ctrl], "oracle": orc.execute(ctrl)}
    res = {"abstraction": ABSTRACTION_VERSION, "corpus": {"chains": len(rows), "leaks": sum(r_["leak"] for r_ in rows), "oracle_blind": sum(r_["blind"] for r_ in rows),
           "rows": [{k: v for k, v in r_.items() if k != "_steps"} for r_ in rows]}, "baselines": cmp_, "discovery": cur, "witness": wit,
           "limits": ["synthetic loopback endpoints and one canary", "oracle variant set misses nested encodings (oracle_blind chains unscored) and partial leaks (weak_sanitize)", "refinement is evidence-scoped to the oracle variant set",
                      "worlds are random op/target subsets of a hand-written library: coverage of designed-for classes only", "positive worlds are rare by construction (4 leaking chains in 252)"]}
    json.dump(res, open(os.path.join(OUT, "result.json"), "w"), indent=1, sort_keys=True)
    json.dump({"definitions": definitions(), "python": platform.python_version(), "machine": platform.platform(), "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
               "result_sha256": hashlib.sha256(open(os.path.join(OUT, "result.json"), "rb").read()).hexdigest(), "note": "ephemeral loopback ports; journal hashes vary by run"}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1)
    print("written", OUT)


main()
