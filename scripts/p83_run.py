#!/usr/bin/env python3
"""P83 runner: write-once results/v2/p83-plan/{result,manifest}.json. `--check` re-derives and compares."""
import hashlib, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.plan import spans, profiles, migrate
OUT = os.path.join(ROOT, "results/v2/p83-plan")
def collect():
    t = open(os.path.join(ROOT, "docs/MCPHORIZON_2_0_MASTER_SPEC.md"), encoding="utf-8").read()
    rows = [json.loads(l) for l in open(os.path.join(ROOT, "spec/task_compiled.jsonl"))]
    acc = {k: v for k, v in json.load(open(os.path.join(ROOT, "spec/acceptance.json"))).items() if k[:1] == "P" and k[1:2].isdigit()}
    sm = json.load(open(os.path.join(ROOT, "spec/source_spans.json")))
    hist = spans.history_refs(t, ROOT)
    miss = {k: sorted(r for r, s in v.items() if s == "MISSING") for k, v in hist.items()}; miss = {k: v for k, v in miss.items() if v}
    hr = profiles.high_risk_coverage(rows, acc)
    _, man = migrate.migrate(rows, rows, revision="identity-selfcheck")
    cls = {}
    for r in rows: cls[r["work_class"]] = cls.get(r["work_class"], 0) + 1
    return {"tasks": len(rows), "phases": len({r["phase"] for r in rows}), "span_map_matches_spec": spans.check_span_map(sm, t) == [], "span_map_sha": hashlib.sha256(json.dumps(sm, sort_keys=True).encode()).hexdigest(),
            "tasks_with_path_refs": len(hist), "tasks_with_missing_refs": len(miss), "missing_refs_sample": dict(sorted(miss.items())[:10]),
            "work_classes": cls, "high_risk": hr["high_risk"], "high_risk_with_commands": hr["with_commands"], "high_risk_with_named_oracle": hr["with_named_oracle"],
            "high_risk_gap_count": len(hr["gaps"]), "identity_migration_manifest": man}
def main():
    R = collect(); rf = os.path.join(OUT, "result.json")
    if "--check" in sys.argv:
        old = json.load(open(rf)); bad = [k for k in R if k != "identity_migration_manifest" and old.get(k) != R[k]]
        print("matches recorded run" if not bad else "MISMATCH " + ",".join(bad)); sys.exit(1 if bad else 0)
    if os.path.exists(rf): print("write-once: refusing"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); json.dump(R, open(rf, "w"), indent=1, sort_keys=True)
    json.dump({"result_sha256": hashlib.sha256(open(rf, "rb").read()).hexdigest(), "note": "P83 plan extensions; CANDIDATE"}, open(os.path.join(OUT, "manifest.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in R.items() if k not in ("missing_refs_sample", "identity_migration_manifest")}, indent=1))
main()
