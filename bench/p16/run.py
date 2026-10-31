"""P16-11/12/13/15: comparative run. Write-once results/v2/p16-epistemic/. Oracle variant is reported SEPARATELY and is not deployable."""
import json, subprocess, sys, time
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from bench.p16 import fixtures as F
from bench.p9 import stats as S


def evaluate(cases, truth, fn):
    rows = []
    for c in cases:
        t = time.perf_counter(); d = fn(c.observable()); dt = time.perf_counter() - t
        rows.append({"id": c.id, "domain": c.domain, "kind": c.kind, "split": c.split, "allowed": d["decision"] == "ALLOW", "harm": truth.harmful_if_allowed(c.id), "reverify": len(d["reverify"]), "us": dt * 1e6})
    return rows


def summarize(rows):
    h = [r for r in rows if r["harm"]]; b = [r for r in rows if not r["harm"]]
    ha = sum(r["allowed"] for r in h); fb = sum(not r["allowed"] for r in b)
    return {"harmful_cases": len(h), "harm_allowed": ha, "harm_allowed_ci": [round(x, 3) for x in S.wilson(ha, len(h))], "benign_cases": len(b), "false_blocks": fb, "false_block_ci": [round(x, 3) for x in S.wilson(fb, len(b))],
            "reverify_requests_on_benign": sum(r["reverify"] for r in b), "mean_us": round(sum(r["us"] for r in rows) / len(rows), 2)}


def main():
    out = REPO / "results/v2/p16-epistemic"
    if (out / "result.json").exists(): raise SystemExit("write-once")
    cases, truth = F.build(); res = {"n_cases": len(cases), "deployable": {}, "oracle_dependent": {}, "held_out_test_domains": {}, "by_attack_kind": {}}; allrows = {}
    for name, fn in F.SYSTEMS.items():
        rows = evaluate(cases, truth, fn); allrows[name] = rows; res["deployable"][name] = summarize(rows); res["held_out_test_domains"][name] = summarize([r for r in rows if r["split"] == "test"])
    ids = {c.id: c for c in cases}
    orc = lambda o: None
    res["oracle_dependent"]["truth_aware_upper_bound"] = {"note": "reads TruthRegistry; NOT deployable; shows the ceiling", **summarize([{"id": c.id, "domain": c.domain, "kind": c.kind, "split": c.split, "allowed": not truth.harmful_if_allowed(c.id), "harm": truth.harmful_if_allowed(c.id), "reverify": 0, "us": 0} for c in cases])}
    for k in F.ATTACKS: res["by_attack_kind"][k] = {n: sum(r["allowed"] for r in rows if r["kind"] == k) for n, rows in allrows.items()} | {"n": sum(1 for c in cases if c.kind == k)}
    best = min((n for n in F.SYSTEMS if n not in ("open", "epistemic")), key=lambda n: res["deployable"][n]["harm_allowed"] + res["deployable"][n]["false_blocks"]); res["strongest_baseline"] = best
    a = {r["id"]: not r["allowed"] and r["harm"] or (r["allowed"] and not r["harm"]) for r in allrows["epistemic"]}; b = {r["id"]: not r["allowed"] and r["harm"] or (r["allowed"] and not r["harm"]) for r in allrows[best]}
    n10 = sum(a[i] and not b[i] for i in a); n01 = sum(b[i] and not a[i] for i in a); res["paired_vs_strongest_baseline"] = {"epistemic_correct_only": n10, "baseline_correct_only": n01, "mcnemar_p": S.mcnemar_exact(n10, n01), "note": "cases are template-generated; p-values describe this fixture set only"}
    out.mkdir(parents=True, exist_ok=True); (out / "result.json").write_text(json.dumps(res, indent=1))
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    (out / "manifest.json").write_text(json.dumps({"experiment_id": "p16-epistemic", "git_sha": sha, "command": "python3 bench/p16/run.py", "seed": 16, "status": "candidate; synthetic fixtures authored by the same party as the detector (no independent labels)"}, indent=1)); print(json.dumps({k: res[k] for k in ("deployable", "held_out_test_domains", "paired_vs_strongest_baseline", "strongest_baseline")}, indent=1)); print(json.dumps(res["by_attack_kind"]))


if __name__ == "__main__": main()
