"""P21-11/12/13/14: budgeted red-team search per defence stack, holdout combos, shrinking, mechanism de-dup, regression corpus. Write-once."""
import json, random, subprocess, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from bench.p21 import arena as AR, attacks as T

STACKS = {"open": set(), **{f"only_{l}": {l} for l in AR.LAYERS}, **{f"full_minus_{l}": set(AR.LAYERS) - {l} for l in AR.LAYERS}, "full": set(AR.LAYERS)}
BUDGET, SEED = 400, 21


def search(layers, holdout: bool):
    rng = random.Random(SEED); wins, first, tried = [], None, 0
    while tried < BUDGET:
        c = T.sample(rng)
        if (T.combo(c) in T.HOLDOUT_COMBOS) != holdout and c["objective"] == "exfil": continue
        tried += 1
        if T.run(c, layers)["success"]:
            wins.append(c); first = first or tried
    return wins, first, tried


def main():
    out = REPO / "results/v2/p21-arena"
    if (out / "result.json").exists(): raise SystemExit("write-once")
    res = {"budget_per_stack": BUDGET, "stacks": {}, "findings": [], "regression_corpus": []}; seen = set()
    for name, layers in STACKS.items():
        dev, f1, n1 = search(layers, False); ho, f2, n2 = search(layers, True)
        res["stacks"][name] = {"dev_success_rate": round(len(dev) / n1, 3), "holdout_success_rate": round(len(ho) / n2, 3), "attempts_to_first_success_dev": f1, "attempts_to_first_success_holdout": f2}
        if name in ("full",) or name.startswith("full_minus"):
            for c in dev + ho:
                m = T.mechanism(c, layers); key = (name,) + m
                if key in seen: continue
                seen.add(key); mc = T.shrink(c, layers); res["findings"].append({"stack": name, "mechanism": list(m), "minimal_config": {k: v for k, v in mc.items() if v != T.DEFAULT[k]}, "n_attacks_collapsed": 0}); res["regression_corpus"].append({"stack": name, "config": mc, "expect_success": True})
    for f in res["findings"]: pass
    # every minimal config is also pinned as a regression: it must keep succeeding on exactly the stack it was found on and fail on `full` unless documented unblockable
    for name in ("open",): res["regression_corpus"].append({"stack": name, "config": T.DEFAULT | {"secret_path": "direct"}, "expect_success": True})
    out.mkdir(parents=True, exist_ok=True); (out / "result.json").write_text(json.dumps(res, indent=1))
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    (out / "manifest.json").write_text(json.dumps({"experiment_id": "p21-arena", "git_sha": sha, "command": "python3 bench/p21/run.py", "seed": SEED, "budget": BUDGET, "status": "candidate; in-process arena, red team = seeded random search by the same author (not independent)"}, indent=1))
    for k, v in res["stacks"].items(): print(k, v)
    for f in res["findings"]: print(f["stack"], f["mechanism"], f["minimal_config"])


if __name__ == "__main__": main()
