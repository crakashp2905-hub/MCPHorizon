"""P22-04..07: always/never/threshold/selective verification at matched security targets. THE VERIFIER AND THE HUMAN REVIEWER ARE SIMULATED (no LLM available); numbers show policy trade-offs under stated assumptions only. Write-once."""
import json, math, random, subprocess, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.select import selective as S
from bench.p9 import stats as ST

SEED = 22
HARM_RATE = {"none": .01, "unknown_target": .35, "unknown_lineage": .30, "stale_policy": .10, "ambiguous_evidence": .20, "unsupported_tool": .40, "policy_denied": .9}
REV_MISS, REV_FALSE_BLOCK, V_TOKENS, V_COST = 0.08, 0.02, 800, 0.004        # reviewer approves 8% of harmful, blocks 2% of benign; per verifier call


def cases(n, seed, sd=0.22):
    r = random.Random(seed); out = []
    for i in range(n):
        tags = set()
        if r.random() < .06: tags.add("policy_denied")
        for t in S.TAXONOMY:
            if r.random() < .12: tags.add(t)
        key = "policy_denied" if "policy_denied" in tags else (max((t for t in tags), key=lambda t: HARM_RATE[t]) if tags else "none")
        harm = r.random() < HARM_RATE[key]; score = min(1, max(0, .5 + (.28 if harm else -.28) + r.gauss(0, sd))); lat = r.lognormvariate(math.log(1.1), .4)
        out.append({"id": i, "tags": tags, "harm": harm, "score": score, "lat": lat, "rev_miss": r.random() < REV_MISS, "rev_fb": r.random() < REV_FALSE_BLOCK})
    return out


def evaluate(cs, policy, tau, rho=0.0, budget_frac=0.0):
    pending = [(c["id"], S.prefilter(c["tags"])["prior"]) for c in cs if S.prefilter(c["tags"])["decision"] == "REVIEW"]
    sel = {c["id"] for c in cs}
    if policy == "threshold": sel = {i for i, p in pending if p >= rho}
    elif policy == "selective": sel = S.schedule(pending, int(budget_frac * len(cs)))
    elif policy == "never": sel = set()
    harm_landed = blocks = reviews = calls = 0; lats = []
    for c in cs:
        pre = S.prefilter(c["tags"]); used = pre["decision"] == "REVIEW" and c["id"] in sel and policy != "never"
        d = S.combine(pre, c["score"] if used else None, tau); calls += used
        if used: lats.append(c["lat"])
        if d["decision"] == "ALLOW": harm_landed += c["harm"]
        elif d["decision"] == "REVIEW":
            reviews += 1
            if c["harm"]: harm_landed += c["rev_miss"]
            else: blocks += c["rev_fb"]
        else: blocks += (not c["harm"])
    n = len(cs); lats.sort(); return {"harm_landed_rate": harm_landed / n, "false_blocks": blocks, "human_reviews": reviews, "verifier_calls": calls, "tokens": calls * V_TOKENS, "usd": round(calls * V_COST, 2), "p95_verifier_latency_s": round(lats[int(.95 * len(lats))], 2) if lats else 0.0}


def auc(scores, harms):
    pos = [s for s, h in zip(scores, harms) if h]; neg = [s for s, h in zip(scores, harms) if not h]
    return round(sum((p > n) + .5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg)), 4) if pos and neg else None


def tune(cs, policy, target):
    """Cheapest setting (fewest calls, then fewest reviews) on the CALIBRATION split whose actual harm rate meets the target."""
    best = None
    grid = [(tau, rho, bf) for tau in (.5, .6, .7, .8, .9, 1.01) for rho in ((0.0,) if policy != "threshold" else (0.1, 0.2, 0.3, 0.4, 0.5)) for bf in ((0.0,) if policy != "selective" else (.02, .05, .1, .2, .4))]
    for tau, rho, bf in grid:
        m = evaluate(cs, policy, tau, rho, bf)
        if m["harm_landed_rate"] <= target and (best is None or (m["false_blocks"] * 100 + m["verifier_calls"] + m["human_reviews"] * .1) < best[0]): best = ((m["false_blocks"] * 100 + m["verifier_calls"] + m["human_reviews"] * .1), (tau, rho, bf))
    return best[1] if best else None


def main():
    out = REPO / "results/v2/p22-selective"
    if (out / "result.json").exists(): raise SystemExit("write-once")
    cal, test, drift = cases(3000, SEED), cases(3000, SEED + 1), cases(3000, SEED + 2, sd=0.34)       # drift split: verifier gets noisier
    res = {"assumptions": "verifier and human reviewer are SIMULATED; verifier is restrict-only", "targets": {}}
    for target in (0.02, 0.01):
        rows = {}
        for pol in ("never", "always", "threshold", "selective"):
            cfg = tune(cal, pol, target) if pol != "never" else (1.01, 0.0, 0.0)
            if cfg is None: rows[pol] = {"unattainable_target_on_calibration": True}; continue
            m = evaluate(test, pol, *cfg); m["config"] = {"tau_deny": cfg[0], "rho": cfg[1], "budget_frac": cfg[2]}; m["target_met_on_test"] = m["harm_landed_rate"] <= target; m["harm_ci"] = [round(x, 4) for x in ST.wilson(round(m["harm_landed_rate"] * len(test)), len(test))]; m["harm_landed_rate"] = round(m["harm_landed_rate"], 4)
            if pol != "never": m["on_drifted_verifier"] = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in evaluate(drift, pol, *cfg).items()}
            rows[pol] = m
        res["targets"][str(target)] = rows
    sc = [c["score"] for c in test if c["tags"]]; hh = [c["harm"] for c in test if c["tags"]]; res["calibration_test"] = S.calibration(sc, hh)["ece"]; res["calibration_drifted"] = S.calibration([c["score"] for c in drift if c["tags"]], [c["harm"] for c in drift if c["tags"]])["ece"]
    res["auc_test"] = auc(sc, hh); res["auc_drifted"] = auc([c["score"] for c in drift if c["tags"]], [c["harm"] for c in drift if c["tags"]])
    res["drift_alarm"] = res["auc_drifted"] < res["auc_test"] - 0.05          # ECE is NOT used for drift: scores are not probabilities, so ECE moved the wrong way (0.138 -> 0.094) while discrimination fell
    res["drift_note"] = "ECE is reported but is a misleading drift signal for this score; AUC drop is the alarm"
    out.mkdir(parents=True, exist_ok=True); (out / "result.json").write_text(json.dumps(res, indent=1, default=list))
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    (out / "manifest.json").write_text(json.dumps({"experiment_id": "p22-selective", "git_sha": sha, "command": "python3 bench/p22/run.py", "seed": SEED, "status": "candidate; simulated verifier/reviewer; synthetic harm rates"}, indent=1)); print(json.dumps(res, indent=1, default=list))


if __name__ == "__main__": main()
