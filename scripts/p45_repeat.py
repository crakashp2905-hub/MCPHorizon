#!/usr/bin/env python3
"""Independently repeatable cross-agent budget-composition experiment (P45-16). Runs the composition experiment for any seed in a temp directory and prints JSON; with the recorded seed it must reproduce results/v2/p45-privacy/result.json exactly.
Usage: python3 scripts/p45_repeat.py [--seed N] [--agents A] [--per-agent K] [--eps E] [--trials T]"""
import argparse, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.privacy import experiment as EX
ap = argparse.ArgumentParser(); ap.add_argument("--seed", type=int, default=45); ap.add_argument("--agents", type=int, default=8); ap.add_argument("--per-agent", type=int, default=4); ap.add_argument("--eps", default="0.25"); ap.add_argument("--trials", type=int, default=40); a = ap.parse_args()
out = {s: EX.composition(seed=a.seed, agents=a.agents, per_agent=a.per_agent, eps=a.eps, system=s, trials=a.trials) for s in ("per-agent-limit", "per-principal-accountant", "horizon-basic")}
rec = json.load(open(os.path.join(ROOT, "results/v2/p45-privacy/result.json")))["composition"] if (a.seed, a.agents, a.per_agent, a.eps, a.trials) == (45, 8, 4, "0.25", 40) else None
print(json.dumps(out, indent=1, sort_keys=True)); print("matches recorded run" if rec == out else ("DIFFERS from recorded run" if rec is not None else "(non-default parameters: nothing recorded to compare)"))
sys.exit(1 if rec is not None and rec != out else 0)
