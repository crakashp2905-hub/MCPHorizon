#!/usr/bin/env python3
"""Reproduce one HAA scenario against one baseline (P30-12). Needs root + the local mock ports free. Usage: sudo -E env "PATH=$PATH" python3 scripts/p30_repro.py HAA-14 B5
Prints the attack/control records. Used for failed-scenario reproducers (baselines whose attack had an effect). Local mocks only."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from bench.haa import haa as H, scenarios as SC
if __name__ == "__main__":
    sid, base = sys.argv[1], sys.argv[2]
    with H.World() as w: a, k = SC.SCENARIOS[sid](H.Ctx(base, w))
    print(json.dumps({"scenario": sid, "baseline": base, "attack": a, "control": k}, indent=1, default=str))
