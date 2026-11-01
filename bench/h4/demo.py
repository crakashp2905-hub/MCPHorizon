#!/usr/bin/env python3
"""Minimal end-to-end demo driver: one attack scenario type per suite under B0 (no guard) and B7 (full), with its matched benign control. Prints a table; exit 0 only if B0 shows the effect, B7 blocks it, and the control completes under both."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from bench.h4 import core, hmib, hccb, hecb, hieb         # noqa: F401
PICK = ["HMIB-01", "HCCB-01", "HECB-01", "HIEB-02"]
bad = 0; print(f"{'scenario':10} {'baseline':8} {'effect':7} {'denied':7} {'control_ok':10}")
for sid in PICK:
    res = {}
    for b in ("B0", "B7"):
        rows = core.run_one(core.REGISTRY[sid], b); a = [r for r in rows if r["kind"] == "attack"][0]; c = [r for r in rows if r["kind"] == "control"][0]; res[b] = (a["effect"], a["denied"], c["ok"]); print(f"{sid:10} {b:8} {str(a['effect']):7} {str(a['denied']):7} {str(c['ok']):10}")
    if not (res["B0"][0] and not res["B7"][0] and res["B0"][2] and res["B7"][2]): bad += 1
print("DEMO", "FAIL" if bad else "PASS"); sys.exit(1 if bad else 0)
