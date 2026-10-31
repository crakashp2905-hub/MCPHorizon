"""Run SecBench from a clean checkout: python3 bench/secbench/run.py --split dev|test|train|all [--systems open,full] [--out FILE]. Needs `cd codemode && npm ci` for the Code Mode scenarios."""
from __future__ import annotations
import argparse, json, shutil, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from bench.secbench import spec
from bench.secbench.runner import run_one, summarize, CODE_TEMPLATES
from bench.secbench.world import SUTS, NoRealNetwork
from horizon.codemode.exec import HERE


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--split", default="dev"); ap.add_argument("--systems", default=",".join(SUTS)); ap.add_argument("--out"); ap.add_argument("--seed", type=int, default=spec.SEED); ap.add_argument("--unblinded-demo", action="store_true")
    a = ap.parse_args(argv); scs = spec.build(a.seed); have_node = bool(shutil.which("node")) and (HERE / "node_modules" / "isolated-vm").exists(); rows = []
    with NoRealNetwork():
        for sc in scs:
            if a.split != "all" and sc["truth"]["split"] != a.split: continue
            if sc["truth"]["template_code"] in CODE_TEMPLATES and not have_node: print("SKIP (no node runtime):", sc["visible"]["id"], file=sys.stderr); continue
            for s in a.systems.split(","): rows.append(run_one(sc, s, a.seed))
            if a.unblinded_demo: rows.append({**run_one(sc, "name_heuristic", a.seed, blinded=False), "system": "name_heuristic_unblinded"})
    rep = {"benchmark": spec.VERSION, "split": a.split, "seed": a.seed, "note": "scripted agents (no LLM); self-authored scenarios; oracles are separate code but same author; not independent", "summary": summarize(rows), "rows": rows}
    if a.out: Path(a.out).parent.mkdir(parents=True, exist_ok=True); Path(a.out).write_text(json.dumps(rep, indent=1) + "\n")
    print(json.dumps(rep["summary"], indent=1)); return rep


if __name__ == "__main__": main()
