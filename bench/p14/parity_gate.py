"""P14-14: CI parity gate. Fails on any discrepancy not listed (with explanation) in results/v2/p14-parity/expected_discrepancies.json, and on any listed entry that no longer occurs (stale)."""
import json, subprocess, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(REPO))
from horizon.equiv import parity as P

SEED, N = 1, 40


def observed() -> dict:
    m = P.matrix(P.generate(SEED, N)); return {"matrix": m, "classes": sorted({(d["path"], d["cls"]) for d in m["discrepancies"]})}


def check(expected_path: Path) -> list:
    exp = json.loads(expected_path.read_text()); allowed = {(e["path"], e["cls"]) for e in exp["expected"]}
    for e in exp["expected"]:
        if not e.get("explanation") or not e.get("owner"): return [f"unexplained expected entry {e}"]
    got = {tuple(c) for c in observed()["classes"]}
    return [f"NEW discrepancy {c}" for c in sorted(got - allowed)] + [f"STALE expected discrepancy {c} no longer occurs" for c in sorted(allowed - got)]


def main():
    errs = check(REPO / "results/v2/p14-parity/expected_discrepancies.json")
    from horizon.equiv import effects as F
    for name, x, y in P.non_equivalent_fixtures():
        if F.equivalent(x, y): errs.append(f"non-equivalent fixture {name} judged equivalent (checker vacuous)")
    if P.metamorphic_mcp(): errs.append("metamorphic invariance violated")
    if any(r["allowed"] for r in P.trap_results()): errs.append("alias trap was allowed")
    if errs: print("\n".join(errs)); raise SystemExit(1)
    print("parity gate: OK")


if __name__ == "__main__": main()
