"""Annotation tooling for P8-16/P8-17. It does NOT produce annotations. `sheet` writes a label-free sample for human annotators; `kappa` scores two returned sheets.
No independent dual annotation has been performed for this benchmark (see the benchmark card)."""
from __future__ import annotations
import csv, json, random, sys
from collections import Counter
from pathlib import Path
HERE = Path(__file__).resolve().parent; sys.path.insert(0, str(HERE.parents[1]))
DATA = HERE / "data"


def sheet(out: str, n: int = 40, seed: int = 7):
    rows = []
    for p in sorted((DATA / "truth").glob("*.json")):
        t = json.loads(p.read_text()); v = json.loads((DATA / "visible" / p.name).read_text()); rows.append((t["family"], t["id"], v))
    rnd = random.Random(seed); by = {}
    for f, i, v in rows: by.setdefault(f, []).append((i, v))
    pick = []
    for f, xs in sorted(by.items()): rnd.shuffle(xs); pick += xs[: max(2, n // len(by))]
    rnd.shuffle(pick)
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["scenario_id", "intent", "steps_json", "label (harmful|benign)", "confidence (1-5)", "rationale"])
        for i, v in pick: w.writerow([i, v["intent"], json.dumps(v["steps"]), "", "", ""])
    print("wrote", len(pick), "rows (no truth columns)")


def kappa(a_path: str, b_path: str) -> dict:
    A = {r["scenario_id"]: r["label (harmful|benign)"].strip().lower() for r in csv.DictReader(open(a_path))}; B = {r["scenario_id"]: r["label (harmful|benign)"].strip().lower() for r in csv.DictReader(open(b_path))}
    ids = sorted(set(A) & set(B)); ok = {"harmful", "benign"}
    if not ids or any(A[i] not in ok or B[i] not in ok for i in ids): raise SystemExit("sheets must be fully labelled with harmful|benign on shared ids")
    n = len(ids); po = sum(A[i] == B[i] for i in ids) / n; ca, cb = Counter(A[i] for i in ids), Counter(B[i] for i in ids); pe = sum(ca[k] * cb[k] for k in ok) / n ** 2
    return {"n": n, "observed_agreement": round(po, 3), "cohen_kappa": round((po - pe) / (1 - pe), 3) if pe < 1 else 1.0, "disagreements_for_adjudication": [i for i in ids if A[i] != B[i]]}


if __name__ == "__main__":
    if sys.argv[1] == "sheet": sheet(sys.argv[2])
    elif sys.argv[1] == "kappa": print(json.dumps(kappa(sys.argv[2], sys.argv[3]), indent=1))
