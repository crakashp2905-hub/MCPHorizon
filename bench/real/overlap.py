"""Exact cross-dataset overlap (contamination check). Normalised long strings (>= MIN chars) are hashed per
dataset; pairs with shared hashes are reported with counts and one redacted-length example.  Exact matches only:
near-duplicates / paraphrases are NOT detected.  Trajectory-heavy dirs (runs/, results/) are skipped."""
import hashlib, itertools, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from bench.real import datasets as D, agentdojo as A
MIN = 60
SKIP_DIRS = ("runs/", "results/", "cache/", "node_modules/", "baselines/results/", "baselines/benchmarks/")


def norm(s): return re.sub(r"\s+", " ", s).strip().lower()


def hashes(d):
    out = set()
    for p in D.data_files(d):
        rel = os.path.relpath(p, d)
        if rel.startswith(SKIP_DIRS) or os.path.getsize(p) > D.MAX_BYTES:
            continue
        try:
            recs, _ = D._records(p)
        except Exception:                                  # noqa: BLE001 (already reported by validator)
            continue
        for r in recs:
            for leaf in A.string_leaves(r if not isinstance(r, str) else [r]):
                n = norm(leaf)
                if len(n) >= MIN:
                    out.add(hashlib.sha256(n.encode()).hexdigest())
    return out


def overlaps(sets):
    res = []
    for (a, ha), (b, hb) in itertools.combinations(sorted(sets.items()), 2):
        k = len(ha & hb)
        if k:
            res.append({"a": a, "b": b, "shared_strings": k, "frac_of_smaller": k / min(len(ha), len(hb))})
    return sorted(res, key=lambda x: -x["shared_strings"])


if __name__ == "__main__":
    base = sys.argv[sys.argv.index("--base") + 1]
    reg = json.load(open("bench/real/REGISTRY.json"))
    sets = {e["id"]: hashes(os.path.join(base, e["dir"])) for e in reg if os.path.isdir(os.path.join(base, e["dir"]))}
    res = {"min_chars": MIN, "sizes": {k: len(v) for k, v in sets.items()}, "overlaps": overlaps(sets)}
    json.dump(res, open("bench/real/results/cross_dataset_overlap.json", "w"), indent=1)
    for o in res["overlaps"][:15]:
        print(o["a"], o["b"], o["shared_strings"], round(o["frac_of_smaller"], 3))
    print("pairs with overlap:", len(res["overlaps"]))
