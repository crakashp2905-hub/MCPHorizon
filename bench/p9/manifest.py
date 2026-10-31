"""Integrity manifest for P9 outputs (P9-23): SHA-256 of raw results, the frozen benchmark manifest and the study code."""
import hashlib, json, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]; OUT = REPO / "results/v2/p9_MANIFEST.json"
FILES = ["results/v2/p9_comparative.json", "results/v2/p8_secbench_dev.json", "results/v2/p8_secbench_test.json", "bench/secbench/data/MANIFEST.json", "bench/p9/study.py", "bench/p9/stats.py", "bench/secbench/spec.py", "bench/secbench/world.py", "bench/secbench/runner.py"]
sha = lambda p: hashlib.sha256((REPO / p).read_bytes()).hexdigest()


def write(): OUT.write_text(json.dumps({"files": {p: sha(p) for p in FILES}}, indent=1, sort_keys=True)); print("wrote", OUT)


def verify(strict_code=False):
    m = json.loads(OUT.read_text())["files"]; bad = [p for p, h in m.items() if sha(p) != h and (strict_code or p.startswith("results/") or p.endswith("MANIFEST.json"))]; warn = [p for p, h in m.items() if sha(p) != h and p not in bad]
    return bad, warn


if __name__ == "__main__":
    if sys.argv[1:] == ["write"]: write()
    else:
        bad, warn = verify(); print("code drift (warning):", warn) if warn else None
        if bad: print("MISMATCH:", bad); sys.exit(1)
        print("OK")
