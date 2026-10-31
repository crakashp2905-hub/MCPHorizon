"""Write/verify the frozen benchmark files and the reproducibility manifest (P8-04, P8-12, P8-20). Usage: freeze.py write | verify"""
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent; REPO = HERE.parents[1]; sys.path.insert(0, str(REPO))
from bench.secbench import spec
DATA = HERE / "data"
CODE = ["spec.py", "world.py", "runner.py", "run.py", "freeze.py"]
CODEMODE = ["../../codemode/package-lock.json", "../../codemode/runner.mjs"]


def sha(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(o) -> str: return json.dumps(o, indent=1, sort_keys=True) + "\n"


def render(seed: int = spec.SEED) -> dict[str, str]:
    scs = spec.build(seed); files = {}
    for s in scs:
        files[f"visible/{s['visible']['id']}.json"] = dump(s["visible"]); files[f"truth/{s['truth']['id']}.json"] = dump(s["truth"])
    sp = spec.split(scs); files["splits.json"] = dump({"version": spec.VERSION, "seed": seed, "split_by": "template (tool-family/protocol overlap documented in the benchmark card)", "splits": sp,
                                                       "splits_sha256": hashlib.sha256(json.dumps(sp, sort_keys=True).encode()).hexdigest()})
    return files


def manifest(files: dict[str, str], seed: int) -> dict:
    return {"benchmark": spec.VERSION, "seed": seed, "files": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in sorted(files.items())},
            "code": {c: sha(HERE / c) for c in CODE}, "codemode": {Path(c).name: sha((HERE / c).resolve()) for c in CODEMODE}, "scenario_count": len([k for k in files if k.startswith("visible/")])}


def write(seed: int = spec.SEED):
    files = render(seed)
    for k, v in files.items(): p = DATA / k; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(v)
    (DATA / "MANIFEST.json").write_text(dump(manifest(files, seed))); print("wrote", len(files), "files")


def verify(warnings: list | None = None) -> list[str]:
    """Data files are strict (any difference is an error). Code hashes are recorded for reproducibility but a change only produces a warning."""
    errs = []; m = json.loads((DATA / "MANIFEST.json").read_text()); files = render(m["seed"])
    on_disk = {str(p.relative_to(DATA)) for p in DATA.rglob("*.json") if p.name != "MANIFEST.json"}
    if on_disk != set(m["files"]): errs.append(f"file set differs: {sorted(on_disk ^ set(m['files']))[:5]}")
    for k, h in m["files"].items():
        p = DATA / k
        if not p.exists(): errs.append(f"missing {k}"); continue
        if hashlib.sha256(p.read_bytes()).hexdigest() != h: errs.append(f"checksum mismatch {k}")
        if k in files and hashlib.sha256(files[k].encode()).hexdigest() != h: errs.append(f"regeneration drift {k}")
    for c, h in m["code"].items():
        if sha(HERE / c) != h and warnings is not None: warnings.append(f"code changed since freeze: {c}")
    return errs


if __name__ == "__main__":
    if sys.argv[1:] == ["write"]: write()
    elif sys.argv[1:] == ["verify"]:
        w = []; e = verify(w); print("OK" if not e else "\n".join(e)); [print("WARNING:", x) for x in w]; sys.exit(1 if e else 0)
    else: sys.exit("usage: freeze.py write|verify")
