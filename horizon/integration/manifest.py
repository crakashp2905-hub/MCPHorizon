"""P54-13: what is needed to rerun: interpreter, platform, lockfiles, per-module recorded manifests (seed/definitions/result hash), datasets, receiver evidence. No model is used anywhere in P39..P54, so there are no model revisions to publish."""
import hashlib, json, os, platform, subprocess, sys
from .registry import MODULES, ROOT

def fh(rel): return "sha256:" + hashlib.sha256(open(os.path.join(ROOT, rel), "rb").read()).hexdigest()
def lockfiles():
    out = {}
    for root, ds, fs in os.walk(ROOT):
        ds[:] = [d for d in ds if d not in (".git", "node_modules", "target", "__pycache__", "results")]
        for f in fs:
            if f in ("Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock") or (f.startswith("requirements") and f.endswith(".txt")): out[os.path.relpath(os.path.join(root, f), ROOT)] = fh(os.path.relpath(os.path.join(root, f), ROOT))
    return out
def modules():
    out = {}
    for m in MODULES:
        d = json.load(open(os.path.join(ROOT, "results/v2/%s/manifest.json" % m["results"])))
        out[m["id"]] = {"result_sha256": d.get("result_sha256"), "python": d.get("python"), "head": d.get("head"), "definitions_digest": "sha256:" + hashlib.sha256(json.dumps(d.get("definitions"), sort_keys=True, default=str).encode()).hexdigest()}
    return out
def environment():
    try: head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    except Exception: head = ""
    return {"python": platform.python_version(), "platform": platform.platform(), "implementation": platform.python_implementation(), "git_head": head, "lockfiles": lockfiles(), "stdlib_only_python": True,
            "seeds": {"P43": [43, 160], "P54_protocol_parity": [54, 60], "note": "other modules' seeds are fixed in their code and listed in their manifests"}, "models": "none: no live model is used by any of P39..P54", "images": "none: no container image is built or published by P54", "datasets": "synthetic scenarios defined in the module packages; hashes in module manifests", "module_manifests": modules()}
