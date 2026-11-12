#!/usr/bin/env python3
"""Offline installer for hzd (stdlib only). Run from the extracted release directory:
    python3 install.py --prefix /opt/hzd          # verifies every file against MANIFEST.json, copies to PREFIX/lib, writes PREFIX/bin/hzd
    python3 install.py --verify-only /opt/hzd      # re-checks an installed tree against its manifest (detects edits/additions/removals)
Needs Python >= 3.11 and the `cryptography` package already installed; downloads nothing."""
import argparse, hashlib, json, os, shutil, stat, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def digest(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()


def problems(root: str, manifest: dict, skip=()) -> list:
    bad = []
    for rel, h in manifest["files"].items():
        p = os.path.join(root, rel)
        if not os.path.isfile(p) or os.path.islink(p): bad.append("missing:" + rel)
        elif digest(p) != h: bad.append("modified:" + rel)
    on_disk = set()
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x != "__pycache__"]
        for f in fs: on_disk.add(os.path.relpath(os.path.join(d, f), root))
    for rel in sorted(on_disk - set(manifest["files"]) - set(skip)): bad.append("unexpected:" + rel)
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--prefix"); ap.add_argument("--verify-only"); a = ap.parse_args(argv)
    if sys.version_info < (3, 11): print("needs Python >= 3.11", file=sys.stderr); return 1
    if a.verify_only:
        lib = os.path.join(a.verify_only, "lib"); m = json.load(open(os.path.join(a.verify_only, "MANIFEST.json"))); bad = problems(lib, m)
        print(json.dumps({"ok": not bad, "problems": bad})); return 0 if not bad else 1
    if not a.prefix: ap.error("--prefix or --verify-only required")
    m = json.load(open(os.path.join(HERE, "MANIFEST.json"))); bad = problems(HERE, m, skip=("MANIFEST.json", "install.py"))
    if bad: print(json.dumps({"ok": False, "refused": "release directory does not match MANIFEST.json", "problems": bad})); return 1
    lib = os.path.join(a.prefix, "lib")
    if os.path.exists(lib): print("refusing to overwrite an existing install: " + lib, file=sys.stderr); return 1
    os.makedirs(a.prefix, exist_ok=True)
    for rel in m["files"]:
        dst = os.path.join(lib, rel); os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copyfile(os.path.join(HERE, rel), dst)
    shutil.copyfile(os.path.join(HERE, "MANIFEST.json"), os.path.join(a.prefix, "MANIFEST.json")); os.makedirs(os.path.join(a.prefix, "bin"), exist_ok=True)
    launcher = os.path.join(a.prefix, "bin", "hzd")
    open(launcher, "w").write('#!/bin/sh\nPREFIX="$(cd "$(dirname "$0")/.." && pwd)"\nPYTHONPATH="$PREFIX/lib" PYTHONDONTWRITEBYTECODE=1 exec python3 -B -m horizon.product.cli "$@"\n'); os.chmod(launcher, 0o755)
    print(json.dumps({"ok": True, "prefix": a.prefix, "launcher": launcher, "version": m["version"], "files": len(m["files"])})); return 0


if __name__ == "__main__": sys.exit(main())
