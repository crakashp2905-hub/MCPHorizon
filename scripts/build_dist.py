#!/usr/bin/env python3
"""Deterministic release tarball for hzd: sorted entries, zero mtimes/uid/gid, fixed modes, gzip mtime 0 => same source tree gives byte-identical output (checked by tests). Writes dist/hzd-<version>.tar.gz and .sha256.
Contents: horizon/**.py, schemas/**, install.py, MANIFEST.json (sha256 of every file). Usage: python3 scripts/build_dist.py [--out DIR]"""
import argparse, gzip, hashlib, io, json, os, sys, tarfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)


def collect() -> dict:
    files = {}
    for top in ("horizon", "schemas"):
        for d, ds, fs in os.walk(os.path.join(ROOT, top)):
            ds[:] = sorted(x for x in ds if x != "__pycache__")
            for f in sorted(fs):
                if top == "horizon" and not f.endswith(".py"): continue
                p = os.path.join(d, f); files[os.path.relpath(p, ROOT)] = open(p, "rb").read()
    return files


def build(out_dir: str) -> tuple:
    from horizon.product.home import VERSION
    files = collect(); manifest = {"version": VERSION, "files": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(files.items())}}
    members = dict(files); members["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=1) + "\n").encode(); members["install.py"] = open(os.path.join(ROOT, "packaging", "install.py"), "rb").read()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as t:
        for n in sorted(members):
            ti = tarfile.TarInfo(f"hzd-{VERSION}/{n}"); ti.size = len(members[n]); ti.mtime = 0; ti.uid = ti.gid = 0; ti.uname = ti.gname = ""; ti.mode = 0o755 if n == "install.py" else 0o644; t.addfile(ti, io.BytesIO(members[n]))
    raw = gzip.compress(buf.getvalue(), mtime=0); os.makedirs(out_dir, exist_ok=True); path = os.path.join(out_dir, f"hzd-{VERSION}.tar.gz"); open(path, "wb").write(raw)
    h = hashlib.sha256(raw).hexdigest(); open(path + ".sha256", "w").write(f"{h}  {os.path.basename(path)}\n"); return path, h


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=os.path.join(ROOT, "dist")); a = ap.parse_args(); p, h = build(a.out); print(p, h)
