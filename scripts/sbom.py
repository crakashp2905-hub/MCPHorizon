#!/usr/bin/env python3
"""CycloneDX 1.5 SBOM from lockfiles (P10-15, partial). Sources: package-lock.json files, Cargo.lock. Writes JSON to stdout or --out. Vulnerability/container scanning requires network services and is NOT done here."""
import json, re, sys, subprocess
from pathlib import Path


def components(root="."):
    comps = {}
    files = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True).stdout.split()
    for f in files:
        p = Path(root) / f
        if p.name == "package-lock.json":
            for path, meta in json.loads(p.read_text()).get("packages", {}).items():
                if path and meta.get("version"): n = path.split("node_modules/")[-1]; comps[("npm", n, meta["version"])] = meta.get("integrity")
        elif p.name == "Cargo.lock":
            for m in re.finditer(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', p.read_text()): comps[("cargo", m.group(1), m.group(2))] = None
    return comps


def build(root="."):
    c = components(root)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "application", "name": "mcphorizon"}},
            "components": [{"type": "library", "name": n, "version": v, "purl": f"pkg:{eco}/{n}@{v}", **({"hashes": [{"alg": "SHA-512", "content": h}]} if h and h.startswith("sha512-") else {})} for (eco, n, v), h in sorted(c.items())]}


if __name__ == "__main__":
    doc = json.dumps(build(), indent=1)
    if "--out" in sys.argv: Path(sys.argv[sys.argv.index("--out") + 1]).write_text(doc)
    else: print(doc)
