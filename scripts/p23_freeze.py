#!/usr/bin/env python3
"""Freeze README + MCPWEEK5/6 research artifacts by SHA-256 (P23-01). Usage: p23_freeze.py [--check]. The signing key is generated ephemerally and DISCARDED; the signature therefore proves
integrity of the manifest body as of creation, not an identity. Re-freezing requires a new manifest file (never overwrite)."""
import glob, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from horizon.authz.keys import Signer
from horizon.runtime import provenance as PV
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); OUT = os.path.join(ROOT, "docs/evidence/p23/FREEZE_MANIFEST.json")
paths = sorted([os.path.join(ROOT, "README.md"), os.path.join(ROOT, "week1_report.md")] + [p for d in ("MCPWEEK5", "MCPWEEK6") for p in glob.glob(os.path.join(ROOT, d, "**", "*"), recursive=True) if os.path.isfile(p) and "__pycache__" not in p])
if "--check" in sys.argv:
    m = json.load(open(OUT)); pub = bytes.fromhex(m["public_key"]); ok = PV.verify_manifest(m["manifest"], pub); d = PV.verify_digests(m["manifest"], ROOT)
    print(json.dumps({"signature_ok": ok, **d})); sys.exit(0 if ok and d["ok"] else 1)
if os.path.exists(OUT): sys.exit("refusing to overwrite an existing freeze manifest")
s = Signer.generate("p23-freeze-ephemeral", "mcphorizon"); m = PV.freeze(paths, ROOT, s, note="P23-01 freeze; ephemeral key discarded")
json.dump({"public_key": s.public_raw().hex(), "manifest": m}, open(OUT, "w"), indent=1, sort_keys=True); print(len(m["body"]["files"]), "files frozen")
