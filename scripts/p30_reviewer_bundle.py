#!/usr/bin/env python3
"""Build a signed independent-reviewer bundle (P30-16): tar of the evidence a reviewer needs + manifest of sha256 + Ed25519 signature over the manifest.
The signing key is EPHEMERAL unless --key is given: the signature proves integrity of this bundle, NOT the identity of the author. `verify` re-hashes every member.
Usage: p30_reviewer_bundle.py build OUT.tar [--key PEMFILE] | verify OUT.tar"""
import hashlib, io, json, os, sys, tarfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from horizon.authz.keys import Signer
INCLUDE = ["docs/security/P30_REVIEWER_THREAT_MODEL.md", "docs/security/P30_KERNEL_LIMITS.md", "docs/evidence/p29", "docs/evidence/p30", "docs/evidence/HR_GATES.md", "results/v2/haa-main", "results/v2/haa-heldout", "results/v2/haa-adaptive", "results/v2/haa-latency",
           "horizon/runtime", "bench/haa", "benchmarks/horizon-agent-anomaly", "tests/p24", "tests/p25", "tests/p26", "tests/p27", "tests/p28", "tests/p29", "tests/p30", "scripts/p30_no_external.py", "scripts/hr_gates.py"]
def members():
    out = []
    for p in INCLUDE:
        a = os.path.join(ROOT, p)
        if os.path.isfile(a): out.append(p)
        elif os.path.isdir(a):
            for dp, dn, fn in os.walk(a):
                dn[:] = sorted(d for d in dn if d != "__pycache__")
                out += [os.path.relpath(os.path.join(dp, f), ROOT) for f in sorted(fn) if not f.endswith(".pyc")]
    return sorted(set(out))
def build(out, key=None):
    sg = Signer.load("reviewer-bundle", "mcphorizon", key) if key else Signer.generate("reviewer-bundle", "mcphorizon")
    man = {"kind": "mcphorizon-reviewer-bundle", "status": "CANDIDATE", "files": {m: hashlib.sha256(open(os.path.join(ROOT, m), "rb").read()).hexdigest() for m in members()}, "public_key_hex": sg.public_raw().hex(), "key_is_ephemeral": key is None,
           "not_included": ["live-model (L3) results: none exist", "independent review: none has occurred"]}
    mb = json.dumps(man, sort_keys=True, indent=1).encode(); sig = sg.sign(mb)
    with tarfile.open(out, "w") as t:
        for name, data in (("MANIFEST.json", mb), ("MANIFEST.sig", sig.hex().encode())):
            i = tarfile.TarInfo(name); i.size = len(data); i.mtime = 0; t.addfile(i, io.BytesIO(data))
        for m in man["files"]: t.add(os.path.join(ROOT, m), arcname="files/" + m, filter=lambda ti: (setattr(ti, "mtime", 0), setattr(ti, "uid", 0), setattr(ti, "gid", 0), setattr(ti, "uname", ""), setattr(ti, "gname", ""), ti)[-1])
    return man
def verify(path):
    problems = []
    with tarfile.open(path) as t:
        mb = t.extractfile("MANIFEST.json").read(); sig = bytes.fromhex(t.extractfile("MANIFEST.sig").read().decode()); man = json.loads(mb)
        try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(man["public_key_hex"])).verify(sig, mb)
        except Exception: problems.append("BAD_SIGNATURE")
        names = {m.name for m in t.getmembers() if m.name.startswith("files/")}
        if names != {"files/" + f for f in man["files"]}: problems.append("MEMBER_SET_MISMATCH")
        for f, h in man["files"].items():
            try:
                if hashlib.sha256(t.extractfile("files/" + f).read()).hexdigest() != h: problems.append("HASH_MISMATCH " + f)
            except KeyError: problems.append("MISSING " + f)
    return problems
if __name__ == "__main__":
    if sys.argv[1] == "build": m = build(sys.argv[2], sys.argv[sys.argv.index("--key") + 1] if "--key" in sys.argv else None); print("built", sys.argv[2], len(m["files"]), "files")
    else: p = verify(sys.argv[2]); print("\n".join(p) or "bundle OK"); sys.exit(1 if p else 0)
