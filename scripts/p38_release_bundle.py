#!/usr/bin/env python3
"""P38-16: signed release evidence bundle for P23-P38. Reuses the P30 bundle format (tar + sha256 manifest + Ed25519 signature) with the P31-P38 evidence added.
The signing key is EPHEMERAL unless --key is given: the signature proves bundle integrity, NOT the identity of the author and NOT any independent review. Usage: build OUT.tar [--key PEM] | verify OUT.tar"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)))); import p30_reviewer_bundle as RB
RB.INCLUDE = list(RB.INCLUDE) + ["docs/evidence/p31", "docs/evidence/p32", "docs/evidence/p33", "docs/evidence/p34", "docs/evidence/p35", "docs/evidence/p36", "docs/evidence/p37", "docs/evidence/p38", "docs/papers", "docs/security/LAYER_THREAT_MODELS.md",
    "results/v2/p32-triggerlab", "results/v2/p33-hccb", "results/v2/p36-checkov-compare", "results/v2/h4-main", "research/incident-casebook", "benchmarks/h4", "benchmarks/hieb", "benchmarks/hccb", "benchmarks/horizon-trigger-lab",
    "bench/h4", "horizon/weights", "horizon/triggerlab", "horizon/codeassur", "horizon/agents", "horizon/telemetry", "horizon/infraguard", "tests/p31", "tests/p32", "tests/p33", "tests/p34", "tests/p35", "tests/p36", "tests/p37", "tests/p38",
    "scripts/p38_casebook.py", "scripts/p38_compare.py", "scripts/p38_gates.py", "scripts/p38_papers.py", "scripts/p38_runner_check.py", "scripts/p38_sink_repro.py", "scripts/p38_clean_repro.py", "scripts/p37_demo.py", "spec/acceptance.json", "docs/implementation/STATUS.md"]
if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "build":
        key = a[a.index("--key") + 1] if "--key" in a else None; man = RB.build(a[1], key); man["status"] = "CANDIDATE"; print("built", a[1], len(man["files"]), "files; key", "supplied" if key else "EPHEMERAL")
    elif a and a[0] == "verify":
        p = RB.verify(a[1]); print("VERIFY", "OK" if not p else p); sys.exit(1 if p else 0)
    else: sys.exit("usage: build OUT.tar [--key PEM] | verify OUT.tar")
