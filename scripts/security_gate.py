#!/usr/bin/env python3
"""P28-16: branch-specific security gate over the intentionally-vulnerable fixtures. Labels are strict: PASS only when every expectation was MET with all tools available; otherwise UNKNOWN / UNSUPPORTED / FAIL.
Never prints a PASS for something it could not run."""
import json, os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.runtime import artifacts as A, sandbox as S
DB = {"advisories": [{"id": "HZ-2026-0001", "package": "libfoo", "introduced": "1.0.0", "fixed": "1.2.0", "severity": "HIGH"}]}; DG = A.sha(A._msg(DB["advisories"])); DEPS = "libfoo==1.3.0\n"
CASES = [(n, v, "BLOCK" if v == "vulnerable" else "ALLOW") for n in ("sqli", "traversal", "cmdinj", "authz") for v in ("vulnerable", "patched")] + [(n, "patched", "ALLOW") for n in ("benign_a", "benign_b", "benign_c")]
def branch():
    try: return subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip() or "unknown"
    except OSError: return "unknown"
def main():
    if os.geteuid() != 0 or S.landlock_abi() < 4: print(json.dumps({"branch": branch(), "status": "UNSUPPORTED", "why": "root + Landlock required for the exploit oracle"})); return 0
    rows, mism = [], []
    for n, v, want in CASES:
        e = A.evidence(A.fixture(n, v), deps_text=DEPS, db=DB, db_digest=DG); g = A.gate(e); rows.append({"case": f"{n}/{v}", "want": want, "got": g["decision"], "reasons": g["reasons"], "residual": g["residual"]})
        if g["decision"] != want: mism.append(f"{n}/{v}: want {want} got {g['decision']}")
    unknown = [r["case"] for r in rows if r["got"] == "UNKNOWN"]
    status = "UNKNOWN" if unknown else ("FAIL" if mism else "PASS")
    out = {"branch": branch(), "status": status, "cases": len(rows), "mismatches": mism, "rows": rows, "scope": "PASS means: on this fixture set, every vulnerable build was BLOCKED and every patched/benign build ALLOWED. It says nothing about unseen vulnerability classes."}
    print(json.dumps(out, indent=1)); return 0 if status in ("PASS",) else 1
if __name__ == "__main__": sys.exit(main())
