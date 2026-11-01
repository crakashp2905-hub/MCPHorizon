#!/usr/bin/env python3
"""P42-16 release gate: collects LIVE coverage evidence and fails unless every protection claim in spec/protection_claims.json is SUPPORTED (all its sinks VERIFIED now). Unsupported claims must stay out of the release notes. Needs root + Landlock ABI>=4 (exit 3 otherwise: no evidence = no claim)."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.coverage import harness as H, engine as EN


def gate(claims, bundle, now=None):
    rep = EN.evaluate(bundle, EN.components(), (bundle["issued_at"] + 1) if now is None else now)
    return EN.claims_status({k: v for k, v in claims.items() if k != "unsupported_do_not_claim"}, rep)


if __name__ == "__main__":
    ok, why = H.sandbox_available()
    if not ok: print("NO EVIDENCE:", why); sys.exit(3)
    claims = json.load(open(os.path.join(ROOT, "spec/protection_claims.json"))); b = EN.collect(); st = gate(claims, b)
    for k, v in st.items(): print(("SUPPORTED  " if v["supported"] else "BLOCKED    ") + k, v["blocking"] or "")
    print("not claimable:", "; ".join(claims["unsupported_do_not_claim"])); bad = [k for k, v in st.items() if not v["supported"]]
    print("release gate:", "PASS" if not bad else "FAIL " + ",".join(bad)); sys.exit(1 if bad else 0)
