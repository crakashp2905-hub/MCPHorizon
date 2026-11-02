#!/usr/bin/env python3
"""P87 two-agent scenario (SYNTHETIC, local): authorized delegation + otherwise-identical unauthorized controls. Write-once; --check."""
import hashlib, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.a2a import delegation as D
OUT = os.path.join(ROOT, "results/v2/p87-delegation")
class Clk:
    t = 0.0
    def __call__(s): return s.t
def run():
    S = []
    def case(name, attack, f):
        c = Clk(); a = D.Authority(c); r = a.root("owner", "A", "A", "t1", ["read", "send"], 100); ab = a.delegate(r, "B", "svc", ["read"], 50)
        ok = f(c, a, r, ab); S.append({"name": name, "attack": attack, "effect_allowed": bool(ok)})
    V = lambda a, ch, **k: a.verify_chain(ch, **dict(dict(verifier="svc", tenant="t1", op="read"), **k))[0]
    case("authorized_read", False, lambda c, a, r, ab: V(a, [r, ab]))
    case("unauthorized_send_beyond_scope", True, lambda c, a, r, ab: V(a, [r, ab], op="send"))
    case("wrong_audience", True, lambda c, a, r, ab: V(a, [r, ab], verifier="other"))
    def replay(c, a, r, ab): V(a, [r, ab]); return V(a, [r, ab])
    case("replay", True, replay)
    case("expired", True, lambda c, a, r, ab: (setattr(c, "t", 60), V(a, [r, ab]))[1])
    case("cross_tenant", True, lambda c, a, r, ab: V(a, [r, ab], tenant="t2"))
    def forged(c, a, r, ab):
        bc = a.delegate(ab, "C", "svc", ["read"], 10); g = {k: bc[k] for k in D.FIELDS}; g["scope"] = ["read", "send"]; g["sig"] = a._sig(g); return V(a, [r, ab, g], op="send")
    case("signed_privilege_expansion", True, forged)
    case("revoked_ancestor", True, lambda c, a, r, ab: (a.revoke(r), V(a, [r, ab]))[1])
    cb = {"t1": ["https://cb.t1.test/hook"]}
    case("benign_callback", False, lambda c, a, r, ab: D.callback_allowed(cb, "t1", "https://cb.t1.test/hook"))
    case("foreign_callback", True, lambda c, a, r, ab: D.callback_allowed(cb, "t1", "https://evil.test/x"))
    case("benign_artifact", False, lambda c, a, r, ab: D.artifact_may_influence({"provenance_verified": True, "origin_tenant": "t1", "tenant": "t1", "untrusted_instructions": False}, True))
    case("injected_artifact", True, lambda c, a, r, ab: D.artifact_may_influence({"provenance_verified": True, "origin_tenant": "t1", "tenant": "t1", "untrusted_instructions": True}, True))
    A = [s for s in S if s["attack"]]; G = [s for s in S if not s["attack"]]
    return {"cases": S, "attacks": len(A), "attack_effects_allowed": sum(s["effect_allowed"] for s in A), "benign": len(G), "benign_allowed": sum(s["effect_allowed"] for s in G),
            "note": "SYNTHETIC local authority, no A2A SDK/wire, no remote agents or real network. CG-11 not passed."}
def main():
    R = run(); rf = os.path.join(OUT, "result.json")
    if "--check" in sys.argv:
        old = json.load(open(rf)); print("matches recorded run" if old == R else "MISMATCH"); sys.exit(0 if old == R else 1)
    if os.path.exists(rf): print("write-once"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); json.dump(R, open(rf, "w"), indent=1, sort_keys=True); json.dump({"result_sha256": hashlib.sha256(open(rf, "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w")); print(json.dumps({k: v for k, v in R.items() if k != "cases"}, indent=1))
main()
