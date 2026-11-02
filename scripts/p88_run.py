#!/usr/bin/env python3
"""P88 scenario matrix (SYNTHETIC, local): each attack has an otherwise-identical benign control. Write-once; --check re-derives."""
import hashlib, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
from horizon.approvalui import broker as B
OUT = os.path.join(ROOT, "results/v2/p88-approval")
OP = {"tool": "send_email", "target": "bob@x.test", "args": {"body": "hi", "attach": "a.txt"}}
class Clk:
    t = 0.0
    def __call__(s): return s.t
def fresh():
    c = Clk(); b = B.Broker(c); b.register_approver("alice", "S1"); b.register_agent("agent"); return c, b
def tok(b, op=OP, dest="smtp"):
    rid, _ = b.request(op, dest, 60); st, t = b.decide(rid, "alice", "S1", "https://ui.test", b.new_csrf("alice"), True); return rid, t
def run():
    S = []
    def case(name, attack, fn):
        c, b = fresh(); res = fn(c, b); S.append({"name": name, "attack": attack, "effect_allowed": res == "APPROVED"})
    case("benign_exact", False, lambda c, b: b.consume(tok(b)[1], OP, "smtp")[0])
    case("changed_args", True, lambda c, b: b.consume(tok(b)[1], dict(OP, args={"body": "hi", "attach": "key.pem"}), "smtp")[0])
    case("changed_dest", True, lambda c, b: b.consume(tok(b)[1], OP, "evil")[0])
    def replay(c, b):
        t = tok(b)[1]; b.consume(t, OP, "smtp"); return b.consume(t, OP, "smtp")[0]
    case("replay", True, replay)
    def revoked(c, b):
        r, t = tok(b); b.revoke(r); return b.consume(t, OP, "smtp")[0]
    case("revoked_before_effect", True, revoked)
    def stale(c, b):
        t = tok(b)[1]; b.rev = 2; return b.consume(t, OP, "smtp")[0]
    case("stale_policy", True, stale)
    def late(c, b):
        t = tok(b)[1]; c.t = 61; return b.consume(t, OP, "smtp")[0]
    case("expired", True, late)
    def agent(c, b):
        b.approvers["agent"] = "S1"; r, _ = b.request(OP, "smtp"); return b.decide(r, "agent", "S1", "https://ui.test", b.new_csrf("agent"), True)[0]
    case("agent_self_approval", True, agent)
    def origin(c, b):
        r, _ = b.request(OP, "smtp"); return b.decide(r, "alice", "S1", "https://evil.test", b.new_csrf("alice"), True)[0]
    case("bad_origin", True, origin)
    case("benign_origin", False, lambda c, b: b.decide(b.request(OP, "smtp")[0], "alice", "S1", "https://ui.test", b.new_csrf("alice"), True)[0])
    case("misleading_summary_flagged", True, lambda c, b: "APPROVED" if not B.summary_mismatch("Send a friendly note", OP) else "DENIED")
    case("honest_summary_not_flagged", False, lambda c, b: "APPROVED" if not B.summary_mismatch("bob@x.test hi a.txt", OP) else "DENIED")
    a = [s for s in S if s["attack"]]; g = [s for s in S if not s["attack"]]
    return {"cases": S, "attacks": len(a), "attack_effects_allowed": sum(s["effect_allowed"] for s in a), "benign": len(g), "benign_allowed": sum(s["effect_allowed"] for s in g),
            "note": "SYNTHETIC local broker; no real browser, UI framework, or human approver involved."}
def main():
    R = run()
    rf = os.path.join(OUT, "result.json")
    if "--check" in sys.argv:
        old = json.load(open(rf)); print("matches recorded run" if old == R else "MISMATCH"); sys.exit(0 if old == R else 1)
    if os.path.exists(rf): print("write-once"); sys.exit(2)
    os.makedirs(OUT, exist_ok=True); json.dump(R, open(rf, "w"), indent=1, sort_keys=True); json.dump({"result_sha256": hashlib.sha256(open(rf, "rb").read()).hexdigest()}, open(os.path.join(OUT, "manifest.json"), "w")); print(json.dumps({k: v for k, v in R.items() if k != "cases"}, indent=1))
main()
