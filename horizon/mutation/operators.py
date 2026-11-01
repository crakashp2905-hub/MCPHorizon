"""Mutation operator schema + operators (P43-02..07). Each operator declares: id, family of change, preconditions (an enumerator of feasible parameters), a predicted relation (SAME | CHANGE | UNKNOWN), a confidence flag, and oracle obligations.
The predicted relation is an INTENT heuristic written from syntax; the oracle decides ground truth and the disagreement rate is reported (P43-14)."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
from . import ir
from .oracle import grants

RELATIONS = ("SAME", "CHANGE", "UNKNOWN"); CONFIDENCE = ("high", "medium", "low")


@dataclass(frozen=True)
class Operator:
    id: str; kind: str; enumerate_params: Callable; apply: Callable; predict: Callable; confidence: str; obligation: str
    def describe(self): return {"id": self.id, "kind": self.kind, "confidence": self.confidence, "obligation": self.obligation}


def _sink_ids(g): return [n["id"] for n in ir.sinks(g)]
def _fresh(g, base="m"):
    k = 1
    while ir.node(g, "%s%d" % (base, k)): k += 1
    return "%s%d" % (base, k)


# --- P43-03 protocol swap ------------------------------------------------------------------------------------------------------------------------------------------------------------
def proto_params(g): return [{"sink": s["id"], "protocol": p} for s in ir.sinks(g) for p in ir.PROTOCOLS if p != s["protocol"]]
def proto_apply(g, p): g = ir.clone(g); ir.node(g, p["sink"])["protocol"] = p["protocol"]; return g

# --- P43-04 role / principal transfer (explicit authority constraint: the new principal must exist; transfer is only 'authority-preserving' when a delegation edge links them) ---
def role_params(g): return [{"node": n["id"], "principal": q} for n in g["nodes"] if n["type"] in ("transform", "sink") for q in g["principals"] if q != n["principal"]]
def role_apply(g, p): g = ir.clone(g); ir.node(g, p["node"])["principal"] = p["principal"]; return g
def role_predict(g, p):
    n = ir.node(g, p["node"]); linked = [n["principal"], p["principal"]] in g["delegations"] or [p["principal"], n["principal"]] in g["delegations"]
    if n["type"] != "sink": return "SAME"
    return "SAME" if linked else "UNKNOWN"          # syntax cannot know the target principal's grants: low-confidence UNKNOWN prior, oracle decides

# --- P43-05 dependency order and workflow branch (feasibility checked by ir.feasibility) -------------------------------------------------------------------------------------
def order_params(g):
    out = []; ns = g["nodes"]
    for i, a in enumerate(ns):
        for b in ns[i + 1:]:
            if a["type"] == "sink" and b["type"] == "sink" and a["t"] != b["t"] and not (a.get("guard") or b.get("guard")): out.append({"a": a["id"], "b": b["id"]})
    return out
def order_apply(g, p): g = ir.clone(g); a, b = ir.node(g, p["a"]), ir.node(g, p["b"]); a["t"], b["t"] = b["t"], a["t"]; return g
def presink_params(g):
    out = []
    for s in ir.sinks(g):
        if s.get("approval"):
            a = next(a for a in g["approvals"] if a["id"] == s["approval"]); src_t = max(ir.node(g, i)["t"] for i in s["inputs"])
            if a["issued_t"] - 1 >= src_t: out.append({"sink": s["id"], "t": a["issued_t"] - 1})
    return out
def presink_apply(g, p): g = ir.clone(g); ir.node(g, p["sink"])["t"] = p["t"]; return g
def branch_params(g):
    out = []
    for k in {k for n in g["nodes"] for k in n.get("guard", {})}:
        vals = {v for n in g["nodes"] for kk, v in n.get("guard", {}).items() if kk == k}
        for v in sorted(vals):
            if g["flags"].get(k) != v: out.append({"flag": k, "value": v})
    return out
def branch_apply(g, p): g = ir.clone(g); g["flags"][p["flag"]] = p["value"]; return g

# --- P43-06 sanitization / lineage ------------------------------------------------------------------------------------------------------------------------------------------------
INSERT_OPS = ("identity", "b64", "rot13", "reverse", "hash", "redact", "weak_sanitize")
def san_params(g):
    out = []
    for n in g["nodes"]:
        if n["type"] == "sink":
            for op in INSERT_OPS: out.append({"before": n["id"], "op": op})
    return out
def san_apply(g, p):
    g = ir.clone(g); s = ir.node(g, p["before"]); nid = _fresh(g); t = max(ir.node(g, s["inputs"][0])["t"], s["t"] - 1)
    new = {"id": nid, "type": "transform", "principal": s["principal"], "t": t, "inputs": list(s["inputs"]), "op": p["op"]}
    if s.get("guard"): new["guard"] = dict(s["guard"])
    s["inputs"] = [nid]; g["nodes"].insert(g["nodes"].index(s), new); return g
def san_predict(g, p):
    if p["op"] in ("identity", "b64", "rot13", "reverse"): return "SAME"
    if p["op"] in ("hash", "redact"): return "CHANGE"
    return "UNKNOWN"
def unsan_params(g): return [{"node": n["id"]} for n in g["nodes"] if n["type"] == "transform" and n["op"] in ir.CLEARS]
def unsan_apply(g, p):
    g = ir.clone(g); n = ir.node(g, p["node"]); src = n["inputs"][0]
    for m in g["nodes"]:
        if p["node"] in m.get("inputs", []): m["inputs"] = [src if i == p["node"] else i for i in m["inputs"]]
    g["nodes"].remove(n); return g

# --- destination change -------------------------------------------------------------------------------------------------------------------------------------------------------------
def dest_params(g): return [{"sink": s["id"], "dest": d} for s in ir.sinks(g) for d in ir.DESTS if d != s["dest"]]
def dest_apply(g, p): g = ir.clone(g); ir.node(g, p["sink"])["dest"] = p["dest"]; return g
def dest_predict(g, p):
    s = ir.node(g, p["sink"]); base = set(g["principals"][s["principal"]]["base_auth"])
    return "CHANGE" if (p["dest"] in base) != (s["dest"] in base) else "SAME"       # looks only at the base grant: ignores delegation and approvals on purpose (cheap heuristic)

# --- P43-07 trusted temporal -------------------------------------------------------------------------------------------------------------------------------------------------------
def delay_params(g):
    out = []
    for s in ir.sinks(g):
        if s.get("approval"):
            a = next(a for a in g["approvals"] if a["id"] == s["approval"])
            for d in (1, a["ttl"] + 1, 3 * a["ttl"]): out.append({"sink": s["id"], "delay": d})
    return out
def delay_apply(g, p):
    g = ir.clone(g); n = ir.node(g, p["sink"]); n.setdefault("t_decide", n["t"]); n["t"] += p["delay"]; return g          # execution moves, the decision time (t_decide) stays: a delayed effect
def delay_predict(g, p):
    s = ir.node(g, p["sink"]); a = next(a for a in g["approvals"] if a["id"] == s["approval"]); before = s["t"] < a["issued_t"] + a["ttl"]; after = s["t"] + p["delay"] < a["issued_t"] + a["ttl"]
    return "SAME" if before == after else "CHANGE"
def ttl_params(g): return [{"approval": a["id"], "ttl": t} for a in g["approvals"] for t in (1, 2, 50) if t != a["ttl"]]
def ttl_apply(g, p): g = ir.clone(g); next(a for a in g["approvals"] if a["id"] == p["approval"])["ttl"] = p["ttl"]; return g


OPERATORS = (
    Operator("OP-PROTO-SWAP", "protocol", proto_params, proto_apply, lambda g, p: "SAME", "high", "same data reaches the same destination through an equivalent HTTP/MCP/UTCP encoding"),
    Operator("OP-ROLE-TRANSFER", "principal", role_params, role_apply, role_predict, "low", "authority of the new principal is evaluated by the oracle, never assumed"),
    Operator("OP-ORDER-SWAP", "order", order_params, order_apply, lambda g, p: "SAME", "medium", "independent sinks exchange execution slots; verdict per sink must not change"),
    Operator("OP-SINK-BEFORE-APPROVAL", "order", presink_params, presink_apply, lambda g, p: "CHANGE", "high", "sink runs before the approval it cites exists"),
    Operator("OP-BRANCH-FLIP", "branch", branch_params, branch_apply, lambda g, p: "CHANGE", "medium", "alternative workflow branch executes; feasibility of its inputs is checked first"),
    Operator("OP-SANITIZE-INSERT", "lineage", san_params, san_apply, san_predict, "medium", "safe-redaction table vs real bytes at the receiver"),
    Operator("OP-SANITIZE-REMOVE", "lineage", unsan_params, unsan_apply, lambda g, p: "CHANGE", "medium", "removing a clearing transform re-exposes the value"),
    Operator("OP-DEST-CHANGE", "destination", dest_params, dest_apply, dest_predict, "medium", "authorization of the new destination decided by declared grants/approvals"),
    Operator("OP-TEMPORAL-DELAY", "temporal", delay_params, delay_apply, delay_predict, "medium", "approval validity evaluated at the (real) execution time"),
    Operator("OP-APPROVAL-TTL", "temporal", ttl_params, ttl_apply, lambda g, p: "UNKNOWN", "low", "ttl change moves the validity window; oracle decides"),
)
BY_ID = {o.id: o for o in OPERATORS}


def operators_digest(): return ir.digest([o.describe() for o in OPERATORS])
