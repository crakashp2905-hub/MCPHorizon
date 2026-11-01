"""Regression minimizer (P43-15): shrink a failing graph to a 1-minimal one while a predicate that includes the ORACLE's result stays true. Candidate edits: remove a node (rewiring its consumer to its input), drop a sink, weaken a transform to identity, drop approvals/delegations/flags that are not referenced."""
from __future__ import annotations
from . import ir


def _remove(g, nid):
    g = ir.clone(g); n = ir.node(g, nid)
    if n["type"] == "source" and any(nid in m.get("inputs", []) for m in g["nodes"]): return None          # a source is removable only when nothing consumes it
    if n["type"] == "transform":
        for m in g["nodes"]:
            if nid in m.get("inputs", []): m["inputs"] = [n["inputs"][0] if i == nid else i for i in m["inputs"]]
        g["nodes"].remove(n); return g
    g["nodes"].remove(n)                       # sink (or unconsumed source)
    return g


def _identity(g, nid):
    n = ir.node(g, nid)
    if n["type"] != "transform" or n["op"] == "identity": return None
    g = ir.clone(g); ir.node(g, nid)["op"] = "identity"; return g


def _trim(g):
    g = ir.clone(g); used = {s.get("approval") for s in ir.sinks(g)}; g["approvals"] = [a for a in g["approvals"] if a["id"] in used]
    flags = {k for n in g["nodes"] for k in n.get("guard", {})}; g["flags"] = {k: v for k, v in g["flags"].items() if k in flags}; return g


def candidates(g):
    for n in list(g["nodes"]):
        for f in (_remove, _identity):
            c = f(g, n["id"])
            if c is not None and not ir.feasibility(c) and c["nodes"]: yield c


def minimize(g, predicate, max_rounds=40):
    """predicate(graph)->bool must hold for g. Returns (minimal_graph, evaluations). Deterministic."""
    assert predicate(g); evals = 1; cur = g
    for _ in range(max_rounds):
        progressed = False
        for c in candidates(cur):
            evals += 1
            if predicate(c): cur = c; progressed = True; break
        if not progressed: break
    t = _trim(cur)
    if t != cur and not ir.feasibility(t): evals += 1; cur = t if predicate(t) else cur
    return cur, evals


def is_one_minimal(g, predicate) -> bool:
    return not any(predicate(c) for c in candidates(g))


def pad(g):
    """Add irrelevant structure (identity hops before every sink, an unrelated note->INT sink) so there is something to minimize. Does not change who is authorized."""
    g = ir.clone(g)
    for s in [n for n in g["nodes"] if n["type"] == "sink"]:
        prev = s["inputs"][0]
        for k in range(2):
            nid = "pad%s%d" % (s["id"], k); g["nodes"].insert(g["nodes"].index(s), {"id": nid, "type": "transform", "principal": s["principal"], "t": max(ir.node(g, prev)["t"], 0), "inputs": [prev], "op": "identity", **({"guard": dict(s["guard"])} if s.get("guard") else {})}); prev = nid
        s["inputs"] = [prev]
    g["nodes"] += [{"id": "padsrc", "type": "source", "principal": "agent-a", "t": 0, "op": "read_note"}, {"id": "padsnk", "type": "sink", "principal": "agent-a", "t": 1, "inputs": ["padsrc"], "dest": "INT", "protocol": "http", "approval": None}]
    return g
