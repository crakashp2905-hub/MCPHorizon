"""Policies under test (P43-13 ablation). They see the graph (the trace a policy engine would see) and each re-implements its own authority/lineage: none imports the oracle's judgement.
D1 lexical-direct   : raw canary on the wire to a destination outside the principal's base grant.
D2 lineage-v1       : taint through transforms, grants+delegations+approvals, BUT approvals are checked at DECISION time and branches are not flag-sensitive (author-known modelling gaps).
D2b lineage-v2      : D2 with execution-time approval check and flag-aware branches.
D3 restrictive-rule : block any sink whose lineage touches a secret unless dest is in the base grant (no approvals, no delegation).
D4 learned-signature: blocks sink signatures seen violating in the TRAIN families (used for the split experiment)."""
from __future__ import annotations
from . import ir
from .oracle import values, envelope, SECRET_TEXT

KEEP = {"identity", "b64", "rot13", "reverse", "weak_sanitize"}


def _nodes(g, flag_aware): return ir.executing(g) if flag_aware else sorted(g["nodes"], key=lambda n: (n["t"], g["nodes"].index(n)))
def _tainted(g, nid, nodes):
    by = {n["id"]: n for n in nodes}; n = by.get(nid)
    if n is None: return False
    if n["type"] == "source": return n["op"] == "read_secret"
    if n["type"] == "transform" and n["op"] in ("hash", "redact"): return False
    return _tainted(g, n["inputs"][0], nodes)
def _base(g, p, seen=()):
    if p in seen: return set()
    out = set(g["principals"][p]["base_auth"])
    for a, b in g["delegations"]:
        if b == p: out |= _base(g, a, seen + (p,))
    return out
def chain(g, nid):
    out = []; n = ir.node(g, nid)
    while n and n["type"] != "source":
        if n["type"] == "transform" and n["op"] != "identity": out.append(n["op"])
        n = ir.node(g, n["inputs"][0])
    return tuple(reversed(out))
def sink_sig(g, s): return (s["dest"], chain(g, s["id"]))


def d1(g):
    vals = values(g)
    for s in ir.executing(g):
        if s["type"] != "sink": continue
        m, url, body = envelope(s["protocol"], 1, vals[s["id"]], s.get("prefix", ""))
        if SECRET_TEXT in (url + (body.decode() if body else "")) and s["dest"] not in g["principals"][s["principal"]]["base_auth"]: return "BLOCK"
    return "ALLOW"


def _lineage(g, flag_aware, exec_time):
    nodes = _nodes(g, flag_aware)
    for s in nodes:
        if s["type"] != "sink" or not _tainted(g, s["id"], nodes): continue
        t = s["t"] if exec_time else s.get("t_decide", s["t"])
        ok = s["dest"] in _base(g, s["principal"]) or any(a["id"] == s.get("approval") and a["dest"] == s["dest"] and a["principal"] == s["principal"] and a["issued_t"] <= t < a["issued_t"] + a["ttl"] for a in g["approvals"])
        if not ok: return "BLOCK"
    return "ALLOW"
def d2(g): return _lineage(g, False, False)
def d2b(g): return _lineage(g, True, True)


def d3(g):
    nodes = ir.executing(g)
    for s in nodes:
        if s["type"] == "sink" and _tainted_any(g, s["id"], nodes) and s["dest"] not in g["principals"][s["principal"]]["base_auth"]: return "BLOCK"
    return "ALLOW"
def _tainted_any(g, nid, nodes):
    by = {n["id"]: n for n in nodes}; n = by.get(nid)
    return False if n is None else (n["op"] == "read_secret" if n["type"] == "source" else _tainted_any(g, n["inputs"][0], nodes))


class D4:
    def __init__(self): self.bad = set()
    def fit(self, labeled):                     # labeled: [(graph, ids of sinks the oracle found violating)]
        for g, ids in labeled: self.bad |= {sink_sig(g, s) for s in ir.executing(g) if s["type"] == "sink" and s["id"] in ids}
        return self
    def __call__(self, g): return "BLOCK" if any(sink_sig(g, s) in self.bad for s in ir.executing(g) if s["type"] == "sink") else "ALLOW"


STATIC = {"D1-lexical": d1, "D2-lineage-v1": d2, "D2b-lineage-v2": d2b, "D3-restrictive": d3}
