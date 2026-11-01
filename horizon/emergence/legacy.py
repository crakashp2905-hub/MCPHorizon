"""Frozen reimplementation of the legacy flat-capability closure (P39-01). Source: results/hypergraph.json and capability_engine.closure of the Week-1 prototype (project docs). Do not 'improve' it: it is the baseline."""
import json, os
EDGES = [(frozenset(e["premise"]), frozenset(e["conclusion"]), e["label"]) for e in json.load(open(os.path.join(os.path.dirname(__file__), "legacy_hypergraph.json")))]
OP_CAPS = {"read_secret": {"read_filesystem_credentials"}, "get": {"network_send_external"}, "post": {"network_send_external"}}     # the only op->capability facts the legacy TOOL_DB style can express here


def closure(state, edges=EDGES):
    st = set(state); ch = True
    while ch:
        ch = False
        for p, c, _ in edges:
            if p <= st and not c <= st: st |= c; ch = True
    return st


def legacy_alert(ops) -> bool:
    caps = set()
    for o in ops: caps |= OP_CAPS.get(o, set())
    return "credential_exfiltration_setup" in closure(caps)
