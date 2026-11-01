"""Typed execution-graph IR (P43-01). A graph is plain JSON-able data: principals, delegations, approvals, flags and an ordered list of typed nodes (source | transform | sink). Maps 1:1 onto canonical events (`to_events`), validated against the repo's event schema."""
from __future__ import annotations
import copy, hashlib, json
from .. import schemas

SCHEMA = "mutation-graph/1.0.0"
DESTS = ("INT", "PAR", "EXT")                      # loopback receivers: internal, partner, external
PROTOCOLS = ("http", "mcp", "utcp")
SOURCE_OPS = ("read_secret", "read_note")
TRANSFORM_OPS = ("identity", "b64", "rot13", "reverse", "hash", "redact", "weak_sanitize")
KEEPS = {"identity", "b64", "rot13", "reverse"}     # declared lineage semantics: sensitive stays sensitive
CLEARS = {"hash", "redact"}                         # one-way / replaced: lineage clean (checked against bytes by the oracle)
PARTIAL = {"weak_sanitize"}                         # lineage says sensitive, bytes lose the canary -> oracles disagree -> UNKNOWN
MAX_NODES = 12
TOOL = {"source": "files.read", "transform": "text.transform", "sink": "net.send"}      # tool names are shared by attack and benign twins on purpose


def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":"))
def digest(x): return hashlib.sha256(canon(x).encode()).hexdigest()
def clone(g): return copy.deepcopy(g)
def node(g, nid): return next((n for n in g["nodes"] if n["id"] == nid), None)
def sinks(g): return [n for n in g["nodes"] if n["type"] == "sink"]


def executing(g) -> list:
    """Nodes that run, in execution order (t, then list position). Guards select branches via g['flags']."""
    out = [n for n in g["nodes"] if all(g["flags"].get(k) == v for k, v in n.get("guard", {}).items())]
    return sorted(out, key=lambda n: (n["t"], g["nodes"].index(n)))


def feasibility(g) -> list:
    """Hard preconditions: a graph that fails is INVALID (cannot be executed meaningfully), independent of any security verdict."""
    errs = []; ids = [n["id"] for n in g["nodes"]]
    if len(ids) != len(set(ids)): errs.append("duplicate node id")
    if len(ids) > MAX_NODES: errs.append("too many nodes")
    run = {n["id"]: n for n in executing(g)}; order = [n["id"] for n in executing(g)]
    for n in g["nodes"]:
        if n["type"] == "source" and n["op"] not in SOURCE_OPS: errs.append("bad source op " + n["op"])
        if n["type"] == "transform" and n["op"] not in TRANSFORM_OPS: errs.append("bad transform op " + n["op"])
        if n["type"] == "sink" and (n["dest"] not in DESTS or n["protocol"] not in PROTOCOLS): errs.append("bad sink " + n["id"])
        if n["type"] not in ("source", "transform", "sink"): errs.append("bad type")
        if n["principal"] not in g["principals"]: errs.append("unknown principal " + n["principal"])
        if n["type"] == "source" and n.get("inputs"): errs.append("source with inputs")
        if n["type"] != "source" and len(n.get("inputs", [])) != 1: errs.append("%s needs exactly one input" % n["id"])
    for n in g["nodes"]:
        if n["id"] not in run: continue
        for i in n.get("inputs", []):
            if node(g, i) is None: errs.append("%s: unknown input %s" % (n["id"], i))
            elif i not in run: errs.append("%s: input %s does not execute under the flags" % (n["id"], i))
            elif order.index(i) >= order.index(n["id"]) or run[i]["t"] > n["t"]: errs.append("%s: input %s not produced before use" % (n["id"], i))
    for a in g["approvals"]:
        if a["dest"] not in DESTS or a["principal"] not in g["principals"] or a["ttl"] <= 0: errs.append("bad approval " + a["id"])
    for s in sinks(g):
        if s.get("approval") and not any(a["id"] == s["approval"] for a in g["approvals"]): errs.append("%s: unknown approval" % s["id"])
    return errs


def to_events(g, run_id="run-mutation") -> list:
    """Canonical event per executing node (P43-01). Every event is validated against horizon.schemas by the tests."""
    ev = []
    for k, n in enumerate(executing(g)):
        dest = n.get("dest"); proto = {"http": "native", "mcp": "mcp", "utcp": "utcp"}.get(n.get("protocol"), "native")
        e = {"schema_version": "2.0.0", "event_id": "%s-%s" % (g["id"], n["id"]), "run_id": run_id, "principal_id": n["principal"], "principal_source": "trusted_host_identity", "source_protocol": proto, "protocol_version": "1",
             "phase": "before_call", "logical_operation": {"source": "file.read", "transform": "text.transform", "sink": "net.send"}[n["type"]], "native_operation": n.get("op", "send"), "tool_id": TOOL[n["type"]],
             "target": {"kind": "url" if dest else "resource", "canonical_id": ("loopback://%s" % dest) if dest else "mutation:%s" % n["id"]}, "args_digest": "sha256:" + digest({"n": n["id"], "op": n.get("op"), "i": n.get("inputs")}),
             "monotonic_seq": k, "wall_time": "2026-01-01T00:%02d:%02dZ" % divmod(min(n["t"], 3599), 60)}
        if n.get("inputs"): e["inputs"] = [{"artifact_id": "artifact:%s" % i} for i in n["inputs"]]
        if n.get("approval"): e["authorization_ref"] = "approval:" + n["approval"]
        ev.append(e)
    return ev


def validate_events(g) -> list:
    errs = []
    for e in to_events(g): errs += schemas.validate("event", e)
    return errs
