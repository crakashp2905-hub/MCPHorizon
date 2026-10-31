"""Bounded tool-schema handling (P4-12). Tool schemas come from untrusted servers: bound size/depth/nodes, forbid non-local references,
and never silently under-enforce (unsupported keywords => UNVALIDATED, which the gate treats as a denial for protected effects)."""
from __future__ import annotations
import json
from ...jsonschema_lite import validate as _validate, check_bounds

MAX_BYTES, MAX_DEPTH, MAX_NODES = 65_536, 16, 2_000
REF_KEYS = {"$ref", "$dynamicRef", "$recursiveRef"}


def check_schema_document(schema) -> list[str]:
    if not isinstance(schema, dict): return ["schema must be an object"]
    try: raw = json.dumps(schema, sort_keys=True)
    except (TypeError, ValueError): return ["schema is not JSON-serializable"]
    if len(raw) > MAX_BYTES: return [f"schema exceeds {MAX_BYTES} bytes"]
    probs, nodes = [], [0]
    def walk(v, d):
        nodes[0] += 1
        if d > MAX_DEPTH: probs.append("schema nesting too deep"); return
        if nodes[0] > MAX_NODES: probs.append("schema has too many nodes"); return
        if isinstance(v, dict):
            for k, x in v.items():
                if k in REF_KEYS and not (isinstance(x, str) and x.startswith("#")): probs.append(f"non-local {k} {str(x)[:80]!r} is forbidden (no remote retrieval)")
                walk(x, d + 1)
        elif isinstance(v, list):
            for x in v: walk(x, d + 1)
    walk(schema, 0)
    return probs[:10]


def validate_args(schema: dict, args) -> tuple[str, list[str]]:
    """('VALID'|'INVALID'|'UNVALIDATED', errors). UNVALIDATED means the schema uses keywords this bounded validator does not evaluate."""
    bad = check_schema_document(schema)
    if bad: return "UNVALIDATED", bad
    b = check_bounds(args)
    if b: return "INVALID", [b]
    errs = _validate(args, schema)
    if any("unsupported keyword" in e for e in errs): return "UNVALIDATED", errs[:5]
    return ("INVALID", errs[:10]) if errs else ("VALID", [])
