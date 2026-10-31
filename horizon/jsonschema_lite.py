"""Minimal, bounded JSON Schema (2020-12 subset) validator. Stdlib only.

Supports: type, enum, const, required, properties, additionalProperties(bool), items, minItems, maxItems,
uniqueItems, minLength, maxLength, pattern, minimum, maximum, oneOf, $ref (#/$defs/..).
Rejects (does not evaluate) any other keyword so schemas cannot silently be under-enforced.
Hard bounds on depth / node count / string size make hostile input a rejection, not a DoS.
"""
from __future__ import annotations
import json, math, re

MAX_DEPTH, MAX_NODES, MAX_STR = 32, 20000, 65536
KNOWN = {"$schema", "$id", "$defs", "$ref", "title", "description", "type", "enum", "const", "required",
         "properties", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "minLength",
         "maxLength", "pattern", "minimum", "maximum", "oneOf"}
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _ecma(pat: str) -> str:
    """JSON Schema patterns are unanchored searches; ECMA `$` has no trailing-newline allowance, Python's does."""
    return pat[:-1] + r"\Z" if pat.endswith("$") and not pat.endswith("\\$") else pat


def _is_type(v, t):
    if t == "integer": return isinstance(v, int) and not isinstance(v, bool)
    if t == "number": return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
    return isinstance(v, TYPES[t])


def check_bounds(v, depth=0, counter=None) -> str | None:
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if depth > MAX_DEPTH: return "document nesting exceeds limit"
    if counter[0] > MAX_NODES: return "document too large (node count)"
    if isinstance(v, str):
        if len(v) > MAX_STR: return "string exceeds size limit"
        if "\x00" in v: return "string contains NUL byte"
    elif isinstance(v, float) and not math.isfinite(v): return "non-finite number"
    elif isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str) or "\x00" in k: return "bad object key"
            e = check_bounds(x, depth + 1, counter)
            if e: return e
    elif isinstance(v, list):
        for x in v:
            e = check_bounds(x, depth + 1, counter)
            if e: return e
    return None


def validate(instance, schema: dict, root: dict | None = None, path: str = "$") -> list[str]:
    root = root or schema
    if path == "$":
        b = check_bounds(instance)
        if b: return [f"$: {b}"]
    errs: list[str] = []
    bad = set(schema) - KNOWN
    if bad: return [f"{path}: schema uses unsupported keyword(s) {sorted(bad)}"]
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/") or ref[8:] not in root.get("$defs", {}):
            return [f"{path}: unresolvable $ref {ref}"]
        return validate(instance, root["$defs"][ref[8:]], root, path)
    if "type" in schema:
        ts = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(instance, t) for t in ts):
            return [f"{path}: expected {'/'.join(ts)}, got {type(instance).__name__}"]
    if "const" in schema and (instance != schema["const"] or type(instance) is not type(schema["const"])):
        errs.append(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and not any(instance == e and type(instance) is type(e) for e in schema["enum"]):
        errs.append(f"{path}: {instance!r} not in allowed values {schema['enum']}")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]: errs.append(f"{path}: too short")
        if "maxLength" in schema and len(instance) > schema["maxLength"]: errs.append(f"{path}: too long")
        if "pattern" in schema and not re.search(_ecma(schema["pattern"]), instance):
            errs.append(f"{path}: does not match pattern {schema['pattern']}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]: errs.append(f"{path}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]: errs.append(f"{path}: above maximum")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]: errs.append(f"{path}: too few items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]: errs.append(f"{path}: too many items")
        if schema.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in instance}) != len(instance):
            errs.append(f"{path}: items not unique")
        if "items" in schema:
            for i, x in enumerate(instance): errs += validate(x, schema["items"], root, f"{path}[{i}]")
    if isinstance(instance, dict):
        for r in schema.get("required", []):
            if r not in instance: errs.append(f"{path}: missing required field '{r}'")
        props = schema.get("properties", {})
        for k, x in instance.items():
            if k in props: errs += validate(x, props[k], root, f"{path}.{k}")
            elif schema.get("additionalProperties", True) is False: errs.append(f"{path}: unexpected field '{k}'")
    if "oneOf" in schema:
        ok = [i for i, s in enumerate(schema["oneOf"]) if not validate(instance, s, root, path)]
        if len(ok) != 1: errs.append(f"{path}: must match exactly one alternative (matched {len(ok)})")
    return errs
