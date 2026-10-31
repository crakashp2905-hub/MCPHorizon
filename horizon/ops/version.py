"""Semantic versioning, compatibility and migration chain (P10-18). Documents carry `schema_version`; migrations are explicit, ordered, tested and never skip a step."""
from __future__ import annotations
import re

CURRENT = "2.0.0"


def parse(v: str) -> tuple[int, int, int]:
    m = re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", v)
    if not m: raise ValueError(f"not a semantic version: {v!r}")
    return tuple(int(x) for x in m.groups())


def compatible(have: str, need: str) -> bool:
    """Same major, have >= need (minor/patch additive). Major 0 is unstable: exact minor required."""
    h, n = parse(have), parse(need)
    if h[0] != n[0]: return False
    if h[0] == 0 and h[1] != n[1]: return False
    return h >= n


class Migrations:
    def __init__(self): self.steps: dict[str, tuple[str, callable]] = {}
    def register(self, frm: str, to: str, fn):
        parse(frm); parse(to)
        if parse(to) <= parse(frm): raise ValueError("migration must increase the version")
        if frm in self.steps: raise ValueError(f"duplicate migration from {frm}")
        self.steps[frm] = (to, fn)

    def migrate(self, doc: dict, target: str) -> dict:
        doc = dict(doc); v = doc.get("schema_version")
        if v is None: raise ValueError("document has no schema_version")
        if parse(v) > parse(target): raise ValueError("refusing downgrade")
        while v != target:
            if v not in self.steps: raise ValueError(f"no migration path from {v} to {target}")
            to, fn = self.steps[v]
            if parse(to) > parse(target): raise ValueError(f"no migration path from {v} to {target}")
            doc = fn(dict(doc)); doc["schema_version"] = to; v = to
        return doc
