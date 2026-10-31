"""Monotone ground-rule closure with budgets, deterministic order and witnesses (P2-05, P2-06, P2-07).

Fragment: positive ground rules `premises ⊆ X ⇒ head` over opaque atom strings. No variables, negation, recursion
construct, or code execution. Fixed point is reached in at most |atoms-derivable| passes (each pass adds >=1 atom).
Complexity is O(R * (R + A)) set operations with R = rules, A = atoms; budgets keep both small.
"""
from __future__ import annotations
import re

MAX_RULES, MAX_PREMISES, MAX_ATOMS = 1000, 4, 10000
ATOM = re.compile(r"[a-z][a-z0-9_]*\([A-Za-z0-9_.:/*?@-]{0,128}\)")


class BudgetError(ValueError):
    pass


def parse_rules(rules: list[dict]) -> list[dict]:
    if len(rules) > MAX_RULES: raise BudgetError("too many rules")
    seen, out = set(), []
    for r in rules:
        if set(r) != {"id", "premises", "head", "code"}: raise BudgetError(f"rule has unexpected shape: {sorted(r)}")
        if r["id"] in seen: raise BudgetError(f"duplicate rule id {r['id']}")
        seen.add(r["id"])
        if not (1 <= len(r["premises"]) <= MAX_PREMISES): raise BudgetError(f"{r['id']}: premise arity outside 1..{MAX_PREMISES}")
        for a in [*r["premises"], r["head"]]:
            if not ATOM.fullmatch(a): raise BudgetError(f"{r['id']}: malformed atom {a!r}")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", r["code"]): raise BudgetError(f"{r['id']}: bad reason code")
        out.append({"id": r["id"], "premises": tuple(sorted(set(r["premises"]))), "head": r["head"], "code": r["code"]})
    return sorted(out, key=lambda r: r["id"])


def closure(atoms: list[str], rules: list[dict]) -> dict:
    """Returns {atoms: sorted list, witnesses: {derived_atom: {rule, premises, code}}}. Deterministic; input order irrelevant."""
    rs = parse_rules(rules)
    base = set(atoms)
    for a in base:
        if not ATOM.fullmatch(a): raise BudgetError(f"malformed atom {a!r}")
    if len(base) > MAX_ATOMS: raise BudgetError("too many atoms")
    x, wit, changed = set(base), {}, True
    while changed:
        changed = False
        for r in rs:                                    # fixed (sorted) order => deterministic first-derivation witness
            if r["head"] not in x and all(p in x for p in r["premises"]):
                x.add(r["head"]); wit[r["head"]] = {"rule": r["id"], "premises": list(r["premises"]), "code": r["code"]}
                changed = True
                if len(x) > MAX_ATOMS: raise BudgetError("closure exceeded atom budget")
    return {"atoms": sorted(x), "witnesses": dict(sorted(wit.items()))}
