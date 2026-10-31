"""Incremental per-run state with deterministic replay and evidence-gap eviction (P2-14, P2-15), plus authorization (P2-10/11), epistemic predicate (P2-19) and remediation (P2-21)."""
from __future__ import annotations
import itertools
from .closure import closure
from . import scope as sc


class RunState:
    def __init__(self, rules: list[dict], max_atoms: int = 1000):
        self.rules, self.max_atoms = rules, max_atoms
        self.atoms: list[str] = []          # insertion-ordered observation log
        self.evicted: list[str] = []        # explicit evidence gaps — never silent
        self.last_seq = -1

    def apply(self, event: dict) -> None:
        if event["monotonic_seq"] <= self.last_seq: raise ValueError("non-monotonic event")
        self.last_seq = event["monotonic_seq"]
        for a in event.get("atoms", []):
            if a not in self.atoms: self.atoms.append(a)
        while len(self.atoms) > self.max_atoms:
            self.evicted.append(self.atoms.pop(0))

    @property
    def evidence_complete(self) -> bool: return not self.evicted

    def snapshot(self) -> dict:
        c = closure(self.atoms, self.rules)
        return {**c, "evidence_complete": self.evidence_complete, "evicted_count": len(self.evicted)}


def replay(rules, events, max_atoms=1000) -> dict:
    s = RunState(rules, max_atoms)
    for e in events: s.apply(e)
    return s.snapshot()


def authorized(grants: list[dict], principal: str, tenant: str, action: str, resource_class: str, value: str,
               destination: str | None = None, purpose: str | None = None) -> bool:
    """Grants come from a TRUSTED store keyed by principal; caller-supplied claims are never consulted."""
    for g in grants:
        if g["principal_id"] != principal or g["action"] != action or g["resource_class"] != resource_class: continue
        if g.get("tenant") not in (None, tenant): continue
        cons = g.get("constraints", {})
        if "allowed_destinations" in cons and destination not in cons["allowed_destinations"]: continue
        if "purpose" in cons and cons["purpose"] != purpose: continue
        if sc.matches(g["scope"], value): return True
    return False


def epistemic_risk(consequential: bool, inputs: list[dict], purpose: str) -> bool:
    """Risk_epi(e) <=> Consequential(e) ∧ ∃a: UntrustedAncestor(a) ∧ ¬AdequatelyVerified(a, purpose). A policy predicate, not proof of falsehood."""
    return consequential and any(a["untrusted_ancestor"] and purpose not in a.get("verified_for", []) for a in inputs)


def min_hitting_set(witnesses: list[set], budget: int = 20) -> tuple[set, bool]:
    """Exact for <=budget distinct elements (brute force by size); else greedy approximation. Returns (set, exact)."""
    elems = sorted(set().union(*witnesses)) if witnesses else []
    if len(elems) <= budget:
        for k in range(len(elems) + 1):
            for combo in itertools.combinations(elems, k):
                if all(set(combo) & w for w in witnesses): return set(combo), True
    chosen, left = set(), [set(w) for w in witnesses]
    while left:
        best = max(sorted({e for w in left for e in w}), key=lambda e: sum(e in w for w in left))
        chosen.add(best); left = [w for w in left if best not in w]
    return chosen, False
