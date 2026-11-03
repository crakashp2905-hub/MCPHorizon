"""Idea 5: witness diversity. Witnesses are described by the attributes that make failures correlate. Two witnesses are DEPENDENT if they share a trust root / signing key / operator, or share enough
incidental attributes (host, os_user, library stack, network path) to exceed a similarity threshold. Independent witnessing is only claimed for >=2 INDEPENDENT clusters."""
from __future__ import annotations

HARD = ("trust_root", "signing_key", "operator")          # any shared hard attribute => dependent
SOFT = ("host", "os_user", "library", "network_path")


def similarity(a: dict, b: dict) -> float: return sum(1 for k in SOFT if a.get(k) is not None and a.get(k) == b.get(k)) / len(SOFT)


def dependent(a: dict, b: dict, threshold: float = 0.5) -> bool:
    if any(a.get(k) is not None and a.get(k) == b.get(k) for k in HARD): return True
    return similarity(a, b) >= threshold


def clusters(ws: dict, threshold: float = 0.5) -> list:
    names = sorted(ws); parent = {n: n for n in names}
    def find(x):
        while parent[x] != x: parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if dependent(ws[a], ws[b], threshold): parent[find(a)] = find(b)
    groups = {}
    for n in names: groups.setdefault(find(n), []).append(n)
    return sorted(sorted(g) for g in groups.values())


def effective_independent(ws: dict, threshold: float = 0.5) -> int: return len(clusters(ws, threshold))
def may_claim_independent(ws: dict, threshold: float = 0.5) -> bool: return effective_independent(ws, threshold) >= 2
