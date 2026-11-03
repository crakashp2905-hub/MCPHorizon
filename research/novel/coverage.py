"""Idea 1: UNKNOWN as a measured quantity. Per-surface-item state; coverage reported as a Wilson LOWER bound over verification probes. Items with zero probes are UNKNOWN whatever their declared state (zero-denominator trap).
Declared COVERED never counts without evidence; UNSUPPORTED is reported separately, never in the numerator."""
from __future__ import annotations
import math


def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    if n == 0: return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def report(items: dict, probes: list) -> dict:
    """items: {id: 'COVERED'|'UNKNOWN'|'UNSUPPORTED'} declared; probes: [(id, passed_bool)] independent verification trials (e.g. attempted bypass that was blocked = passed)."""
    n, k = {}, {}
    for i, ok in probes:
        if i not in items: raise ValueError(f"probe for undeclared item {i}")
        n[i] = n.get(i, 0) + 1; k[i] = k.get(i, 0) + (1 if ok else 0)
    state = {}
    for i, d in items.items():
        if d == "UNSUPPORTED": state[i] = "UNSUPPORTED"
        elif d != "COVERED" or n.get(i, 0) == 0: state[i] = "UNKNOWN"
        elif k[i] < n[i]: state[i] = "FAILED"
        else: state[i] = "COVERED"
    sup = [i for i in items if state[i] != "UNSUPPORTED"]
    cov = [i for i in sup if state[i] == "COVERED"]
    # lower bound on the fraction of supported surface that is covered: items covered AND per-item pass rate lower bounds multiplied through the pooled probes of covered items
    pk = sum(k[i] for i in cov); pn = sum(n[i] for i in cov); lo_pass = wilson(pk, pn)[0] if pn else 0.0
    return {"counts": {s: sum(1 for v in state.values() if v == s) for s in ("COVERED", "UNKNOWN", "FAILED", "UNSUPPORTED")}, "states": state,
            "covered_fraction": (len(cov) / len(sup)) if sup else 0.0, "covered_fraction_lower": (len(cov) / len(sup)) * lo_pass if sup else 0.0, "unknown_fraction": (sum(1 for i in sup if state[i] == "UNKNOWN") / len(sup)) if sup else 1.0}
