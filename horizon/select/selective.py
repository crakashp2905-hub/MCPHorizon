"""Selective verification (P22-01..03,05). The verifier is ADVISORY AND RESTRICTIVE ONLY: it can turn a REVIEW into a DENY, never anything into an ALLOW, and can never override a hard deny.
Authority to proceed comes only from deterministic prefilters (no uncertainty) or a human reviewer."""
from __future__ import annotations
import heapq

TAXONOMY = ("unknown_target", "unknown_lineage", "stale_policy", "ambiguous_evidence", "unsupported_tool")
HARD_DENY = ("policy_denied",)
PRIOR = {"unknown_target": .35, "unknown_lineage": .30, "stale_policy": .10, "ambiguous_evidence": .20, "unsupported_tool": .40}       # deterministic prefilter priors (design constants, calibrated separately)


def prefilter(tags: set) -> dict:
    """Cheap and deterministic. Returns ALLOW (clean), DENY (hard), or REVIEW with a risk prior."""
    if tags & set(HARD_DENY): return {"decision": "DENY", "reason": "HARD_DENY", "prior": 1.0}
    unk = tags - set(HARD_DENY)
    if not unk: return {"decision": "ALLOW", "reason": "CLEAN", "prior": 0.0}
    bad = unk - set(TAXONOMY)
    if bad: return {"decision": "REVIEW", "reason": "UNKNOWN_UNCERTAINTY_TAG", "prior": 1.0}       # fail closed on tags we do not understand
    p = 1.0
    for t in unk: p *= 1 - PRIOR[t]
    return {"decision": "REVIEW", "reason": "UNCERTAIN", "prior": round(1 - p, 4)}


def combine(pre: dict, verifier_score: float | None, tau_deny: float) -> dict:
    """Hard-deny precedence; verifier may only restrict."""
    if pre["decision"] in ("DENY", "ALLOW"): return pre
    if verifier_score is not None and verifier_score >= tau_deny: return {"decision": "DENY", "reason": "VERIFIER_RESTRICT", "prior": pre["prior"]}
    return pre


def schedule(pending: list, budget: int) -> set:
    """Cost-aware: spend a limited number of verifier calls on the highest-prior uncertain items (all calls cost the same here). pending = [(id, prior)]."""
    return {i for i, _ in heapq.nlargest(budget, pending, key=lambda x: (x[1], str(x[0])))} if budget > 0 else set()


def calibration(scores: list, harms: list, bins=10) -> dict:
    """Reliability: expected calibration error of verifier scores against ACTUAL outcomes."""
    n = len(scores); ece = 0.0; rows = []
    for b in range(bins):
        idx = [i for i, s in enumerate(scores) if b / bins <= s < (b + 1) / bins or (b == bins - 1 and s == 1.0)]
        if not idx: continue
        conf = sum(scores[i] for i in idx) / len(idx); acc = sum(harms[i] for i in idx) / len(idx); ece += len(idx) / n * abs(conf - acc); rows.append({"bin": b, "n": len(idx), "mean_score": round(conf, 3), "harm_rate": round(acc, 3)})
    return {"ece": round(ece, 4), "bins": rows}
