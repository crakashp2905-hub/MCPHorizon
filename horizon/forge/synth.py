"""Bounded enumerative synthesis + bounded non-certifiability certificate (HF-PR04/05 slice). UNTRUSTED relative to checker: it proposes, checker.check decides.
The certificate lists the finite portfolio size and the checker's violation for EVERY enumerated plan, so a reviewer can re-run it; it claims nothing outside the model."""
from __future__ import annotations
import itertools
from .ir import Task, Plan, PLACEMENTS, FORMS
from . import checker


def _subsets(items):
    items = tuple(sorted(items))
    for r in range(len(items) + 1):
        for c in itertools.combinations(items, r): yield c


def enumerate_plans(task: Task):
    for pl in PLACEMENTS:
        for f in FORMS:
            for c in _subsets(task.available_controls):
                for w in _subsets(task.available_witnesses): yield Plan(pl, f, c, w)


def utility_loss(task: Task, plan: Plan) -> int: return 1 if plan.form == "aggregate" else 0


def synthesize(task: Task) -> dict:
    """Result kinds: CERTIFIED_WITH_SCOPE | CERTIFIABLE_AFTER_RELOCATION | NOT_CERTIFIABLE_WITHIN_MODEL. Deterministic: ties broken by (cost, utility loss, repr)."""
    task.validate(); plans = list(enumerate_plans(task)); ok = [p for p in plans if checker.check(task, p)]
    if not ok:
        return {"result": "NOT_CERTIFIABLE_WITHIN_MODEL", "bounds": {"plans_enumerated": len(plans)}, "refutations": {repr(p): checker.violations(task, p) for p in plans},
                "scope": "finite portfolio only; NOT a proof that no safe real-world implementation exists"}
    best = min(ok, key=lambda p: (p.cost(), utility_loss(task, p), repr(p)))
    naive = Plan("remote", "raw", (), ())
    kind = "CERTIFIED_WITH_SCOPE" if checker.check(task, naive) else "CERTIFIABLE_AFTER_RELOCATION"
    return {"result": kind, "plan": best, "cost": best.cost(), "utility_loss": utility_loss(task, best), "bounds": {"plans_enumerated": len(plans), "feasible": len(ok)}}


def verify_negative_certificate(task: Task, cert: dict) -> bool:
    """Independent re-check: certificate must cover EXACTLY the enumerated portfolio and every listed violation must be reproduced by the checker."""
    if cert.get("result") != "NOT_CERTIFIABLE_WITHIN_MODEL": return False
    plans = list(enumerate_plans(task)); ref = cert.get("refutations", {})
    if cert["bounds"]["plans_enumerated"] != len(plans) or set(ref) != {repr(p) for p in plans}: return False
    return all(ref[repr(p)] and ref[repr(p)] == checker.violations(task, p) for p in plans)
