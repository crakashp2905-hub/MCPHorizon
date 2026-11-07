"""Utility floor + Pareto frontier over the finite Forge portfolio (blueprint S3-03/S3-06). CANDIDATE, UNTRUSTED proposer; admissibility is still decided by checker.check.
A blanket denial is NOT a solution: it is reported as DENY_ALL with utility_loss=FULL and is never returned as a certified plan. Optimality claims are relative to the enumerated portfolio only."""
from __future__ import annotations
from .ir import Task, Plan
from . import checker
from .synth import enumerate_plans, utility_loss

FULL_LOSS = 2     # strictly worse than any real plan (max real loss is 1): denial delivers none of the task


def feasible(task: Task) -> list:
    task.validate(); return [p for p in enumerate_plans(task) if checker.check(task, p)]


def frontier(task: Task) -> list:
    """Non-dominated (cost, utility_loss) feasible plans; one representative per point (deterministic tie-break by repr)."""
    best = {}
    for p in feasible(task):
        k = (p.cost(), utility_loss(task, p))
        if k not in best or repr(p) < repr(best[k]): best[k] = p
    pts = sorted(best)
    out = []
    for k in pts:
        if not any(o != k and o[0] <= k[0] and o[1] <= k[1] for o in pts): out.append((k, best[k]))
    return out


def solve_with_floor(task: Task, max_utility_loss: int) -> dict:
    if not (isinstance(max_utility_loss, int) and not isinstance(max_utility_loss, bool) and 0 <= max_utility_loss < FULL_LOSS): raise ValueError("floor must be 0 or 1")
    ok = [p for p in feasible(task) if utility_loss(task, p) <= max_utility_loss]
    if not ok:
        return {"result": "NOT_CERTIFIABLE_UNDER_FLOOR", "floor": max_utility_loss, "deny_all": {"is_solution": False, "utility_loss": FULL_LOSS},
                "feasible_without_floor": len(feasible(task)), "scope": "finite portfolio only"}
    best = min(ok, key=lambda p: (p.cost(), utility_loss(task, p), repr(p)))
    return {"result": "FEASIBLE_AT_FLOOR", "plan": best, "cost": best.cost(), "utility_loss": utility_loss(task, best), "floor": max_utility_loss}


def verify_frontier(task: Task, front: list) -> bool:
    """Independent re-check by exhaustive pairwise comparison (different algorithm from frontier()): every listed plan is checker-admissible,
    none is dominated by any admissible plan, and every admissible plan is weakly dominated by some listed point."""
    adm = [(p.cost(), utility_loss(task, p)) for p in enumerate_plans(task) if checker.check(task, p)]
    pts = [k for k, _ in front]
    if len(set(pts)) != len(pts): return False
    for k, p in front:
        if not checker.check(task, p) or (p.cost(), utility_loss(task, p)) != k: return False
        if any(a[0] <= k[0] and a[1] <= k[1] and a != k for a in adm): return False
    return all(any(k[0] <= a[0] and k[1] <= a[1] for k in pts) for a in adm)
