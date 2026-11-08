"""Exhaustive evaluation of the WHOLE finite Forge task space plus baseline planners (blueprint S3 follow-up). CANDIDATE, research prototype, outside the trusted kernel.
The task space is every combination the IR can express (3 labels x aggregate_ok x remote_trust x control subsets x witness subsets x need_effect_witness = 768 tasks), so every statement below is about ALL of it, not a sample.
It is still a model: the checker's rules were written by the same author as the planners, there is no independent world, and 'unsafe' means 'rejected by that checker'."""
from __future__ import annotations
import itertools
from .ir import Task, Plan, LABELS, REMOTE_TRUST, CONTROLS, WITNESSES
from . import checker
from .synth import synthesize, enumerate_plans, utility_loss, verify_negative_certificate, _subsets
from .pareto import FULL_LOSS, frontier, solve_with_floor, verify_frontier


def all_tasks():
    for lab, agg, trust, ctl, wit, need in itertools.product(LABELS, (False, True), REMOTE_TRUST, list(_subsets(CONTROLS)), list(_subsets(WITNESSES)), (False, True)):
        yield Task(lab, agg, trust, ctl, wit, need)


# ---- baseline planners: each returns a Plan or None (= denies). They are judged by the SAME checker as the synthesizer.
def deny_all(t): return None
def cheapest_unchecked(t): return Plan("remote", "raw", (), ())                       # cost 0, ignores every constraint
def always_local(t): return Plan("local_sandbox", "raw", ("local_sandbox",) if "local_sandbox" in t.available_controls else (), ())
def synthesized(t):
    r = synthesize(t); return r.get("plan")
def synthesized_with_floor0(t):
    r = solve_with_floor(t, 0); return r.get("plan")
BASELINES = {"deny_all": deny_all, "cheapest_unchecked": cheapest_unchecked, "always_local": always_local, "synthesized": synthesized, "synthesized_no_utility_loss": synthesized_with_floor0}


def score(planner, tasks):
    n = ok = unsafe = denied = 0; cost = loss = 0
    for t in tasks:
        n += 1; p = planner(t)
        if p is None: denied += 1; loss += FULL_LOSS; continue
        if checker.check(t, p): ok += 1; cost += p.cost(); loss += utility_loss(t, p)
        else: unsafe += 1; loss += FULL_LOSS              # a rejected plan delivers nothing safe
    return {"tasks": n, "admissible": ok, "unsafe": unsafe, "denied": denied, "mean_cost_of_admissible": round(cost / ok, 3) if ok else None, "mean_utility_loss_all_tasks": round(loss / n, 3)}


def exhaustive() -> dict:
    tasks = list(all_tasks()); res = {"tasks": len(tasks), "frontier_verified": 0, "frontier_sizes": {}, "not_certifiable": 0, "negative_certs_verified": 0, "floor_consistent": 0, "floor0_not_certifiable": 0, "failures": []}
    for i, t in enumerate(tasks):
        fr = frontier(t); res["frontier_sizes"][str(len(fr))] = res["frontier_sizes"].get(str(len(fr)), 0) + 1
        if verify_frontier(t, fr): res["frontier_verified"] += 1
        else: res["failures"].append(["FRONTIER", i])
        s = synthesize(t)
        if s["result"] == "NOT_CERTIFIABLE_WITHIN_MODEL":
            res["not_certifiable"] += 1
            if verify_negative_certificate(t, s) and not fr: res["negative_certs_verified"] += 1
            else: res["failures"].append(["NEG_CERT", i])
        f1, f0 = solve_with_floor(t, 1), solve_with_floor(t, 0)
        best1 = min((k[0] for k, _ in fr), default=None); best0 = min((k[0] for k, _ in fr if k[1] == 0), default=None)
        ok1 = (f1["result"] == "NOT_CERTIFIABLE_UNDER_FLOOR") if best1 is None else (f1.get("cost") == best1)
        ok0 = (f0["result"] == "NOT_CERTIFIABLE_UNDER_FLOOR") if best0 is None else (f0.get("cost") == best0)
        if ok1 and ok0 and (f0.get("result") != "FEASIBLE_AT_FLOOR" or f0["utility_loss"] == 0): res["floor_consistent"] += 1
        else: res["failures"].append(["FLOOR", i])
        if f0["result"] == "NOT_CERTIFIABLE_UNDER_FLOOR": res["floor0_not_certifiable"] += 1
    res["baselines"] = {k: score(f, tasks) for k, f in BASELINES.items()}
    res["frontier_sizes"] = dict(sorted(res["frontier_sizes"].items())); return res
