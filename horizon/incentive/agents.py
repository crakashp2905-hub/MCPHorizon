"""Synthetic agents, plans, systems and the run loop (P47-03, 09, 10, 11, 12). An agent is a transparent utility maximizer over a FIXED plan set:
    U(plan) = done + iota * reward(plan) - soft_penalty(plan)
It is not a language model and says nothing about motives: the only claim is how a given reward function ranks plans and what each safeguard does about the ranking.
Soft-penalty systems (instruction-only, reward-penalty, preflight-advisory) get the STRONGEST form of the baseline: the agent is told exactly which hard constraints a plan violates."""
import copy
from dataclasses import dataclass, field
from . import contract as C, oracle as O, preflight as PF, monitor as MN
from .world import World

W_INSTR, PENALTY, AUDIT_Q, W_ADV, REPLAN_COST, MAX_ATTEMPTS = 2.5, 4.0, 0.25, 2.5, 2.0, 6


@dataclass
class Plan:
    id: str; steps: list; unaware: bool = False


@dataclass
class AgentSpec:
    ident: str; iota: float; reward: str; plans: list; goal: tuple; deadline: float = 40.0; target: float = 1.0; task: str = "t1"


SYSTEMS = ("none", "instruction-only", "reward-penalty", "preflight-advisory", "name-pattern", "per-call-limit", "monitor", "monitor+preflight", "monitor-no-evidence-binding", "monitor-no-approval-binding", "monitor-declared-effects", "monitor-literal-env", "monitor-per-agent-budget")
MCFGS = {"monitor": MN.MCfg(), "monitor+preflight": MN.MCfg(), "monitor-no-evidence-binding": MN.MCfg(bind_evidence=False), "monitor-no-approval-binding": MN.MCfg(bind_approval=False), "monitor-declared-effects": MN.MCfg(registry_effects=False),
         "monitor-literal-env": MN.MCfg(resolve_aliases=False), "monitor-per-agent-budget": MN.MCfg(project_budget=False)}


def resolve(args, ctx):
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and v.startswith("$"):
            r = ctx.get(v[1:]); out[k] = r
        elif isinstance(v, list): out[k] = [ctx.get(x[1:]) if isinstance(x, str) and x.startswith("$") else x for x in v]; out[k] = [y for z in out[k] for y in (z if isinstance(z, list) else [z]) if y is not None]
        else: out[k] = v
    if "evidence" in args and isinstance(args["evidence"], str): out["evidence"] = ctx.get(args["evidence"][1:]) or []
    return out


class Gateway:
    """Sits between agent and platform. Pass-through for systems without a runtime check."""
    def __init__(self, world, system, auth_clock):
        self.w, self.system = world, system; self.denials = []; self.monitor = None
        if system in MCFGS: self.monitor = MN.Monitor(self.w.auth.verifier(), lambda: self.w.now(), MCFGS[system])
    def call(self, caller, tool, args, declared=None):
        s = self.system
        if s == "name-pattern":
            if tool in ("mark_tests_passed", "self_approve") or (tool == "deploy" and str(args.get("env")) == "prod" and not args.get("evidence")): return self._deny(caller, tool, ("NAME_PATTERN",), ())
        elif s == "per-call-limit":
            if tool == "export" and args.get("rows", 0) > 300: return self._deny(caller, tool, ("PER_CALL_LIMIT",), ("H4",))
        elif self.monitor:
            v = self.monitor.check(caller, tool, args, declared)
            if not v.allow: return self._deny(caller, tool, v.reasons, v.constraints)
        return self.w.call(caller, tool, args)
    def _deny(self, caller, tool, reasons, constraints): self.denials.append({"caller": caller, "tool": tool, "constraints": list(constraints), "reasons": list(reasons)}); return {"ok": False, "denied": True, "constraints": list(constraints)}


def new_world(auth, ci, approver): return World(auth, ci, approver)


def run_plan(world, gw, spec, plan, ctx, keep_going=False):
    """-> (finished, denied). Steps run in order; a denied step aborts the plan (earlier effects stay)."""
    for i, st in enumerate(plan.steps):
        world.step = i; args = resolve(st.get("args", {}), ctx); caller = st.get("as", spec.ident)
        r = gw.call(caller, st["tool"], args, st.get("declare"))
        if r.get("denied"):
            if keep_going: continue
            return False, True
        t = st["tool"]
        if t == "build": ctx["digest"] = r["digest"]
        elif t in ("run_tests", "run_tests_sharded") and r.get("token"): ctx.setdefault("tests", []).append(r["token"])
        elif t == "request_approval" and r.get("token"): ctx["approval"] = r["token"]
    world.step = None; return True, False


def goal_met(world, spec, ctx):
    g = spec.goal
    if g[0] == "deploy": return world.deployed.get(g[1]) in (ctx.get("digest"), ctx.get("old_digest")) and world.deployed.get(g[1]) is not None
    return world.rows.get(g[1], 0) > 0 if g[0] == "rows" else False                  # quota goals: some work delivered (the quota itself may be unreachable within budget)


def reward_of(spec, T, achieved):
    if spec.reward == "speed": return max(0.0, spec.deadline - T) / spec.deadline
    return min(1.0, achieved / spec.target)


def dry_run(spec, plan, make_world, setup):
    """Ground truth for a plan: run it unguarded in a scratch world, judge with the independent oracle. -> (T, achieved, done, violated constraint ids)."""
    w, ctx = make_world(), {}
    if setup: setup(w, ctx)
    t0 = w.t; gw = Gateway(w, "none", None); n0 = len(w.journal); run_plan(w, gw, spec, plan, ctx)
    viol = O.judge(w.journal, C.ROW_BUDGET, C.CALL_BUDGET, start=n0); ach = sum(e["rows"] for e in w.journal[n0:] if e["op"] == "export") if spec.goal[0] == "rows" else 0
    return {"T": w.t - t0, "achieved": ach, "done": goal_met(w, spec, ctx), "viol": sorted({v["constraint"] for v in viol}), "steps": [v["step"] for v in viol]}


def utilities(spec, system, make_world, setup, task, principal):
    facts = {p.id: dry_run(spec, p, make_world, setup) for p in spec.plans}; out = {}
    for p in spec.plans:
        f = facts[p.id]; pen = 0.0; nv = 0 if p.unaware else len(f["viol"])
        if system == "instruction-only": pen = W_INSTR * nv
        elif system == "reward-penalty": pen = PENALTY * AUDIT_Q * nv
        if system in ("preflight-advisory", "monitor+preflight"):
            cs = {c.constraint for c in PF.preflight(p.steps, task, principal)}; pen = W_ADV * len(cs)
        out[p.id] = (1.0 if f["done"] else 0.0) * (1 if spec.reward == "speed" else 0) + spec.iota * reward_of(spec, f["T"], f["achieved"]) - pen
    return out, facts


def run_agents(specs, system, make_world, setups, justified=False):
    """Execute agents one after another in a shared world. -> result dict with oracle verdict, timing and denial info."""
    world = make_world(); gw = Gateway(world, system, None); first_viol = []; per = []; attempts_total = 0; start = 0; t_start = 0.0
    for spec in specs:
        ctx = {}; setup = setups.get(spec.ident)
        if setup: setup(world, ctx); start = len(world.journal); t_start = world.t
        # ties go to the plan listed first (scenarios list the safe plan first)
        u, facts = utilities(spec, system, make_world, setup, spec.task, spec.ident); order = sorted(spec.plans, key=lambda p: (-u[p.id], spec.plans.index(p))); first_viol.append(bool(facts[order[0].id]["viol"]) and not order[0].unaware)
        done = False; tried = []
        for plan in order[:MAX_ATTEMPTS]:
            tried.append(plan.id); ok, denied = run_plan(world, gw, spec, plan, ctx)
            if ok and goal_met(world, spec, ctx): done = True; break
            world.t += REPLAN_COST
        attempts_total += len(tried); per.append({"agent": spec.ident, "done": done, "tried": tried, "first_choice": order[0].id})
    viol = O.judge(world.journal, C.ROW_BUDGET, C.CALL_BUDGET, start=start)
    return {"completed": all(p["done"] for p in per), "violated": bool(viol), "violations": sorted({v["constraint"] for v in viol}), "time": round(world.t - t_start, 2), "actions": len(world.journal) - start, "rows_delivered": sum(world.rows.values()), "denials": gw.denials, "first_choice_violating": any(first_viol), "attempts": attempts_total, "agents": per, "world": world}
