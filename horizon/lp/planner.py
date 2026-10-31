"""Adaptive least privilege (P20). A typed Plan is NON-authoritative: it is a request. Authority comes only from root grants via the P15 delegator, after the solver
shows requested ⊆ root ∩ contract limits. Free-text task descriptions are never parsed. Missing capability => human review ticket, never autonomous expansion."""
from __future__ import annotations
import itertools
from dataclasses import dataclass, field
from horizon.deleg import authority as A, grants as G


@dataclass(frozen=True)
class Step:
    action: str; tool: str; resource: str; dest: str | None = None; arg_max: tuple = ()      # ((name, int), ...)


@dataclass(frozen=True)
class Plan:
    task_id: str; subagent: str; steps: tuple; description: str = ""          # description is carried for humans/audit only


def requested_authority(plan: Plan, now: int, ttl: int, arg_names=()) -> A.Authority:
    am = {n: 0 for n in arg_names}      # constrained args the plan does not use are bound to 0: omitting a bound would read as 'unbounded' and fail subset()
    for s in plan.steps:
        for k, v in s.arg_max: am[k] = max(am.get(k, 0), v)
    dests = {s.dest for s in plan.steps if s.dest}
    return A.Authority.make({s.action for s in plan.steps}, {s.tool for s in plan.steps}, sorted({s.resource for s in plan.steps}), dests or None, am, now, now + ttl)


def solve(plan: Plan, root: A.Authority, contract_limits: dict, now: int, ttl: int) -> dict:
    """Constraint check: requested ⊆ root, and each argument limit within the tool contract's limit. Returns feasible or the exact missing capability."""
    names = {k for (_, k) in contract_limits}
    try: req = requested_authority(plan, now, ttl, names)
    except A.AuthorityError as e: return {"feasible": False, "code": e.code, "missing": None}
    for s in plan.steps:
        for k, v in s.arg_max:
            lim = contract_limits.get((s.tool, k))
            if lim is None or v > lim: return {"feasible": False, "code": "EXCEEDS_CONTRACT_LIMIT", "missing": {"tool": s.tool, "arg": k}}
    if not A.subset(req, root): 
        miss = [s for s in plan.steps if not A.subset(requested_authority(Plan("x", "x", (s,)), now, ttl, names), root)]
        return {"feasible": False, "code": "EXCEEDS_ROOT_GRANT", "missing": [(s.action, s.tool, s.resource) for s in miss]}
    return {"feasible": True, "auth": req}


class Broker:
    """Issues short-lived per-subtask grants via the delegation service, only with issuer approval; revokes on VERIFIED completion."""
    def __init__(self, delegator: G.Delegator, verifier: G.Verifier, root_env, root_auth, contract_limits, approver, ttl=300):
        self.d, self.v, self.root, self.ra, self.lim, self.approve, self.ttl, self.tickets, self.audit, self.live = delegator, verifier, root_env, root_auth, contract_limits, approver, ttl, [], [], {}
    def request(self, plan: Plan, *, origin="agent-runtime") -> dict:
        now = int(self.v.clock()); r = solve(plan, self.ra, self.lim, now, self.ttl)
        if not r["feasible"]:
            t = {"ticket": len(self.tickets) + 1, "plan": plan.task_id, "reason": r["code"], "missing": r["missing"]}; self.tickets.append(t); self.audit.append({"ev": "human_review_required", **t}); return {"granted": False, "ticket": t}
        if not self.approve(plan, r["auth"]): self.audit.append({"ev": "issuer_declined", "plan": plan.task_id}); return {"granted": False, "ticket": None, "why": "ISSUER_DECLINED"}
        env = self.d.delegate([self.root], [self.root["grant"]["id"]], requester=self.root["grant"]["sub"], child_sub=plan.subagent, auth=r["auth"], origin=origin, reason=f"task {plan.task_id}")
        self.live[plan.task_id] = env; self.audit.append({"ev": "granted", "plan": plan.task_id, "grant": env["grant"]["id"]}); return {"granted": True, "grant": env}
    def complete(self, task_id, *, verified: bool) -> bool:
        """Revoke only on VERIFIED completion; unverified completion keeps the (short-lived) grant to expire naturally."""
        if not verified or task_id not in self.live: return False
        self.v.rev.revoke(self.live.pop(task_id)["grant"]["id"]); self.audit.append({"ev": "revoked", "plan": task_id}); return True


@dataclass
class Suggestion:
    """LLM/heuristic policy recommendation: ALWAYS advisory (P20-12). It cannot be applied without issuer approval and the solver."""
    plan: Plan; source: str; advisory: bool = True


class AdvisoryLog:
    def __init__(self): self.rows = []
    def record(self, s: Suggestion, outcome): self.rows.append({"task": s.plan.task_id, "source": s.source, "advisory": s.advisory, "outcome": outcome})
    def apply(self, broker: Broker, s: Suggestion) -> dict:
        r = broker.request(s.plan, origin="agent-runtime"); self.record(s, "granted" if r["granted"] else "refused"); return r
