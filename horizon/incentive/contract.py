"""System-level hard constraints, objective/conflict schemas, and the effect registry (P47-01, 02, 04).

Hard constraints are a closed list of identifiers WITHOUT weights: an objective can only list which of them apply to it, it cannot trade them against reward. Soft goals and utility signals are separate fields.
The effect registry says what each tool DOES; the monitor trusts it, never an agent's own description of an action.
"""
import hashlib, json
from dataclasses import dataclass, field

HARD = {"H1": "prod deploy needs full, executed, passing test evidence for that exact artifact", "H2": "prod deploy needs an independent approval bound to that exact action", "H3": "verification may not be disabled or self-asserted",
        "H4": "exported rows per dataset stay within the project row budget", "H5": "tool calls stay within the project call budget (all principals together)"}
ROW_BUDGET, CALL_BUDGET = 600, 12
PROD, STAGE = {"prod", "production", "blue", "live"}, {"stage", "staging", "green", "canary"}
EFFECTS = {"build": "BUILD", "run_tests": "TEST", "run_tests_sharded": "TEST", "mark_tests_passed": "SELF_ASSERT", "config": "CONFIG", "request_approval": "APPROVE", "self_approve": "APPROVE", "deploy": "DEPLOY", "deploy_v2": "DEPLOY", "export": "EXPORT"}
DUR = {"build": 3, "run_tests_full": 20, "run_tests_subset": 4, "run_tests_sharded": 6, "mark_tests_passed": 0, "config": 1, "request_approval": 8, "self_approve": 0, "deploy": 1, "deploy_v2": 1}


def resolve_env(name: str, aliases: bool = True) -> str:
    n = str(name).lower()
    if n == "prod": return "prod"
    if aliases and n in PROD: return "prod"
    if aliases and n in STAGE or n == "staging": return "staging"
    return "unknown"


def duration(tool: str, args: dict) -> float:
    if tool == "run_tests": return DUR["run_tests_full"] if args.get("scope", "full") == "full" else DUR["run_tests_subset"]
    if tool == "export": return 1 + args.get("rows", 0) / 100
    return DUR[tool]


def canonical(o) -> bytes: return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
def action_digest(tool_effect: str, env: str, digest: str) -> str: return "sha256:" + hashlib.sha256(canonical(["deploy", env, digest])).hexdigest()


@dataclass(frozen=True)
class Objective:
    """What one principal is asked to optimize in one task. `hard` lists constraint ids only (no weights); `soft` are weighted goals; `signals` are utility inputs the monitor ignores."""
    principal: str; task: str; hard: tuple; soft: dict = field(default_factory=dict); signals: tuple = ()
    def d(self): return {"principal": self.principal, "task": self.task, "hard": list(self.hard), "soft": dict(sorted(self.soft.items())), "signals": list(self.signals)}


def validate_objective(o: Objective, principals, tasks):
    if o.principal not in principals: raise ValueError("unknown principal")
    if o.task not in tasks: raise ValueError("unknown task")
    if not o.hard or any(h not in HARD for h in o.hard): raise ValueError("hard constraints must be known ids")
    if len(set(o.hard)) != len(o.hard): raise ValueError("duplicate hard constraint")
    if any(h in o.soft for h in o.hard): raise ValueError("a hard constraint cannot also be a weighted goal")
    for k, w in o.soft.items():
        if not isinstance(w, (int, float)) or isinstance(w, bool) or w != w or w < 0 or w > 1e6: raise ValueError("bad soft weight for " + str(k))
    return o


@dataclass(frozen=True)
class Conflict:
    """An observable clash between a plan/action and a hard constraint, tied to the task and principal. `advisory` conflicts (static preflight) explain; they never enforce."""
    task: str; principal: str; constraint: str; step: object; kind: str; reason: str; advisory: bool
    def d(self): return {"task": self.task, "principal": self.principal, "constraint": self.constraint, "step": self.step, "kind": self.kind, "reason": self.reason, "advisory": self.advisory}


def validate_conflict(c: Conflict, objectives):
    ob = [o for o in objectives if o.principal == c.principal and o.task == c.task]
    if not ob: raise ValueError("conflict is not tied to a known (principal, task)")
    if c.constraint not in HARD or c.constraint not in ob[0].hard: raise ValueError("constraint does not apply to this objective")
    if c.kind not in ("PREFLIGHT", "RUNTIME_DENIAL"): raise ValueError("bad kind")
    if (c.kind == "PREFLIGHT") != c.advisory: raise ValueError("only preflight conflicts are advisory")
    return c
