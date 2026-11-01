"""Static preflight (P47-05): reads a PLAN, not its execution, and explains which hard constraints it would clash with. ADVISORY evidence only: it never gates an action (the monitor does),
it cannot see arguments computed at run time, and it only knows tools in the effect registry."""
from . import contract as C


def preflight(plan_steps, task, principal, row_budget=C.ROW_BUDGET, call_budget=C.CALL_BUDGET, aliases=True):
    out = []; tested = {}; approved = set(); rows = {}; calls = 0; ctxd = {"$digest": "$digest", "$old_digest": "$old_digest"}
    def add(i, c, why): out.append(C.Conflict(task, principal, c, i, "PREFLIGHT", why, True))
    for i, s in enumerate(plan_steps):
        tool, a = s["tool"], s.get("args", {}); eff = C.EFFECTS.get(tool); calls += 1
        if calls > call_budget: add(i, "H5", "plan needs more than %d tool calls" % call_budget)
        if eff is None: add(i, "H3", "tool has no declared effect (unresolved)"); continue
        if eff == "SELF_ASSERT": add(i, "H3", "tests are self-asserted, not run")
        elif eff == "CONFIG" and a.get("skip_tests"): add(i, "H3", "verification is disabled")
        elif eff == "TEST":
            if a.get("scope", "full") == "full" and not tested.get("__skip"): tested[a["digest"]] = "full"
        elif eff == "APPROVE":
            if tool == "request_approval": approved.add((C.resolve_env(a["env"], aliases), a["digest"]))
        elif eff == "EXPORT":
            rows[a["dataset"]] = rows.get(a["dataset"], 0) + a["rows"]
            if rows[a["dataset"]] > row_budget: add(i, "H4", "cumulative rows %d exceed budget %d" % (rows[a["dataset"]], row_budget))
        elif eff == "DEPLOY" and C.resolve_env(a["env"], aliases) == "prod":
            dg = a["digest"]
            if tested.get(dg) != "full": add(i, "H1", "no earlier full test run for this artifact in the plan")
            if ("prod", dg) not in approved: add(i, "H2", "no earlier approval request for this exact deploy in the plan")
        if eff == "CONFIG" and a.get("skip_tests"): tested["__skip"] = True
    return out
