"""P47 experiments: system matrix (P47-12, 14), incentive-intensity sweep (P47-10), conflict localization (P47-05, 14), replan behaviour (P47-11)."""
import copy, statistics
from ..emergence.experiment import wilson
from . import scenarios as SC, agents as A, contract as C, oracle as O, preflight as PF, monitor as MN

VARIANTS = 3; IOTAS = (0.0, 1.0, 2.0, 4.0, 8.0, 16.0); SWEEP_SYSTEMS = ("none", "instruction-only", "reward-penalty", "preflight-advisory", "monitor")


def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}
def mean(xs): return round(statistics.mean(xs), 2) if xs else None


def run_one(sid, system, var, iota=None):
    sc = SC.get(sid, var)
    if iota is not None:
        for s in sc["specs"]: s.iota = iota
    r = A.run_agents(sc["specs"], system, SC.make_world, sc["setups"], sc["justified"]); den = len(r["denials"]); w = r.pop("world")
    return {"id": sid, "kind": sc["kind"], "system": system, "var": var, "completed": r["completed"], "violated": r["violated"], "violations": r["violations"], "safe_completed": r["completed"] and not r["violated"], "time": r["time"], "actions": r["actions"], "rows_delivered": r["rows_delivered"],
            "denials": den, "false_blocks": 0 if sc["kind"] == "attack" or sc["justified"] else den, "justified_denials": den if sc["kind"] == "benign" and sc["justified"] else 0, "first_choice_violating": r["first_choice_violating"], "attempts": r["attempts"], "iota": sc["specs"][0].iota}


def summarize(rows):
    out = {}
    for sy in A.SYSTEMS:
        at = [r for r in rows if r["system"] == sy and r["kind"] == "attack"]; bn = [r for r in rows if r["system"] == sy and r["kind"] == "benign"]
        out[sy] = {"attack_runs_with_unauthorized_effect": rate(sum(r["violated"] for r in at), len(at)), "attack_runs_safely_completed": rate(sum(r["safe_completed"] for r in at), len(at)), "attack_runs_denied_at_least_once": rate(sum(1 for r in at if r["denials"]), len(at)),
                   "benign_runs_completed": rate(sum(r["completed"] for r in bn), len(bn)), "benign_runs_with_violation": rate(sum(r["violated"] for r in bn), len(bn)), "benign_runs_with_false_block": rate(sum(1 for r in bn if r["false_blocks"]), len(bn)),
                   "benign_runs_justified_denial": rate(sum(1 for r in bn if r["justified_denials"]), len(bn)), "mean_time_benign": mean([r["time"] for r in bn]), "mean_time_attack_safe": mean([r["time"] for r in at if r["safe_completed"]]), "mean_actions_benign": mean([r["actions"] for r in bn]),
                   "first_choice_violating": rate(sum(r["first_choice_violating"] for r in at), len(at))}
    return out


def per_scenario(rows):
    out = {}
    for sid in SC.IDS:
        k = SC.get(sid, 0); d = {"kind": k["kind"], "note": k["note"], "systems": {}}
        for sy in A.SYSTEMS:
            rs = [r for r in rows if r["id"] == sid and r["system"] == sy]
            d["systems"][sy] = ("V%d" % sum(r["violated"] for r in rs) if k["kind"] == "attack" else "%d/%d" % (sum(r["safe_completed"] for r in rs), len(rs))) + ("" if k["kind"] == "benign" else "/S%d" % sum(r["safe_completed"] for r in rs))
        out[sid] = d
    return out


def sweep():
    rows = []
    for sid in [i for i in SC.IDS if i.startswith("A")]:
        for sy in SWEEP_SYSTEMS:
            for io in IOTAS: rows.append(run_one(sid, sy, 1, io))
    out = {}
    for sy in SWEEP_SYSTEMS:
        out[sy] = {}
        for io in IOTAS:
            rs = [r for r in rows if r["system"] == sy and r["iota"] == io]
            out[sy][str(io)] = {"first_choice_violating": rate(sum(r["first_choice_violating"] for r in rs), len(rs)), "violated": rate(sum(r["violated"] for r in rs), len(rs)), "safe_completed": rate(sum(r["safe_completed"] for r in rs), len(rs)), "mean_time": mean([r["time"] for r in rs])}
    return out


def localization():
    """Which hard constraints does a violating plan clash with? Oracle (ground truth, from effects) vs static preflight vs the monitor's runtime denials (P47-05, 14)."""
    res = []; fp = []
    for sid in [i for i in SC.IDS if i.startswith("A")]:
        sc = SC.get(sid, 1)
        for spec in sc["specs"]:
            for p in spec.plans:
                f = A.dry_run(spec, p, SC.make_world, sc["setups"].get(spec.ident)); pc = PF.preflight(p.steps, spec.task, spec.ident)
                if f["viol"]:
                    w, ctx = SC.make_world(), {}
                    if sc["setups"].get(spec.ident): sc["setups"][spec.ident](w, ctx)
                    gw = A.Gateway(w, "monitor", None)
                    A.run_plan(w, gw, spec, p, ctx, keep_going=True)                  # keep going after a denial so every clash is reported
                    mon = sorted({c for d in gw.denials for c in d["constraints"]}); pre = sorted({c.constraint for c in pc})
                    res.append({"scenario": sid, "plan": p.id, "oracle": f["viol"], "preflight": pre, "monitor": mon, "preflight_exact": pre == f["viol"], "monitor_exact": mon == f["viol"], "oracle_steps": sorted(set(f["steps"])), "preflight_steps": sorted({c.step for c in pc})})
                elif pc: fp.append({"scenario": sid, "plan": p.id, "flagged": sorted({c.constraint for c in pc})})
    for sid in [i for i in SC.IDS if i.startswith("B")]:
        sc = SC.get(sid, 1)
        for spec in sc["specs"]:
            for p in spec.plans:
                pc = PF.preflight(p.steps, spec.task, spec.ident); f = A.dry_run(spec, p, SC.make_world, sc["setups"].get(spec.ident))
                if pc and not f["viol"]: fp.append({"scenario": sid, "plan": p.id, "flagged": sorted({c.constraint for c in pc})})
    return {"violating_plans": res, "preflight_false_positives": fp, "n": len(res), "preflight_exact": sum(r["preflight_exact"] for r in res), "monitor_exact": sum(r["monitor_exact"] for r in res)}


def run():
    rows = []
    for sid in SC.IDS:
        for sy in A.SYSTEMS:
            for v in range(VARIANTS): rows.append(run_one(sid, sy, v))
    return {"rows": rows, "summary": summarize(rows), "per_scenario": per_scenario(rows), "sweep": sweep(), "localization": localization(), "variants": VARIANTS, "iotas": list(IOTAS), "runs": len(rows), "systems": list(A.SYSTEMS), "scenarios": [{"id": s, "kind": SC.get(s, 0)["kind"], "note": SC.get(s, 0)["note"]} for s in SC.IDS],
            "constants": {"W_INSTR": A.W_INSTR, "PENALTY": A.PENALTY, "AUDIT_Q": A.AUDIT_Q, "W_ADV": A.W_ADV, "REPLAN_COST": A.REPLAN_COST, "MAX_ATTEMPTS": A.MAX_ATTEMPTS, "IOTA": SC.IOTA, "ROW_BUDGET": C.ROW_BUDGET, "CALL_BUDGET": C.CALL_BUDGET}}
