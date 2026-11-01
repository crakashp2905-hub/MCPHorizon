"""P53 experiments (P53-12..15): systems x scenarios, judged by the independent oracle. Deterministic."""
from ..emergence.experiment import wilson
from . import migrate as M, scenarios as SC, core as C
from .world import World
from .oracle import judge

def systems():
    S = [M.Baseline(n) for n in ("state-serialization", "token-copying", "container-snapshot", "config-sync", "tool-name-check", "restrictive-rule")] + [M.Continuity("continuity")]
    for f in M.CCfg.__dataclass_fields__: S.append(M.Continuity("continuity-no-" + f.replace("_", "-"), M.CCfg(**{f: False})))
    return S

def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}
def matches(e, x):
    op, key = x
    return e["op"] == op and (key is None or key in (e.get("host"), e.get("action"), e.get("ob"), e.get("amount")))

def run_one(ex, sc):
    w = World(ex, sc); res = w.execute(); m = {"controls": w.K, "caps": {"api": 100}, "obligations": [o["id"] for o in w.grants.obligations]}
    v = judge(m, w.recv, w.grants, w.approvals, w.rev); E = w.recv.effects
    done = all(any(matches(e, x) for e in E) for x in sc["expect"]) and not v
    if sc.get("single"): done = done and len(E) == len(sc["expect"])
    active = w.tgt if res["status"] == "MIGRATED" else (w.src if res["status"] == "ROLLED_BACK" else None)
    return {"scenario": sc["id"], "kind": sc["kind"], "system": ex.name, "status": res["status"], "reasons": res["reasons"], "unknown": bool(res["unknown"]), "violations": v, "violation_kinds": sorted({k for x in v for k in x["kinds"]}), "completed": done, "effects": len(E),
            "covered": None if active is None else not C.covers(w.K, active.eff), "replay_status": getattr(w, "status2", {}).get("status")}

def run():
    S = systems(); rows = [run_one(ex, sc) for ex in S for sc in SC.SCENARIOS]; summ = {}; per = {s["id"]: {"kind": s["kind"], "desc": s["desc"], "systems": {}} for s in SC.SCENARIOS}; meta = {s["id"]: s for s in SC.SCENARIOS}
    for ex in S:
        R = [r for r in rows if r["system"] == ex.name]; A = [r for r in R if r["kind"] == "attack"]; B = [r for r in R if r["kind"] == "benign"]; U = [r for r in R if r["kind"] == "unknown"]; F = {r["scenario"]: r for r in R if r["kind"] == "failure"}
        summ[ex.name] = {"attacks_with_a_prohibited_effect": rate(sum(1 for r in A if r["violations"]), len(A)), "benign_completed": rate(sum(1 for r in B if r["completed"]), len(B)), "benign_not_completed": [r["scenario"] for r in B if not r["completed"]], "benign_migrated": rate(sum(1 for r in B if r["status"] == "MIGRATED"), len(B)), "benign_with_a_prohibited_effect": [r["scenario"] for r in B if r["violations"]],
                         "benign_unjustified_denials": [r["scenario"] for r in B if r["status"] not in ("MIGRATED",) and not meta[r["scenario"]].get("justified_denial")], "justified_denials": [r["scenario"] for r in B if r["status"] != "MIGRATED" and meta[r["scenario"]].get("justified_denial")],
                         "unsupported_paths_with_a_prohibited_effect": rate(sum(1 for r in U if r["violations"]), len(U)), "unsupported_flagged_unknown": sum(1 for r in U if r["unknown"]), "unsupported_unflagged_with_effect": [r["scenario"] for r in U if r["violations"] and not r["unknown"]],
                         "policy_continuity_coverage": rate(sum(1 for r in A + B if r["covered"]), sum(1 for r in A + B if r["covered"] is not None)), "lost_obligation_or_label": sorted({r["scenario"] for r in A if set(r["violation_kinds"]) & {"OBLIGATION_LOST", "LABEL_VIOLATION"}}),
                         "revocation_not_propagated": sorted({r["scenario"] for r in list(F.values()) + A if "REVOKED_AFTER" in r["violation_kinds"]}), "telemetry_offline_attack_violated": bool(F["F01"]["violations"]), "telemetry_offline_benign_completed": F["F02"]["completed"]}
        for r in R:
            t = "V:" + "+".join(r["violation_kinds"]) if r["violations"] else ("ok" if r["kind"] == "attack" or r["completed"] else "BLOCKED")
            per[r["scenario"]]["systems"][ex.name] = t + ("(" + r["status"] + (",UNKNOWN" if r["unknown"] else "") + ")" if r["status"] != "MIGRATED" else "")
    full = {r["scenario"]: r for r in rows if r["system"] == "continuity"}
    red = [e.name for e in S if e.name.startswith("continuity-no-") and all((r["violations"] != [], r["completed"], r["status"]) == (full[r["scenario"]]["violations"] != [], full[r["scenario"]]["completed"], full[r["scenario"]]["status"]) for r in rows if r["system"] == e.name)]
    return {"systems": [e.name for e in S], "scenarios": [{"id": s["id"], "kind": s["kind"], "desc": s["desc"], "target": s["target"]} for s in SC.SCENARIOS], "summary": summ, "per_scenario": per, "rows": rows, "redundant": red, "runs": len(rows),
            "counterexamples": [{"scenario": r["scenario"], "system": r["system"], "violations": r["violations"]} for r in rows if r["kind"] == "attack" and r["violations"] and r["system"] in ("state-serialization", "token-copying", "container-snapshot", "config-sync", "tool-name-check", "restrictive-rule")]
                               + [{"scenario": r["scenario"], "system": r["system"], "violations": r["violations"], "note": "outside the assumptions (attestor deceived)" if r["scenario"] == "U02" else "unflagged"} for r in rows if r["system"] == "continuity" and r["violations"]]}
