"""P50 experiments (P50-13, 15): systems x scenarios against the receiver's own counters. Deterministic except the thread race in A02, which is made stable by a barrier and a fixed gap."""
from ..emergence.experiment import wilson
from . import harness as H, scenarios as SC


def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}
def run_one(sc, sysm):
    e = H.Env(sysm)
    try:
        sc["fn"](e); over = e.over(); exp = [a for a in e.attempts if a["expect"]]; unk = 0
        if e.led:
            unk = sum(1 for (s,) in e.led.db.execute("SELECT state FROM res").fetchall() if s == "UNKNOWN") + sum(1 for (s,) in e.led.db.execute("SELECT state FROM res").fetchall() if s == "STARTED")
        return {"scenario": sc["id"], "kind": sc["kind"], "system": sysm.name, "over": over, "excess": sum(o["total"] - o["cap"] for o in over), "completed": (all(a["status"] == "ok" for a in exp) if exp else None), "denied": sum(1 for a in e.attempts if a["status"] == "denied"),
                "effects": sum(x["n"] for x in e.rc.effects), "unknown_reservations": unk, "invariants": (e.led.invariants() if e.led else None), "chain": (e.led.verify_chain() if e.led else None)}
    finally: e.close()
def run():
    S = H.systems(); rows = [run_one(sc, s) for s in S for sc in SC.SCENARIOS]; summ = {}; per = {sc["id"]: {"kind": sc["kind"], "desc": sc["desc"], "systems": {}} for sc in SC.SCENARIOS}
    for s in S:
        R = [r for r in rows if r["system"] == s.name]; at = [r for r in R if r["kind"] == "attack"]; bn = [r for r in R if r["kind"] == "benign"]
        summ[s.name] = {"attack_over_budget": rate(sum(1 for r in at if r["over"]), len(at)), "mean_excess_units": round(sum(r["excess"] for r in at) / len(at), 1), "benign_completed": rate(sum(1 for r in bn if r["completed"]), len(bn)), "benign_over_budget": sum(1 for r in bn if r["over"]),
                        "failure_over_budget": sum(1 for r in R if r["kind"] == "failure" and r["over"]), "failure_unknown_reservations": sum(r["unknown_reservations"] for r in R if r["kind"] == "failure"), "invariant_violations": sum(len(r["invariants"] or []) for r in R)}
        for r in R: per[r["scenario"]]["systems"][s.name] = ("V%d" % r["excess"] if r["over"] else "ok") if r["kind"] != "benign" else ("ok" if r["completed"] and not r["over"] else ("BLOCKED" if not r["completed"] else "OVER"))
    return {"systems": [s.name for s in S], "scenarios": [{"id": s["id"], "kind": s["kind"], "desc": s["desc"]} for s in SC.SCENARIOS], "summary": summ, "per_scenario": per, "runs": len(rows), "redundant": [s.name for s in S if s.name.startswith("budget-no-") and summ[s.name]["attack_over_budget"]["k"] == 0], "rows": [{k: r[k] for k in ("scenario", "system", "over", "excess", "completed", "denied", "effects", "unknown_reservations")} for r in rows]}
