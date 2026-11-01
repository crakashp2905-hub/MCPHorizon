"""P54-10: simulated loss of coverage and tampered evaluator records must yield UNKNOWN / BLOCK / FAIL, never a false PASS.
Live: the P49 evaluator against every scenario where the run really violated policy; the receipt verdict against edited evidence; P53 with the revocation feed offline. Recorded (not re-run here): P42 detection of injected regressions, P52 telemetry-offline."""
import json, os
from unittest import mock
from ..evalint import experiment as EE, scenarios as ES
from ..continuity import experiment as CE, scenarios as CS
from . import receipts as RC
from .registry import BY_ID, load

def evaluator():
    full = [s for s in EE.SYSTEMS if s[0] == "evalint"][0]; rows = []
    for sc in ES.SCENARIOS:
        r = EE.run_one(sc, full)
        if r["violation"]: rows.append({"scenario": sc["id"], "kind": sc["kind"], "tamper": sc["tamper"], "verdict": r["verdict"], "false_pass": r["false_pass"]})
    inside = [x for x in rows if x["kind"] != "boundary"]; edge = [x for x in rows if x["kind"] == "boundary"]
    return {"violating_runs": len(inside), "false_pass": sum(x["false_pass"] for x in inside), "verdicts": sorted({x["verdict"] for x in inside}), "rows": inside,
            "outside_assumptions": edge, "note": "X01 (all three collectors omit consistently) is outside the stated assumptions of P49; it is a known false PASS and is reported, not counted"}
def evaluator_baselines():
    """Control: the weak graders DO produce false passes on the same runs (otherwise the check above proves nothing)."""
    out = {}
    for s in EE.SYSTEMS:
        if s[1] != "base": continue
        n = f = 0
        for sc in ES.SCENARIOS:
            r = EE.run_one(sc, s)
            if r["violation"] and sc["kind"] != "boundary": n += 1; f += r["false_pass"]
        out[s[0]] = {"false_pass": f, "violating_runs": n}
    return out

def receipts():
    """Edit the evidence under a valid receipt, in each of the three places; expire it; present another module's receipt; present none; present one from a different authority."""
    svc = RC.ReceiptService(); v = svc.verifier(); tok = svc.issue("P53"); out = {}
    real = RC.fsha
    for name, needle in (("result_edited", "result.json"), ("oracle_edited", "continuity/oracle.py"), ("system_edited", "continuity/migrate.py")):
        with mock.patch.object(RC, "fsha", lambda rel, n=needle: "sha256:edited" if n in rel else real(rel)): out[name] = RC.verdict("P53", tok, v)
    out["expired"] = RC.verdict("P53", tok, v, now=int(svc.clock()) + 10 ** 6); out["other_module"] = RC.verdict("P52", tok, v); out["none"] = RC.verdict("P53", None, v)
    out["other_authority"] = RC.verdict("P53", RC.ReceiptService().issue("P53"), v); out["intact"] = RC.verdict("P53", tok, v)
    return out
def receipts_ok(o): return o["intact"]["verdict"] == "INTACT" and all(o[k]["verdict"] in ("TAMPERED", "UNKNOWN") for k in o if k != "intact")

def coverage_loss():
    ex = [e for e in CE.systems() if e.name == "continuity"][0]; f = {s["id"]: CE.run_one(ex, s) for s in CS.SCENARIOS if s["id"] in ("F01", "F02")}
    p42 = load(BY_ID["P42"]); p52 = load(BY_ID["P52"])["summary"]["temporal"]
    return {"p53_revoked_and_feed_offline": {"prohibited_effect": bool(f["F01"]["violations"]), "status": f["F01"]["status"], "unknown": f["F01"]["unknown"]}, "p53_benign_and_feed_offline": {"completed": f["F02"]["completed"], "status": f["F02"]["status"]},
            "p52_recorded": {"attack_violated": p52["telemetry_offline_attack_violated"], "benign_completed": p52["telemetry_offline_benign_completed"]}, "p42_recorded": {"regressions_detected": p42["benchmark"]["horizon_coverage"]["loss_of_assurance_detected"], "regressions": p42["benchmark"]["horizon_coverage"]["regressions"], "healthy_false_alarm": p42["healthy_control"]["false_alarm"]}}
