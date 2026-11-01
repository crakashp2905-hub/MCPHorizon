"""P54 assembly: runs every integration check and returns one record. Deterministic apart from the environment section and wall-clock fields in the reproduction rows."""
from . import audit as AU, receipts as RC, review as RV, stats as ST, protocols as PR, statemachine as SM, tamper as TP, reproduce as RP, manifest as MF, gates as GT
from .registry import MODULES, load

def has_baselines(m):
    r = load(m); S = r.get("summary", {})
    return bool({"baselines", "detectors", "benchmark"} & set(r)) or (isinstance(S, dict) and len(S) >= 3)

def collect(reproduce=True, freeze=None):
    svc = RC.ReceiptService(); toks = svc.issue_all(); v = svc.verifier()
    R = {"audit": AU.audit(), "freeze": freeze or AU.freeze(), "table": ST.table(), "families": ST.families(), "negative_findings": ST.negative_findings(),
         "receipts": [RC.verdict(m["id"], toks[m["id"]], v) for m in MODULES], "review": RV.review(), "has_baselines": {m["id"]: has_baselines(m) for m in MODULES}}
    R["freeze_diff"] = AU.check(R["freeze"])
    p = PR.parity(); R["protocols"] = {"parity": {k: p[k] for k in ("workflows", "paths", "traps", "metamorphic_discrepancies")}, "discrepancy_count": len(p["discrepancies"]), "unexpected_discrepancies": PR.unexpected(p), "expected": sorted("%s/%s" % x for x in PR.expected_classes()),
                                       "non_equivalent_fixtures_flagged": all(not eq for _, eq in PR.fixtures()), "carrier_roundtrip": PR.carriers(), "browser": PR.browser_adapter(), "native_adapters": "none available in this environment"}
    R["statemachine"] = SM.run_all()
    ev = TP.evaluator(); rc = TP.receipts(); R["tamper"] = {"evaluator": ev, "evaluator_baselines": TP.evaluator_baselines(), "receipts": rc, "receipts_ok": TP.receipts_ok(rc), "coverage_loss": TP.coverage_loss()}
    R["reproduction"] = RP.reproduce_all() if reproduce else []
    R["environment"] = MF.environment()
    R["gates"] = GT.evaluate(R)
    return R
