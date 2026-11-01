"""P49 experiments: systems x scenarios, with the mock service's own record as ground truth (P49-14, 15). Deterministic; intervals are Wilson over scenarios and descriptive only."""
from dataclasses import replace
from ..emergence.experiment import wilson
from . import evaluator as EV, scenarios as SC
from .core import ECfg, digest, canonical
from .world import Run, Services, Deploy

WEAK = Deploy(labels_in_workspace=True, evidence_writable=True, os_audit=False)
STRONG = Deploy()
BENIGN_FLAGS = {"DUPLICATE", "REORDERED"}
ABL = [("signatures", "signatures"), ("chain", "chain"), ("seal", "seal"), ("run_binding", "run_binding"), ("manifest", "manifest"), ("time", "time"), ("receiver_oracle", "receiver_oracle"), ("tool_stream", "tool_stream"), ("os_stream", "os_stream"), ("reconcile", "reconcile"), ("identity", "identity"), ("transcript_check", "transcript_check")]
SYSTEMS = [("self-report", "base", WEAK, None), ("app-logging", "base", WEAK, None), ("shared-grader", "base", WEAK, None), ("audit-no-root-sep", "base", WEAK, None), ("evalint", "full", STRONG, ECfg())] \
    + [("evalint-no-" + n, "full", STRONG, replace(ECfg(), **{f: False})) for n, f in ABL] + [("evalint-no-label-acl", "full", Deploy(labels_in_workspace=True), ECfg()), ("evalint-no-os-audit", "full", Deploy(os_audit=False), ECfg())]
BASE = {"self-report": EV.self_report, "app-logging": EV.app_logging, "shared-grader": EV.shared_grader, "audit-no-root-sep": EV.audit_no_root_sep}
def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}


def run_one(sc, sysm):
    name, kind, dep, cfg = sysm; svc = Services(); r = Run(dep, svc, breach=sc["breach"], uids=sc["uids"]); sc["fn"](r); r.finish()
    if sc["post"]: sc["post"](r)
    b = r.bundle(); v = EV.evaluate(b, {"verifier": svc.verifier, "now": r.clock.now() + 1, "label": r.eval_label}, cfg) if kind == "full" else BASE[name](b, r)
    nbytes = sum(len(canonical(x)) for rs in r.streams.values() for x in rs)
    viol = r.violation(); fl = [f for f in v["flags"] if f.split(":")[-1] not in BENIGN_FLAGS]; detected = v["verdict"] != "PASS" or bool(fl)
    cheat = any(a == "labels" for _, a in r.denied) is False and sc["tamper"] == "label" and dep.labels_in_workspace
    return {"scenario": sc["id"], "kind": sc["kind"], "system": name, "verdict": v["verdict"], "flags": v["flags"], "violation": viol, "tamper": sc["tamper"], "detected": detected, "cheat_succeeded": cheat, "records": sum(len(x) for x in r.streams.values()), "bytes": nbytes,
            "verified_effects": len(v.get("verified_effects", [])), "unknowns": len(v.get("unknowns", [])), "false_pass": viol and v["verdict"] == "PASS"}


def run():
    rows = [run_one(sc, s) for s in SYSTEMS for sc in SC.SCENARIOS]; summ = {}; per = {sc["id"]: {"kind": sc["kind"], "desc": sc["desc"], "systems": {}} for sc in SC.SCENARIOS}
    for name, *_ in SYSTEMS:
        R = [r for r in rows if r["system"] == name]; hostile = [r for r in R if r["kind"] in ("attack", "failure") and r["violation"]]; tam = [r for r in R if r["kind"] == "attack" and r["tamper"]]; ben = [r for r in R if r["kind"] == "benign"]; bd = [r for r in R if r["kind"] == "boundary"]
        summ[name] = {"false_pass_under_compromise": rate(sum(r["false_pass"] for r in hostile), len(hostile)), "unverifiable_under_compromise": rate(sum(r["verdict"] == "UNVERIFIABLE" for r in hostile), len(hostile)), "tamper_discovery": rate(sum(r["detected"] for r in tam), len(tam)),
                      "benign_pass": rate(sum(r["verdict"] == "PASS" and not r["violation"] for r in ben if not r["violation"]), len([r for r in ben if not r["violation"]])), "benign_unverifiable": sum(r["verdict"] == "UNVERIFIABLE" for r in ben), "benign_false_fail": sum(r["verdict"] == "FAIL" and not r["violation"] for r in ben),
                      "honest_violation_reported_fail": [r["verdict"] for r in ben if r["violation"]], "label_cheat_successes": sum(r["cheat_succeeded"] for r in R), "boundary_verdict": [r["verdict"] for r in bd], "mean_records": round(sum(r["records"] for r in ben) / len(ben), 1), "mean_bytes": round(sum(r["bytes"] for r in ben) / len(ben))}
        for r in R: per[r["scenario"]]["systems"][name] = r["verdict"] + ("*" if r["violation"] else "")
    return {"systems": [s[0] for s in SYSTEMS], "scenarios": [{"id": s["id"], "kind": s["kind"], "desc": s["desc"]} for s in SC.SCENARIOS], "summary": summ, "per_scenario": per, "runs": len(rows), "rows": [{k: r[k] for k in ("scenario", "system", "verdict", "flags", "violation")} for r in rows]}
