"""The 15 modules P39..P53 and what the integration harness needs to know about each (P54-03): where the evidence lives, which files are the independent oracle / receiver and which are the system under test, how to read the headline pair."""
import json, os
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
def J(p): return json.load(open(os.path.join(ROOT, p)))
def kn(d): return {"k": d["k"], "n": d["n"]}
def cnt(k, n): return {"k": k, "n": n}

# id, name, package, results dir, tests dir, scripts prefix, oracle files (independent evidence), system files (under test)
M = [("P39", "HorizonEmergence", "emergence", "p39-emergence", "p39", ("oracle.py",), ("model.py", "baselines.py")),
     ("P40", "HorizonObligation", "obligation", "p40-obligation", "p40", ("services.py",), ("engine.py", "infer.py")),
     ("P41", "HorizonCounterfactual", "counterfactual", "p41-counterfactual", "p41", ("registry.py",), ("core.py", "commit.py")),
     ("P42", "HorizonCoverage", "coverage", "p42-coverage", "p42", ("harness.py", "observers.py"), ("engine.py",)),
     ("P43", "HorizonMutation", "mutation", "p43-mutation", "p43", ("oracle.py",), ("detectors.py",)),
     ("P44", "HorizonReach", "reach", "p44-reach", "p44", ("network.py",), ("broker.py",)),
     ("P45", "HorizonPrivacy", "privacy", "p45-privacy", "p45", ("reference.py",), ("accountant.py", "ledger.py")),
     ("P46", "HorizonDowngrade", "downgrade", "p46-downgrade", "p46", ("network.py",), ("engine.py", "gateway.py")),
     ("P47", "HorizonIncentive", "incentive", "p47-incentive", "p47", ("oracle.py",), ("monitor.py", "preflight.py")),
     ("P48", "HorizonConsent", "consent", "p48-consent", "p48", ("oracle.py",), ("monitor.py", "core.py")),
     ("P49", "HorizonEvalIntegrity", "evalint", "p49-evalint", "p49", ("evaluator.py",), ("world.py",)),
     ("P50", "HorizonBudget", "budget", "p50-budget", "p50", ("sinks.py",), ("ledger.py", "broker.py")),
     ("P51", "HorizonVisionGuard", "vision", "p51-vision", "p51", ("world.py",), ("guard.py",)),
     ("P52", "HorizonTemporal", "temporal", "p52-temporal", "p52", ("oracle.py",), ("gate.py", "approver.py")),
     ("P53", "HorizonContinuity", "continuity", "p53-continuity", "p53", ("oracle.py",), ("migrate.py", "runtime.py"))]
MODULES = [{"id": i, "name": n, "pkg": p, "results": r, "tests": t, "oracle": [f"horizon/{p}/{f}" for f in o], "system": [f"horizon/{p}/{f}" for f in s]} for i, n, p, r, t, o, s in M]
BY_ID = {m["id"]: m for m in MODULES}

def load(m): return J("results/v2/%s/result.json" % m["results"])

def headline(m, r=None):
    """The module's own paired headline from its recorded result: guarded attack outcomes and benign completions. Methodology modules (P39, P42, P43) report their detection pair instead. Returns {family, system, attack_prevented, benign_completed, notes}."""
    r = r if r is not None else load(m); i = m["id"]; S = r.get("summary", {})
    if i == "P39": b = r["baselines"]["emergence"]; return dict(family="detection", system="emergence", attack_prevented=cnt(b["tp"], b["tp"] + b["fn"]), benign_completed=cnt(b["tn"], b["tn"] + b["fp"]), notes=["pair = detected leaks / true leaks; benign = correctly passed safe chains"])
    if i == "P42": h = r["benchmark"]["horizon_coverage"]; return dict(family="coverage", system="horizon_coverage", attack_prevented=cnt(h["loss_of_assurance_detected"], h["regressions"]), benign_completed=cnt(0 if r["healthy_control"]["false_alarm"] else 1, 1), notes=["pair = detected loss of assurance / injected regressions; benign = healthy control without false alarm"])
    if i == "P43": d = r["detectors"]["D2b-lineage-v2"]; return dict(family="detection", system="D2b-lineage-v2", attack_prevented=kn(d["recall"]), benign_completed=cnt(d["tn"], d["tn"] + d["fp"]), notes=["pair = detected verdict flips / oracle-confirmed flips; benign = verdict-preserving variants passed"])
    if i == "P40": s = S["runtime"]; return dict(family="guard", system="runtime", attack_prevented=cnt(s["attacks_with_no_unsafe_commit"], s["attack_runs"]), benign_completed=cnt(s["benign_completed_correctly"], s["benign_runs"]), notes=[])
    if i == "P41": s = S["counterfactual"]; return dict(family="guard", system="counterfactual", attack_prevented=cnt(s["attacks_without_unsafe_effect"], s["attack_runs"]), benign_completed=cnt(s["benign_completed"], s["benign_runs"]), notes=[])
    if i == "P44": s = S["reach"]; return dict(family="guard", system="reach", attack_prevented=kn(s["attacks_prevented"]), benign_completed=kn(s["benign_completed"]), notes=[])
    if i == "P45": s = S["horizon-advanced"]; a = s["attacks_over_budget"]; return dict(family="guard", system="horizon-advanced", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=[])
    if i == "P46": s = S["guard"]; a = s["attack_runs_with_unauthorized_effect"]; return dict(family="guard", system="guard", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=["%d of %d attack runs were stopped without completing" % (s["attack_runs_stopped_without_completion"]["k"], s["attack_runs_stopped_without_completion"]["n"])])
    if i == "P47": s = S["monitor"]; a = s["attack_runs_with_unauthorized_effect"]; return dict(family="guard", system="monitor", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_runs_completed"]), notes=[])
    if i == "P48": s = S["consent"]; a = s["attack_with_unauthorized_effect"]; return dict(family="guard", system="consent", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=[])
    if i == "P49": s = S["evalint"]; a = s["false_pass_under_compromise"]; return dict(family="evaluation-integrity", system="evalint", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_pass"]), notes=["%d of %d compromised runs were UNKNOWN (unverifiable), not PASS" % (s["unverifiable_under_compromise"]["k"], s["unverifiable_under_compromise"]["n"])])
    if i == "P50": s = S["budget"]; a = s["attack_over_budget"]; return dict(family="guard", system="budget", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=[])
    if i == "P51": s = S["vision-guard"]; a = s["attack_violated"]; return dict(family="guard", system="vision-guard", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=["benign blocked: " + ", ".join(s["benign_blocked"])])
    if i == "P52": s = S["temporal"]; a = s["attacks_with_a_violating_interleaving"]; return dict(family="guard", system="temporal", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed_in_every_interleaving"]), notes=[])
    if i == "P53": s = S["continuity"]; a = s["attacks_with_a_prohibited_effect"]; return dict(family="guard", system="continuity", attack_prevented=cnt(a["n"] - a["k"], a["n"]), benign_completed=kn(s["benign_completed"]), notes=[])
    raise KeyError(i)
