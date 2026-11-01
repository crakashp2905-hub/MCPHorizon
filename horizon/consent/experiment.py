"""P48 experiments: system matrix (P48-14), ablations, display faithfulness (P48-08 structural), compare screen. Deterministic: no random choices, so one run per (scenario, system); intervals are Wilson over scenarios (descriptive)."""
from ..emergence.experiment import wilson
from . import harness as H, scenarios as SC, core as K, review as RV


def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}


def compare_view():
    e = H.Env(H.systems()[5]); c = e.ctx(); clean = SC.PUB(); a = SC.PUB(mirrors=["mirror"]); m = e.platform.effect_of(a, c["tenant"], c["task"]); prev = e.platform.effect_of(clean, c["tenant"], c["task"]); views = {}
    for mode in ("button", "prose", "args", "effect", "diff"): views[mode] = e.service.present(mode, a, c, previous=prev, agent_fields=e.true_fields(clean, c))
    return RV.compare_screen(views, m, e.names())


def run():
    sysm = H.systems(); rows = [H.run_one(sc, s) for s in sysm for sc in SC.SCENARIOS]; summ = {}; per = {sc["id"]: {"kind": sc["kind"], "desc": sc["desc"], "systems": {}} for sc in SC.SCENARIOS}
    for s in sysm:
        at = [r for r in rows if r["system"] == s.name and r["kind"] == "attack"]; bn = [r for r in rows if r["system"] == s.name and r["kind"] == "benign"]; kinds = {}
        for r in at:
            for v in r["violations"]: kinds[v["kind"]] = kinds.get(v["kind"], 0) + 1
        summ[s.name] = {"attack_with_unauthorized_effect": rate(sum(1 for r in at if r["violations"]), len(at)), "attack_blocked_all_effects": rate(sum(1 for r in at if not r["violations"]), len(at)), "benign_completed": rate(sum(1 for r in bn if r["completed"]), len(bn)),
                        "benign_with_violation": rate(sum(1 for r in bn if r["violations"]), len(bn)), "false_blocks": sum(r["false_blocks"] for r in bn), "violation_kinds": kinds}
        for r in rows:
            if r["system"] == s.name: per[r["scenario"]]["systems"][s.name] = ("V" + "+".join(sorted({v["kind"] for v in r["violations"]}))) if r["violations"] and r["kind"] == "attack" else ("ok" if (r["kind"] == "benign" and r["completed"]) else ("blocked" if r["kind"] == "attack" else "BLOCKED"))
    disp = {}
    for s in sysm:
        if s.name in ("confirm-button", "free-form-prompt", "consent-args-display", "consent", "consent+diff"):
            rv = [x for r in rows if r["system"] == s.name and r["kind"] == "attack" for x in r["reviews"]]; n = len(rv)
            disp[s.name] = {"mode": s.mode, "requests": n, "mean_correct_fields": round(sum(x["faith"]["correct"] for x in rv) / n, 2), "mean_total_fields": round(sum(x["faith"]["total"] for x in rv) / n, 2), "requests_with_omitted": sum(1 for x in rv if x["faith"]["omitted"]), "requests_with_misleading": sum(1 for x in rv if x["faith"]["misleading"]), "reviewer_objected": sum(1 for x in rv if not x["approved"])}
    return {"systems": [s.name for s in sysm], "scenarios": [{"id": s["id"], "kind": s["kind"], "desc": s["desc"]} for s in SC.SCENARIOS], "summary": summ, "per_scenario": per, "display": disp, "compare_screen": compare_view(), "runs": len(rows),
            "flags": H.FLAGS, "redundant_flags": [f for f in H.FLAGS if summ["consent-no-" + f]["attack_with_unauthorized_effect"]["k"] == 0]}
