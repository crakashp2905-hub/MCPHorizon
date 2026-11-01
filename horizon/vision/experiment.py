"""P51 experiments (P51-13, 14, 15): systems x scenarios. The oracle reads only the synthetic Site's receiver log and the scenario's authorized-effect list. Deterministic."""
from ..emergence.experiment import wilson
from ..hpolicy.authority import HorizonPolicy
from . import core as C, guard as G, scenarios as SC
from .world import Browser, Site, perform, violations, completed, APP

class Clock:
    def __init__(self): self.t = 1_000_000.0
    def __call__(self): return self.t

def systems():
    F = G.GCfg
    S = [("none", "baseline", None), ("screenshot-filter", "baseline", None), ("dom-text", "baseline", None), ("safe-browsing", "baseline", None), ("tool-allowlist", "baseline", None), ("restrictive-rule", "baseline", None), ("vision-guard", "guard", F())]
    for n, kw in (("element", {"bind_element": False}), ("frame", {"bind_frame": False}), ("element-frame", {"bind_element": False, "bind_frame": False}), ("element-frame-version", {"bind_element": False, "bind_frame": False, "bind_version": False}), ("version", {"bind_version": False}), ("derive-effect", {"derive_effect": False}), ("dest-policy", {"dest_policy": False}),
                  ("data-policy", {"data_policy": False}), ("input", {"bind_input": False}), ("approval", {"approval": False}), ("fail-closed", {"fail_closed": False}), ("script-unknown", {"script_unknown": False}), ("approval-binding", {"bind_approval": False})):
        S.append(("vision-guard-no-" + n, "guard", F(**kw)))
    return S

def _authorized(e, authorized): d = e.get("data", "plain"); return any(a["kind"] == e["kind"] and a["dest"] == e["dest"] and a.get("data", d) == d and a.get("resource", e["resource"]) in ("*", e["resource"]) for a in authorized)

def run_one(sc, name, kind, cfg):
    page = sc["build"](); br = Browser(page); site = Site(); clock = Clock(); auth = HorizonPolicy("pol-1", clock=clock); approver = auth.register_issuer("approver", {"APPROVAL"}); task = SC.task(**sc["task"])
    sysm = G.Guard(auth.verifier(), clock, cfg) if kind == "guard" else G.Baseline(name); decisions = []; confirms = 0
    for st in sc["steps"]:
        vis = None; op = "click"
        if "label" in st:
            xy = br.find_label(st["label"]); x, y = xy; vis = br.visual(x, y); intent, observed = vis.id, br.digest_of(vis)
        elif "ax" in st:
            op = st.get("tool", "click"); tgt = page.el(st["ax"]); x, y = tgt.rect[0] + 1, tgt.rect[1] + 1; vis = tgt; intent, observed = tgt.id, br.digest_of(tgt)
        else:
            op = "key"; x = y = None; bel = page.el(st["believed"]); intent, observed = bel.id, br.digest_of(bel)
        if st.get("tool"): op = st["tool"]
        if st.get("race"): page.mutate(st["race"])
        e = br.hit(x, y) if op == "click" and "ax" not in st else (page.el(st["ax"]) if "ax" in st else page.el(page.focus))
        if op == "click" and "ax" in st: e = br.hit(x, y) or e
        if e is None: decisions.append(("NOOP", "NOTHING_HIT")); continue
        b = br.binding(e, vis); view = {"visible": vis.text if vis else None, "dom": " ".join(v for v in (page.el(intent).text if intent else "", page.el(intent).role if intent else "") if v) + " " + " ".join(str(v) for v in ((e.reported or {}) if e.reported is not None else {k: (e.effect or {}).get(k) for k in ("kind", "dest", "resource")}).values()),
                                         "reported": e.reported if e.reported is not None else ({k: e.effect[k] for k in ("kind", "dest", "resource")} if e.effect else {"kind": "NONE"}), "frame_origin": page.frames[e.frame].origin, "top_origin": page.top, "instrumented": False}
        merged = {**view, **(b or {})}
        act = {"op": op, "x": x, "y": y, "intent": intent, "observed": observed, "tab": "t1"}
        d, why = sysm.decide(act, merged if (kind == "baseline" or b) else None, task)
        if d == "CONFIRM":
            confirms += 1; eff = b["effect"] if cfg.derive_effect else b["reported"]       # the reviewer sees what the guard shows
            if _authorized(eff, sc["authorized"]):
                tok = approver.issue("APPROVAL", principal="agent", artifact="ui", args_digest=C.envelope_digest(C.envelope(op, b["element"]["digest"], eff, b["input_digest"], b["top_origin"], b["tab"])), ttl=600, now=int(clock()))
                d, why = sysm.decide(act, b, task, tok)
            else: d, why = "DENY", "REVIEW_REFUSED"
        decisions.append((d, why))
        if d == "ALLOW": perform(br, site, e)
    viol = violations(site.log, sc["authorized"]); done = completed(site.log, sc["expected"]) if sc["expected"] else None
    return {"scenario": sc["id"], "kind": sc["kind"], "system": name, "violations": viol, "performed": len(site.log), "completed": done, "decisions": [list(x) for x in decisions], "unknown": sum(1 for d in decisions if d[0] == "UNKNOWN"),
            "denied": sum(1 for d in decisions if d[0] == "DENY"), "confirms": confirms}

def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}
def run():
    S = systems(); rows = [run_one(sc, n, k, c) for n, k, c in S for sc in SC.SCENARIOS]; summ = {}; per = {sc["id"]: {"kind": sc["kind"], "desc": sc["desc"], "systems": {}} for sc in SC.SCENARIOS}
    would = {r["scenario"]: bool(r["violations"]) for r in rows if r["system"] == "none"}
    meta = {sc["id"]: sc for sc in SC.SCENARIOS}
    for n, _, _ in S:
        R = [r for r in rows if r["system"] == n]; A = [r for r in R if r["kind"] == "attack"]; U = [r for r in R if r["kind"] in ("unknown",) or r["scenario"] == "M01"]; B = [r for r in R if r["kind"] == "benign"]
        summ[n] = {"attack_violated": rate(sum(1 for r in A if r["violations"]), len(A)), "unknown_paths_violated": rate(sum(1 for r in U if r["violations"]), len(U)), "unknown_paths_flagged_UNKNOWN": sum(1 for r in U if r["unknown"]),
                   "unknown_paths_that_would_violate": sum(1 for r in U if would[r["scenario"]]), "benign_completed": rate(sum(1 for r in B if r["completed"]), len(B)), "benign_blocked": [r["scenario"] for r in B if not r["completed"]],
                   "benign_unjustified_confirms": sum(r["confirms"] for r in B if not meta[r["scenario"]]["justified_confirm"]), "accessibility_completed": rate(sum(1 for r in B if meta[r["scenario"]]["ax"] and r["completed"]), sum(1 for r in B if meta[r["scenario"]]["ax"])),
                   "telemetry_offline_benign_completed": next(bool(r["completed"]) for r in R if r["scenario"] == "M02")}
        for r in R:
            per[r["scenario"]]["systems"][n] = ("V" if r["violations"] else "ok") if r["kind"] in ("attack", "unknown") or r["scenario"] == "M01" else ("ok" if r["completed"] else "BLOCKED")
    return {"systems": [n for n, _, _ in S], "scenarios": [{"id": s["id"], "kind": s["kind"], "desc": s["desc"]} for s in SC.SCENARIOS], "summary": summ, "per_scenario": per, "would_violate_unguarded": would, "runs": len(rows),
            "rows": [{k: r[k] for k in ("scenario", "system", "violations", "performed", "completed", "decisions", "unknown", "confirms")} for r in rows],
            "redundant": [n for n, k, _ in S if n.startswith("vision-guard-no-") and all(bool(r["violations"]) == bool(next(x for x in rows if x["scenario"] == r["scenario"] and x["system"] == "vision-guard")["violations"]) and r["completed"] == next(x for x in rows if x["scenario"] == r["scenario"] and x["system"] == "vision-guard")["completed"] for r in rows if r["system"] == n)]}
