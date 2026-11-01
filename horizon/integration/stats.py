"""P54-14: per-family tables with Wilson intervals and the negative findings, all read from the recorded results of P39..P53 (nothing is re-scored here).
Counts are scenarios, not independent trials, and every suite was written by the same author as its module and baselines: intervals are descriptive and not a performance claim."""
import json, os
from ..emergence.experiment import wilson
from .registry import MODULES, BY_ID, headline, ROOT

def ci(k, n): return None if not n else [round(x, 4) for x in wilson(k, n)]
def row(c): return {"k": c["k"], "n": c["n"], "rate": None if not c["n"] else round(c["k"] / c["n"], 4), "ci": ci(c["k"], c["n"])}
def table():
    rows = []
    for m in MODULES:
        h = headline(m); rows.append({"module": m["id"], "name": m["name"], "family": h["family"], "system": h["system"], "attack_prevented": row(h["attack_prevented"]), "benign_completed": row(h["benign_completed"]), "notes": h["notes"]})
    return rows
def families():
    out = {}
    for r in table():
        f = out.setdefault(r["family"], {"modules": [], "attack_k": 0, "attack_n": 0, "benign_k": 0, "benign_n": 0})
        f["modules"].append(r["module"]); f["attack_k"] += r["attack_prevented"]["k"]; f["attack_n"] += r["attack_prevented"]["n"]; f["benign_k"] += r["benign_completed"]["k"]; f["benign_n"] += r["benign_completed"]["n"]
    for f in out.values(): f["attack_ci"] = ci(f["attack_k"], f["attack_n"]); f["benign_ci"] = ci(f["benign_k"], f["benign_n"])
    return out

def _j(rel): return json.load(open(os.path.join(ROOT, rel)))
def _has(rel, needle): return needle in open(os.path.join(ROOT, rel)).read()
# (module, finding, source file, needle that must appear in the source file)
CURATED = [("P44", "some forbidden destinations were reached: attacks prevented are less than all attack runs", "results/v2/p44-reach/result.json", "attacks_with_forbidden_effect"),
           ("P46", "a quarter of attack runs ended without completing the task (the guard stopped them; the task was not done)", "results/v2/p46-downgrade/result.json", "attack_runs_stopped_without_completion"),
           ("P47", "benign runs with a justified denial exist: the monitor refused something the contract really forbade", "results/v2/p47-incentive/result.json", "benign_runs_justified_denial"),
           ("P49", "under compromise a share of runs are UNVERIFIABLE rather than PASS: the module declines to vouch for them, it does not recover the truth", "results/v2/p49-evalint/result.json", "unverifiable_under_compromise"),
           ("P50", "failure runs leave reservations in an UNKNOWN state that stay charged", "results/v2/p50-budget/result.json", "failure_unknown_reservations"),
           ("P51", "two benign tasks (B09, B11) are blocked by the guard", "results/v2/p51-vision/result.json", "benign_blocked"),
           ("P52", "paths the gateway does not support (U01, U02) are only flagged UNKNOWN, not prevented", "results/v2/p52-temporal/result.json", "unsupported_paths_violated_and_flagged_unknown"),
           ("P53", "U02 (a deceived attestor) is a known trust gap: reported, not prevented", "results/v2/p53-continuity/trust_gaps.json", "U02")]
def negative_findings():
    out = []
    for r in table():
        a, b = r["attack_prevented"], r["benign_completed"]
        if a["k"] < a["n"]: out.append({"module": r["module"], "finding": "%s: %d of %d attack runs were NOT prevented (headline system %s)" % (r["module"], a["n"] - a["k"], a["n"], r["system"]), "source": "results/v2/%s/result.json" % BY_ID[r["module"]]["results"], "auto": True})
        if b["k"] < b["n"]: out.append({"module": r["module"], "finding": "%s: %d of %d benign runs did not complete (headline system %s)" % (r["module"], b["n"] - b["k"], b["n"], r["system"]), "source": "results/v2/%s/result.json" % BY_ID[r["module"]]["results"], "auto": True})
    for m, f, src, needle in CURATED:
        if not _has(src, needle): raise AssertionError("curated finding for %s not found in %s" % (m, src))
        out.append({"module": m, "finding": f, "source": src, "auto": False})
    return out
