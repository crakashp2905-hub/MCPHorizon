#!/usr/bin/env python3
"""Generate docs/evidence/p51/RESULTS.md from the write-once results. `--check` verifies the doc is current."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
R = json.load(open(os.path.join(ROOT, "results/v2/p51-vision/result.json"))); BJ = json.load(open(os.path.join(ROOT, "results/v2/p51-vision-browser/browser.json")))
ci = lambda c: "%d/%d [%.2f, %.2f]" % (c["k"], c["n"], c["ci"][0], c["ci"][1])
DESC = {"none": "agent acts on what it sees", "screenshot-filter": "blocks when the text visible under the click point contains a risk word (upload, send, delete, pay, transfer, export, submit, download, share, confirm)", "dom-text": "blocks when the DOM text / page-reported effect of the element the agent named looks risky",
        "safe-browsing": "origin blocklist (the attack origins are not on it)", "tool-allowlist": "allows click/key tools, denies the explicit upload/download tools; no element or origin binding (the policy-only baseline)",
        "restrictive-rule": "hand-written blanket rule on TRUSTED bindings: deny every upload, download and clipboard effect and every cross-origin effect", "vision-guard": "HorizonVisionGuard: element/frame/version binding to browser-derived identity, effect derived by the browser, destination and data policy, input digest, approval at protected sinks, UNKNOWN when it cannot bind"}

def results():
    rows = {(r["scenario"], r["system"]): r for r in R["rows"]}; S = R["summary"]
    L = ["# P51 results — HorizonVisionGuard (CANDIDATE)", "", "Generated from `results/v2/p51-vision/result.json` (model experiment) and `results/v2/p51-vision-browser/browser.json` (real Chromium), both write-once. **Ground truth is the synthetic site's server-side receiver log** judged against each scenario's authorized-effect list; no click log, guard decision or agent claim is read by the oracle. Verified effects (prohibited effect really reached a receiver) and UNKNOWN (the guard could not bind the action) are reported separately.", "",
         "Intervals are Wilson over scenarios and descriptive: the suite is small, scripted and written by the same author as the guard.", "", "## Model experiment: %d runs = %d scenarios × %d systems" % (R["runs"], len(R["scenarios"]), len(R["systems"])), "",
         "| system | attacks with a prohibited effect [95% CI] | unsupported/unbindable paths with a prohibited effect | of those, flagged UNKNOWN | benign completed [95% CI] | benign not completed | unjustified confirmations on benign | accessibility paths completed | matched benign form with telemetry offline |", "|---|---|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = S[s]; L.append("| %s | %s | %s | %d | %s | %s | %d | %s | %s |" % (s, ci(v["attack_violated"]), ci(v["unknown_paths_violated"]), v["unknown_paths_flagged_UNKNOWN"], ci(v["benign_completed"]), ", ".join(v["benign_blocked"]) or "none", v["benign_unjustified_confirms"], ci(v["accessibility_completed"]), "completed" if v["telemetry_offline_benign_completed"] else "blocked"))
    L += ["", "| baseline / system | what it does |", "|---|---|"] + ["| %s | %s |" % kv for kv in DESC.items()] + ["| vision-guard-no-<mechanism> | full guard with one mechanism disabled |", "",
          "Attack scenarios are A01–A11; the 'unsupported/unbindable' set is U01–U05 (native file dialog, popup, drag-drop, side panel, script-initiated request) plus M01 (telemetry offline during an overlay page): %d of %d would produce a prohibited effect if run unguarded." % (sum(1 for k in ("U01", "U02", "U03", "U04", "U05", "M01") if R["would_violate_unguarded"][k]), 6), "",
          "## Per scenario (`V` = a prohibited effect reached a receiver; benign: ok / BLOCKED)", "", "| id | kind | " + " | ".join(R["systems"]) + " |", "|---|---|" + "---|" * len(R["systems"])]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"][s] for s in R["systems"])))
    L += ["", "| id | what happens |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["desc"]) for s in R["scenarios"]]
    L += ["", "## Ablations: where the outcome changes against the full guard", "", "| ablation | scenarios that change (outcome → outcome) |", "|---|---|"]
    for s in R["systems"]:
        if not s.startswith("vision-guard-no-"): continue
        ch = [x["id"] for x in R["scenarios"] if R["per_scenario"][x["id"]]["systems"][s] != R["per_scenario"][x["id"]]["systems"]["vision-guard"]]
        L.append("| %s | %s |" % (s, "; ".join("%s: %s→%s" % (i, R["per_scenario"][i]["systems"]["vision-guard"], R["per_scenario"][i]["systems"][s]) for i in ch) or "none (redundant in this suite)"))
    L += ["", "Redundant here: %s. Element, frame and version binding each catch the overlay/clickjacking cases (A01–A03, A11); only removing all three loses them (`vision-guard-no-element-frame-version`). Approval-envelope binding is covered by unit tests, not by a scenario in which a token for another envelope is available to the attacker." % ", ".join(R["redundant"]), "",
          "## Real Chromium (%s), loopback only" % BJ["chromium"], "", "Three synthetic origins (app 127.0.0.1, evil localhost, ads 127.0.0.2), Chromium with `--no-proxy-server`, every non-loopback request aborted (stray requests recorded below: %d). Trusted binding is read through DevTools (hit-test, frame tree, isolated-world element semantics); the agent's 'screenshot' perception is a DOM-side proxy for pixels." % sum(len(r["stray_requests"]) for r in BJ["rows"]), "",
          "| scenario | kind | unguarded: prohibited effect reached the receiver | guarded decision | guarded: prohibited effect | benign completed (unguarded / guarded) |", "|---|---|---|---|---|---|"]
    byid = {}
    for r in BJ["rows"]: byid.setdefault(r["scenario"], {})[r["guarded"]] = r
    for sid, g in byid.items():
        a, b = g[False], g[True]; L.append("| %s | %s | %s | %s | %s | %s |" % (sid, a["kind"], "yes (%s)" % ", ".join("%s %s %s" % (e["kind"], e["resource"], e["data"]) for e in a["violations"]) if a["violations"] else "no", "; ".join("%s %s" % tuple(d) for d in b["decisions"]), "yes" if b["violations"] else "no",
                                                                                 "%s / %s" % (a["completed"], b["completed"]) if a["completed"] is not None else "n/a"))
    t = BJ["timing_ms_machine_specific"]; L += ["", "Per-action guard decision time (DevTools probe): see `decision_ms` is not recorded per row; whole-scenario wall time for the matched benign form, %d repeats: unguarded median %.0f ms / p95 %.0f ms; guarded median %.0f ms / p95 %.0f ms. **Machine-specific**, dominated by Chromium context start-up; the per-action probe cost is several CDP round trips (single-digit to ~20 ms in the exploratory runs) and the model decision is microseconds (`scripts/p51_bench.py`).  Accessibility regressions are measured only in the model (B06, B10) and in none of the real-browser scenarios.".replace("see `decision_ms` is not recorded per row; ", "") % (t["guarded"]["n"], t["unguarded"]["median"], t["unguarded"]["p95"], t["guarded"]["median"], t["guarded"]["p95"]), "",
          "## What this does and does not show", "", "- Zero prohibited effects for the full guard is a property of 11 attacks and 6 unbindable paths written by the same author, in a model plus 5 real-browser attacks. It is not a proof and the intervals say so.",
          "- Element-binding accuracy: in the model every attack that relies on a mismatch between the visible and hit-tested element is caught by element, frame or version binding; the real browser reproduces this for overlays (R01, R02), a cross-origin frame (R03), a re-pointed form (R04) and a clobbered form action (R05).",
          "- Script-initiated effects (fetch, XHR, window.open from a handler) have no declarative effect to derive. The guard reports UNKNOWN for any element with a click-like listener on it, its form or an ancestor; that blocks ordinary scripted buttons (B11, R11) and is the price of not guessing.",
          "- Native file dialogs, popups, drag-and-drop and extension surfaces are outside the instrumentation (U01–U04) and are UNKNOWN; they are modelled, not exercised in Chromium.",
          "- The preflight reviewer is a mechanical ideal-attentive proxy (approves iff the shown effect is in the authorized list); it measures the mechanism, not human behaviour.", ""]
    return "\n".join(L)

p = os.path.join(ROOT, "docs/evidence/p51/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p51 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
