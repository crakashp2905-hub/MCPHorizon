#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = json.load(open(os.path.join(ROOT, "results/v2/p48-consent/result.json")))
ci = lambda c: "%d/%d [%.2f, %.2f]" % (c["k"], c["n"], c["ci"][0], c["ci"][1])
BASE = ["none", "tool-guardrail", "confirm-button", "free-form-prompt", "signed-args", "consent", "consent+diff", "consent-args-display", "consent-prose-display"]
DESC = {"none": "no gate", "tool-guardrail": "static name allowlist / amount cap / no SECRET artifacts; no approvals", "confirm-button": "yes/no button; token bound to nothing but the task; reusable until expiry", "free-form-prompt": "approver sees the agent's own prose summary; unbound token",
        "signed-args": "'cryptographic binding alone': token signed over the tool arguments only; approver sees the arguments", "consent": "full system: manifest-derived effect display, token bound to action + effect envelope + tenant + task + agent + policy, single use, separation of duties, authority, dual control, org prohibitions",
        "consent+diff": "consent plus a 'changes since last approval' section", "consent-args-display": "full binding but the approver sees only tool arguments", "consent-prose-display": "full binding but the approver sees the agent's prose"}


def results():
    L = ["# P48 results — HorizonConsent (CANDIDATE)", "", "Generated from `results/v2/p48-consent/result.json` (write-once). %d runs = %d scenarios × %d systems. The harness is deterministic (no sampling), so intervals are Wilson over scenarios and descriptive only. The approver is a **mechanical ideal-attentive reviewer**: it objects to exactly what its display shows that contradicts the task intent, and to nothing else. This measures what a display *contains*; it is not a human study (P48-12 and P48-13 are not met)." % (R["runs"], len(R["scenarios"]), len(R["systems"])), "",
         "**Unauthorized effect** = the independent oracle, comparing the platform's effect journal to the immutable approval ledger and to the scenario's ground-truth intent with its own code, finds a committed effect that is outside intent, unapproved, or approved invalidly. The oracle always has the journal, so there is no UNKNOWN effect here; what is unknown is listed under limits.", "",
         "## Systems", "", "| system | attack runs with an unauthorized effect [95% CI] | attack runs fully blocked | benign completed | benign with violation | benign false blocks | violation kinds |", "|---|---|---|---|---|---|---|"]
    for s in R["systems"]:
        v = R["summary"][s]; L.append("| %s | %s | %s | %s | %s | %d | %s |" % (s, ci(v["attack_with_unauthorized_effect"]), ci(v["attack_blocked_all_effects"]), ci(v["benign_completed"]), ci(v["benign_with_violation"]), v["false_blocks"], ", ".join("%s×%d" % kv for kv in sorted(v["violation_kinds"].items())) or "—"))
    L += ["", "| system | what it does |", "|---|---|"] + ["| %s | %s |" % (k, DESC[k]) for k in BASE] + ["| consent-no-<flag> | full system with exactly one mechanism disabled (%s) |" % ", ".join(R["flags"])]
    L += ["", "## Per scenario", "", "Attack cells: `blocked` = no unauthorized effect; `V<kinds>` = unauthorized effect found by the oracle. Benign cells: `ok` = completed, `BLOCKED` = false block.", "", "| id | kind | " + " | ".join(R["systems"]) + " |", "|---|---|" + "---|" * len(R["systems"])]
    for sid, d in R["per_scenario"].items(): L.append("| %s | %s | %s |" % (sid, d["kind"], " | ".join(d["systems"][s] for s in R["systems"])))
    L += ["", "| id | what happens |", "|---|---|"] + ["| %s | %s |" % (s["id"], s["desc"]) for s in R["scenarios"]]
    L += ["", "## Ablations (which mechanism stops which attack)", "", "Redundant in this suite (disabling alone changes nothing because another layer also stops every attack here): **%s**. Their unit tests exercise them in isolation; they are layered defences, not dead code, but the experiment does not separate them." % ", ".join(R["redundant_flags"]), "",
          "## Display faithfulness (P48-08, structural)", "", "For every approval request in the 21 attack scenarios, the fields the display carries are compared with the true manifest (op, irreversibility, scope, classification, receivers, resource id and digest, amount). *Omitted* = a field the approver needs is absent; *misleading* = present but different from the truth.", "",
          "| display (system) | requests | mean correct fields / total | requests with an omitted field | requests with a misleading field | reviewer objected |", "|---|---|---|---|---|---|"]
    for s, d in R["display"].items(): L.append("| %s (%s) | %d | %s / %s | %d | %d | %d |" % (d["mode"], s, d["requests"], d["mean_correct_fields"], d["mean_total_fields"], d["requests_with_omitted"], d["requests_with_misleading"], d["reviewer_objected"]))
    L += ["", "Read-only comparison screen for scenario A05 (hidden mirror added; the agent's prose summary describes the clean action):", "", "```", R["compare_screen"], "```", "",
          "## What this does and does not show", "", "- Zero unauthorized effects for the full system is a property of these 21 attacks against this platform, normalizer and policy, written by one author. It is not a bound.",
          "- Binding and display are separate: tokens bind what the *platform* computed at approval time. Where the approver is shown prose or arguments (`consent-prose-display`, `consent-args-display`), a deceptive request before approval (A05, A06, A21) still yields a faithful token for the wrong effect. Only the manifest display lets the (ideal) reviewer notice.",
          "- The reviewer is an idealisation. Real approvers skim, habituate and misjudge; nothing here estimates that, and an approved effect digest establishes action identity, not that the human's decision was correct.", ""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p48/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p48 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
