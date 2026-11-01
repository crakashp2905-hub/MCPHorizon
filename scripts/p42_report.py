#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); D = os.path.join(ROOT, "results/v2/p42-coverage")
R = json.load(open(os.path.join(D, "result.json"))); B = json.load(open(os.path.join(D, "bundle.json")))


def results():
    L = ["# P42 results — HorizonCoverage (CANDIDATE)", "", "Generated from `results/v2/p42-coverage/{result,bundle}.json` (write-once). Every sink is exercised with a synthetic unauthorized effect under the enforcing configuration and a deliberately weakened one (3 reps each); the state is VERIFIED only when the effect is absent under enforcement AND present under the weakened config (observer calibration). Nothing defaults to safe.", "",
         "Bundle digest `%s`, issued_at %d, TTL %d s, kernel %s." % (B["bundle_digest"][:16], B["issued_at"], B["ttl_s"], B["environment"]["kernel"]), "", "## Coverage ratios per sink family", "", "| family | sinks | VERIFIED | UNKNOWN | MISSING | verified ratio |", "|---|---|---|---|---|---|"]
    for f, v in R["ratios"].items(): L.append("| %s | %d | %d | %d | %d | %s |" % (f, v["sinks"], v["VERIFIED"], v["UNKNOWN"], v["MISSING"], v["verified_ratio"]))
    L += ["", "## Per sink", "", "| sink | family | enforcement | observation | overall | enforcement point | observation channel |", "|---|---|---|---|---|---|---|"]
    for s in B["sinks"]: L.append("| %s | %s | %s | %s | %s | %s | %s |" % (s["id"], s["family"], s["enforcement"][0], s["observation"][0], s["overall"], s["enforcement_point"], s["observation_channel"]))
    L += ["", "Notes: " + "; ".join("%s — %s" % (s["id"], s["note"]) for s in B["sinks"] if s["note"]), "", "## Protection claims (release prerequisite)", "", "| claim | supported | blocking sinks |", "|---|---|---|"]
    for k, v in R["claims"].items(): L.append("| %s | %s | %s |" % (k, v["supported"], v["blocking"] or "—"))
    L += ["", "Not claimable (no verified coverage): " + "; ".join(R["unsupported_do_not_claim"]), "", "## Blind-spot regressions", "", "| id | what | affected sinks (before→after) | real unauthorized effect | coverage | tool logging | hash-chained logging | all-safe |", "|---|---|---|---|---|---|---|---|"]
    for r in R["regressions"]: L.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (r["id"], r["what"], ", ".join("%s %s→%s" % (k, a, b) for k, (a, b) in r["affected"].items()), r["unauthorized_effect_occurred"], r["coverage_detected"], r["tool_logging_detected"], r["chain_logging_detected"], r["all_safe_detected"]))
    L += ["", "## Benchmark (loss of assurance detected)", "", "| reporter | detected | missed | false assurance while a real unauthorized effect occurred |", "|---|---|---|---|"]
    for k, v in R["benchmark"].items(): L.append("| %s | %d/%d | %d | %d of %d |" % (k, v["loss_of_assurance_detected"], v["regressions"], v["missed"], v["false_assurance_with_real_unauthorized_effect"], v["regressions_with_real_effect"]))
    hc = R["healthy_control"]; L += ["", "Healthy control (no regression): degraded sinks %s, stream %s, false alarm %s." % (hc["degraded_sinks"] or "none", hc["stream_state"], hc["false_alarm"]), "",
          "The benchmark measures whether a reporter *notices that assurance was lost* on author-defined regressions. Tool-level logging and all-safe reporting are structurally unable to see most of them (no host observation, no expiry); this is a property of what they record, not a claim they are badly built. Hash-chained logging catches the 3 log-tampering cases only.", "", "## Limits", ""] + ["* " + x for x in R["limits"]] + [""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p42/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p42 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
