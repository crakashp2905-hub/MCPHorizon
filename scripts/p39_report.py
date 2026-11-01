#!/usr/bin/env python3
"""Generates docs/evidence/p39/RESULTS.md and docs/papers/PAPER_EMERGENCE.md from the write-once results. `--check` fails if the files are stale."""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = json.load(open(os.path.join(ROOT, "results/v2/p39-emergence/result.json")))
f = lambda x: "—" if x is None else ("%.3f" % x if isinstance(x, float) else str(x))
ci = lambda c: "[%s, %s]" % (f(c[0]), f(c[1]))


def results():
    L = ["# P39 results — HorizonEmergence (CANDIDATE, synthetic, loopback only)", "", "Generated from `results/v2/p39-emergence/result.json` (write-once). Outcomes come from the receiver journal (separate process); model predictions are never used as labels.", "",
         "## Labeled corpus", "", "%d minimal source→transform*→sink chains; **%d leak** to the unapproved endpoint B per the journal; %d are *oracle-blind* (nested encodings the receiver cannot recognise) and are not scored." % (R["corpus"]["chains"], R["corpus"]["leaks"], R["corpus"]["oracle_blind"]), "",
         "## Detectors on the same chains (P39-13)", "", "| detector | TP | FP | FN | TN | UNKNOWN (leaked) | recall [95% CI] | FPR [95% CI] |", "|---|---|---|---|---|---|---|---|"]
    for k, v in R["baselines"].items(): L.append("| %s | %d | %d | %d | %d | %d (%d) | %s %s | %s %s |" % (k, v["tp"], v["fp"], v["fn"], v["tn"], v["unknown"], v["unknown_that_leaked"], f(v["recall"]), ci(v["recall_ci"]), f(v["fpr"]), ci(v["fpr_ci"])))
    e = R["baselines"]["emergence"]; L += ["", "Strict reading: counting UNKNOWN as *not detected*, emergence catches %d of %d leaking chains (the other %d sit behind unmodeled endpoint C)." % (e["tp"], e["tp"] + e["fn"] + e["unknown_that_leaked"], e["unknown_that_leaked"])]
    L += ["", "UNKNOWN is reported separately and is neither an alert nor a pass. Only 4 chains leak, so recall intervals are wide: **the corpus cannot distinguish recall differences among detectors that catch all modeled leaks.** The `emergence` false positives are all `weak_sanitize` chains the model conservatively treats as taint-preserving; `emergence_refined` applies one oracle-derived refinement (evidence = one disproved chain) and is evaluated on the other chains, but the refinement is scoped to the oracle's variant set — weak_sanitize still leaks a *partial* string.", ""]
    D = R["discovery"]; L += ["## Discovery recall and verified-candidate precision vs search budget (P39-14)", "", "%d seeded worlds (random op/target subsets), %d positive. Unguided = mean over 5 seeds (a world counts as found if ≥ half the seeds found it). Budget = evaluated (state, action) transitions." % (D["worlds"], D["positive_worlds"]), ""]
    for mode, pts in D["curves"].items():
        L += ["### %s" % mode, "", "| budget | recall (found/positive) [95% CI] | verified | disproved | verified precision [95% CI] |", "|---|---|---|---|---|"]
        for p in pts: L.append("| %d | %s (%d/%d) %s | %d | %d | %s %s |" % (p["budget"], f(p["recall"]), p["recall_worlds"][0], p["recall_worlds"][1], ci(p["recall_ci"]), p["verified_candidates"], p["disproved_candidates"], f(p["verified_precision"]), ci(p["verified_precision_ci"])))
        L.append("")
    L += ["## Unknown and unmodeled capability (P39-15)", "", "Positive worlds whose only leak path goes through endpoint C, whose delegation the analyst did not model: **%s**. The search reports C paths as UNKNOWN (%d unknown chains in the corpus run), never as safe and never as verified. Scope assumption: endpoints A and B are modeled exactly; C is unmodeled; the real receiver redirects on every port, which only the oracle sees." % (", ".join(D["positive_worlds_only_via_unmodeled_C"]) or "none", R["baselines"]["emergence"]["unknown"]), ""]
    W = R["witness"]; L += ["## Witness (P39-16)", "", "Candidate `%s` was discovered by the search and verified by the journal (leak to B: **%s**). Matched safe control: same endpoint and shape with `hash` in place of `b64` — leak to B: **%s** (B still received a connection: %d)." % (" → ".join(s["op"] + (":" + s["target"] if s["target"] else "") for s in W["candidate"]["steps"]), W["oracle"]["leak_to_B"], W["control_same_endpoint_with_hash"]["oracle"]["leak_to_B"], W["control_same_endpoint_with_hash"]["oracle"]["per_endpoint"]["B"]["conns"]), "",
          "## Limits", ""] + ["* " + x for x in R["limits"]] + [""]
    return "\n".join(L)


def paper():
    W = R["witness"]; b = R["baselines"]; return """# Paper artifact — Effect-aware discovery of unsafe composition from individually allowed calls (CANDIDATE)

*Falsifiable claims, scoped assumptions and a verified witness. Synthetic loopback only; not a security guarantee.*

## Claim C1 (witness)
Under a direct-call policy that allows every call below, the sequence `read_secret → b64 → get(partner /redir?to=<third party>)` delivers the canary to a third party. Verified by the receiver journal: leak = **%s**. The matched control (`hash` instead of `b64`, same endpoint) leaks = **%s**. Tool-name co-occurrence cannot separate the two (D3 alerts on both).

## Claim C2 (scoped bounded completeness)
**Assumptions.** (A1) Each transform summary over-approximates taint (unknown transforms preserve taint). (A2) The delegation table of every *modeled* endpoint is complete. (A3) Chains have at most 4 steps and 4 live values. (A4) The sink policy is "tainted data may only reach secure sinks".
**Statement.** With unbounded search budget, every chain within A3 that violates A4 through modeled endpoints is enumerated as a candidate. Chains touching an unmodeled endpoint are reported UNKNOWN.
**Falsifier.** An oracle-confirmed leak through modeled endpoints within A3 that is not a candidate. `tests.p39.test_emergence.Completeness` checks this on the labeled corpus: none found (corpus has only %d leaking chains, so this is weak evidence).

## Claim C3 (what it does not claim)
No claim of general recall on real MCP deployments; no claim about covert channels, timing, partial-content leaks (the oracle cannot see them), or nested encodings (unscored).

## Measured
D0 recall %s; D3 recall %s at FPR %s; emergence FPR %s before and %s after one evidence-scoped refinement; %d leaking chains behind UNKNOWN. See `docs/evidence/p39/RESULTS.md`.
""" % (W["oracle"]["leak_to_B"], W["control_same_endpoint_with_hash"]["oracle"]["leak_to_B"], R["corpus"]["leaks"], f(b["D0"]["recall"]), f(b["D3"]["recall"]), f(b["D3"]["fpr"]), f(b["emergence"]["fpr"]), f(b["emergence_refined"]["fpr"]), b["emergence"]["unknown_that_leaked"])


def main():
    outs = {os.path.join(ROOT, "docs/evidence/p39/RESULTS.md"): results(), os.path.join(ROOT, "docs/papers/PAPER_EMERGENCE.md"): paper()}
    if "--check" in sys.argv:
        bad = [p for p, t in outs.items() if not os.path.exists(p) or open(p).read() != t]; print("stale: " + ", ".join(bad) if bad else "p39 docs current"); sys.exit(1 if bad else 0)
    for p, t in outs.items(): open(p, "w").write(t)
    print("written")


main()
