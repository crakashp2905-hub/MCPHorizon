#!/usr/bin/env python3
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); R = json.load(open(os.path.join(ROOT, "results/v2/p43-mutation/result.json")))
ci = lambda c: "%.3f [%.3f, %.3f]" % (c["rate"], c["ci"][0], c["ci"][1]) if c and c.get("n") else "—"
pct = lambda x: "—" if x is None else "%.3f" % x


def results():
    g = R["generation"]; L = ["# P43 results — HorizonMutation (CANDIDATE)", "", "Generated from `results/v2/p43-mutation/result.json` (write-once). Ground truth V comes from a two-way oracle: bytes really sent to loopback receivers (journal written by a separate process) and a labeled-lineage computation; disagreement or an unobserved send is UNKNOWN and never scored. Authority is the declared graph rule (see taxonomy doc).", "",
         "Seed 43. %d seed graphs (6 root causal families × attack/benign twin); %d depth-1 + %d depth-2 mutants; %d candidates rejected by preconditions; %d real sends, %d answered from the memo of an earlier identical real send. Oracle status over all mutants: %s. UNKNOWN reasons: %s." % (g["seeds"], g["depth1"], g["depth2"], g["rejected_by_preconditions"], g["oracle_runs"], g["oracle_cache_hits"], g["status"], g["unknown_reasons"]), "",
         "## Generators compared (P43-13/14)", "", "| generator | generated | oracle OK | confirmed violating | diversity (distinct effect paths / OK) | unique failure modes found in D1,D2,D2b,D3 | invalid rate | UNKNOWN rate | semantic-preservation error | preservation accuracy | flip accuracy |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for k, v in R["generators"].items():
        if "generated" not in v: L.append("| %s | — | — | — | — | — | — | — | — | — | — |" % k); continue
        r = v["relation"]; L.append("| %s | %d | %d | %d | %s | %d | %s | %s | %s | %s | %s |" % (k, v["generated"], v["oracle_ok"], v["oracle_confirmed_violating"], pct(v["diversity"]), v["unique_failure_modes"], ci(r["invalid_rate"]) if k != "fixed_handcrafted" else "—", ci(r["unknown_rate"]) if k != "fixed_handcrafted" else "—", ci(r["semantic_preservation_error_rate"]), ci(r["violation_preservation_accuracy"]), ci(r["violation_flip_accuracy"])))
    L += ["", "* `fixed_handcrafted`: the 12 seeds. `lexical_perturbation`: payload-text prefixes only. `unconstrained_scripted_random`: a random graph editor with no preconditions — a **scripted stand-in, not an LLM**; %s." % R["generators"]["llm_generator"]["status"],
          "* Predicted relation is a syntax heuristic; \"preservation accuracy\" = of mutants predicted SAME, the share where the oracle's V is equal; \"flip accuracy\" = of predicted CHANGE, the share where it differs; \"semantic-preservation error\" = predicted SAME but V changed.", "", "### Per operator (constrained generator, after dedup; predicted→observed)", "", "| operator | counts |", "|---|---|"]
    for k, v in R["generators"]["horizon_mutation_constrained"]["relation"]["per_operator"].items(): L.append("| %s | %s |" % (k, ", ".join("%s: %d" % kv for kv in sorted(v.items()))))
    d = R["dedup"]; L += ["", "## Dedup (P43-10)", "", "%d mutants in; %d exact duplicates by semantic effect path (dest, transform chain, approval class at execution and at decision, authority tier); %d near duplicates (Jaccard ≥ %.1f on graph features, same family and same V); %d kept." % (d["input"], d["exact_duplicates"], d["near_duplicates"], d["dedup_similarity_threshold"], d["kept"]), "",
          "## Policies under test (kept, oracle-OK mutants)", "", "| policy | recall on confirmed violations | benign disruption (false block) | median decision µs |", "|---|---|---|---|"]
    for n, v in R["detectors"].items(): L.append("| %s | %d/%d = %s | %d/%d = %s | %s |" % (n, v["tp"], v["tp"] + v["fn"], ci(v["recall"]), v["fp"], v["fp"] + v["tn"], ci(v["benign_disruption"]), R["detector_latency_us_median"][n]))
    L += ["", "On the 12 fixed seeds alone: " + "; ".join("%s recall %s, disruption %s" % (n, pct(v["recall"]["rate"]), pct(v["benign_disruption"]["rate"])) for n, v in R["detectors_on_seeds_only"].items()) + ".", "",
          "### Ablation (overlapping evidence)", "", "| configuration | recall | benign disruption |", "|---|---|---|"] + ["| %s | %s | %s |" % (n, ci(v["recall"]), ci(v["benign_disruption"])) for n, v in R["ablation"].items()]
    L += ["", "### Unique failure modes (policy, error, last operator, family)", ""] + ["* " + " / ".join(x) for x in R["failure_modes"]]
    sp = R["split"]; sr = R["split_raw_not_deduplicated"]; row = lambda n, s: "| %s | %d | %s | %s | %s |" % (n, s["learned_signatures"], ci(s["on_train_side"]["recall"]), ci(s["on_held_out"]["recall"]), ci(s["on_held_out"]["benign_disruption"]))
    L += ["", "## Family split vs random split (P43-11), policy D4 learns violating sink signatures", "", "Dev families %s; test families %s; family overlap between sides: %s." % (sp["dev_families"], sp["test_families"], sp["family_overlap"] or "none"), "", "| split | signatures learned | recall on dev side | recall held out | false-block held out |", "|---|---|---|---|---|",
          row("family split, deduplicated", sp["family_split"]), row("random split, deduplicated", sp["random_split"]), row("family split, raw (near-duplicates kept)", sr["family_split"]), row("random split, raw (near-duplicates kept)", sr["random_split"]), "",
          "Held-out sets are small (see n in the rates); the raw random split shows leakage from near-duplicate mutants of the same seed, which the family split removes.", "", "## Matched attack/benign pairs (P43-12)", "",
          "%d oracle-confirmed pairs (attack V=true, twin V=false, identical tool-name multiset); edits used: %s." % (R["pairs"]["n"], R["pairs"]["edits"]), "", "| policy | pairs where attack blocked AND twin allowed |", "|---|---|"] + ["| %s | %s |" % (n, ci(v)) for n, v in R["pairs"]["paired_correct"].items()]
    L += ["", "## Regression minimizer (P43-15)", "", "| failing case | nodes original | nodes padded | nodes minimal | evaluations | oracle V unchanged | policy still misses | 1-minimal |", "|---|---|---|---|---|---|---|---|"] + ["| %s | %d | %d | %d | %d | %s | %s | %s |" % (m["id"], m["nodes_original"], m["nodes_before"], m["nodes_after"], m["evaluations"], m["oracle_V_unchanged"], m["d2_still_misses"], m["one_minimal"]) for m in R["minimizer"]]
    L += ["", "## Limits", ""] + ["* " + x for x in R["limits"]] + [""]
    return "\n".join(L)


p = os.path.join(ROOT, "docs/evidence/p43/RESULTS.md"); t = results()
if "--check" in sys.argv:
    ok = os.path.exists(p) and open(p).read() == t; print("p43 docs current" if ok else "stale: " + p); sys.exit(0 if ok else 1)
open(p, "w").write(t); print("written")
