"""The P43 experiment: one deterministic function used by the runner and the tests. All verdicts come from the oracle (real loopback bytes + lineage) or from detectors that never see the oracle."""
from __future__ import annotations
import statistics, time
from collections import Counter, defaultdict
from ..emergence.experiment import wilson
from . import ir, pipeline as PL, detectors as DT, seeds as SD, operators as OP, minimize as MZ
from .oracle import Oracle


def rate(k, n): return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci": wilson(k, n) if n else None}


def relation_stats(items, V_of_parent):
    """predicted (generator intent) vs observed (oracle) relation per step."""
    c = Counter(); per_op = defaultdict(Counter)
    for m in items:
        st = m["provenance"][-1]; pred = st["predicted"]; opn = st.get("operator", "?"); pv = V_of_parent(m); cv = m["oracle"]
        if cv["status"] == "INVALID": c["invalid"] += 1; per_op[opn]["invalid"] += 1; continue
        if cv["status"] == "UNKNOWN" or pv is None: c["unknown"] += 1; per_op[opn]["unknown"] += 1; continue
        obs = "SAME" if cv["V"] == pv else "CHANGE"
        if pred == "UNKNOWN": c["pred_unknown"] += 1; per_op[opn]["pred_unknown"] += 1; continue
        key = "%s->%s" % (pred, obs); c[key] += 1; per_op[opn][key] += 1
    same = c["SAME->SAME"] + c["SAME->CHANGE"]; chg = c["CHANGE->CHANGE"] + c["CHANGE->SAME"]
    return {"counts": dict(c), "violation_preservation_accuracy": rate(c["SAME->SAME"], same), "violation_flip_accuracy": rate(c["CHANGE->CHANGE"], chg), "semantic_preservation_error_rate": rate(c["SAME->CHANGE"], same), "total": len(items),
            "invalid_rate": rate(c["invalid"], len(items)), "unknown_rate": rate(c["unknown"], len(items)), "per_operator": {k: dict(v) for k, v in sorted(per_op.items())}}


def verdicts(items, dets):
    out = []
    for m in items:
        if m["oracle"]["status"] != "OK": continue
        row = {"id": m["id"], "family": m["family"], "V": m["oracle"]["V"], "last_op": (m["provenance"][-1].get("operator") if m["provenance"] else "SEED"), "kinds": tuple(p.get("kind") for p in m["provenance"])}
        for name, f in dets.items(): row[name] = f(m["graph"])
        out.append(row)
    return out


def confusion(rows, name):
    tp = sum(1 for r in rows if r["V"] and r[name] == "BLOCK"); fn = sum(1 for r in rows if r["V"] and r[name] == "ALLOW"); fp = sum(1 for r in rows if not r["V"] and r[name] == "BLOCK"); tn = sum(1 for r in rows if not r["V"] and r[name] == "ALLOW")
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": rate(tp, tp + fn), "benign_disruption": rate(fp, fp + tn)}


def failure_modes(rows, name):
    modes = set()
    for r in rows:
        if r["V"] and r[name] == "ALLOW": modes.add((name, "MISSED_VIOLATION", r["last_op"], r["family"]))
        if not r["V"] and r[name] == "BLOCK": modes.add((name, "FALSE_BLOCK", r["last_op"], r["family"]))
    return modes


def gen_report(label, items, parent_V, dets):
    ok = [m for m in items if m["oracle"]["status"] == "OK"]; rows = verdicts(items, dets); sigs = {PL.effect_signature(m) for m in ok}
    modes = set()
    for n in dets: modes |= failure_modes(rows, n)
    viol = [m for m in ok if m["oracle"]["V"]]
    return {"generator": label, "generated": len(items), "oracle_ok": len(ok), "oracle_confirmed_violating": len(viol), "families_with_confirmed_violation": sorted({m["family"] for m in viol}), "distinct_effect_paths": len(sigs), "diversity": round(len(sigs) / len(ok), 4) if ok else None,
            "unique_failure_modes": len(modes), "relation": relation_stats(items, parent_V)}


def run(rng_seed=43, depth2=160, minimize_cases=6) -> dict:
    t0 = time.time(); G = PL.generate(rng_seed, depth2); dets = dict(DT.STATIC); res = {"seed": rng_seed}
    with Oracle() as o:
        roots = {r["id"]: r for r in G["roots"]}; PL.label(o, list(roots.values())); mut = PL.label(o, G["mutants"]); byid = {m["id"]: m for m in mut}
        def parent_V(m):
            p = roots.get(m["parent"]) if m["parent"] in roots else byid.get(m["parent"]) if m.get("parent") else roots.get(m["root"])
            return p["oracle"]["V"] if p and p["oracle"]["status"] == "OK" else None
        def root_V(m): r = roots[m["root"]]; return r["oracle"]["V"] if r["oracle"]["status"] == "OK" else None
        # ---- constrained pipeline, dedup ----
        dd = PL.dedup(mut); kept = dd["kept"]; res["dedup"] = {"input": dd["input"], "kept": len(kept), "exact_duplicates": dd["exact_duplicates"], "near_duplicates": dd["near_duplicates"], "dedup_similarity_threshold": 0.9}
        res["generation"] = {"seeds": len(roots), "depth1": G["depth1"], "depth2": G["depth2"], "rejected_by_preconditions": len(G["rejected_by_preconditions"]), "oracle_runs": o.runs, "oracle_cache_hits": o.hits,
                             "status": dict(Counter(m["oracle"]["status"] for m in mut)), "unknown_reasons": dict(Counter(re_.split(":", 1)[1].split(" ")[1] if False else ("partial-sanitizer" if "partially" in re_ else "lineage-vs-bytes") for m in mut for re_ in m["oracle"]["reasons"]))}
        # ---- baselines ----
        fixed = [dict(r, provenance=[{"operator": "FIXED", "predicted": "SAME", "kind": "fixed"}], parent=None) for r in roots.values()]
        lex = PL.label(o, PL.lexical_baseline(rng_seed)); rnd = PL.label(o, PL.random_baseline(rng_seed))
        res["generators"] = {"fixed_handcrafted": gen_report("fixed_handcrafted", fixed, lambda m: None, dets), "lexical_perturbation": gen_report("lexical_perturbation", lex, root_V, dets), "unconstrained_scripted_random_NOT_AN_LLM": gen_report("unconstrained_random", rnd, root_V, dets),
                             "horizon_mutation_constrained": gen_report("horizon_mutation", kept, parent_V, dets), "horizon_mutation_before_dedup": gen_report("horizon_mutation_raw", mut, parent_V, dets),
                             "llm_generator": {"status": "NOT RUN: no live model in this environment; no number is reported"}}
        res["relation_all_constrained"] = relation_stats(mut, parent_V)
        # ---- detectors ----
        rows = verdicts(kept, dets); res["detectors"] = {n: confusion(rows, n) for n in dets}
        res["detectors_by_family"] = {f: {n: confusion([r for r in rows if r["family"] == f], n) for n in dets} for f in SD.FAMILIES}
        res["detectors_on_seeds_only"] = {n: confusion(verdicts(fixed, dets), n) for n in dets}
        either = lambda g: "BLOCK" if "BLOCK" in (DT.d2(g), DT.d3(g)) else "ALLOW"
        ab = {"D2-lineage-v1": dets["D2-lineage-v1"], "D2b-lineage-v2": dets["D2b-lineage-v2"], "D3-restrictive": dets["D3-restrictive"], "D2+D3 (overlapping evidence)": either}
        res["ablation"] = {n: confusion(verdicts(kept, ab), n) for n in ab}
        lat = {}
        for n, f in dets.items():
            ts = []
            for m in kept[:200]: a = time.perf_counter(); f(m["graph"]); ts.append((time.perf_counter() - a) * 1e6)
            lat[n] = round(statistics.median(ts), 1)
        res["detector_latency_us_median"] = lat
        modes = set()
        for n in dets: modes |= failure_modes(rows, n)
        res["failure_modes"] = sorted([list(x) for x in modes]); res["failure_modes_by_detector"] = dict(Counter(x[0] for x in modes))
        # ---- splits (D4) ----
        def d4_eval(split):
            fit = [(m["graph"], {s["sink"] for s in m["oracle"]["sinks"] if s["violation"]}) for m in split["dev"] if m["oracle"]["status"] == "OK"]; d4 = DT.D4().fit(fit)
            r_dev = verdicts([m for m in split["dev"]], {"D4": d4}); r_test = verdicts(split["test"], {"D4": d4})
            return {"train_n": len(fit), "learned_signatures": len(d4.bad), "on_train_side": confusion(r_dev, "D4"), "on_held_out": confusion(r_test, "D4")}
        fam = PL.split_by_family(kept); rnd_split = PL.split_random(kept, rng_seed)
        fam_raw = PL.split_by_family(mut); rnd_raw = PL.split_random(mut, rng_seed)
        res["split_raw_not_deduplicated"] = {"family_split": d4_eval(fam_raw), "random_split": d4_eval(rnd_raw)}
        res["split"] = {"family_split": d4_eval(fam), "random_split": d4_eval(rnd_split), "dev_families": list(SD.DEV_FAMILIES), "test_families": list(SD.TEST_FAMILIES),
                        "family_overlap": sorted({m["family"] for m in fam["dev"]} & {m["family"] for m in fam["test"]}), "d2_on_test_families": confusion(verdicts(fam["test"], dets), "D2-lineage-v1"), "d2b_on_test_families": confusion(verdicts(fam["test"], dets), "D2b-lineage-v2")}
        # ---- matched pairs ----
        pairs = PL.matched_pairs(o, kept); pr = []
        for p in pairs:
            m = byid.get(p["attack"]) or next(x for x in kept if x["id"] == p["attack"]); pr.append({n: (f(m["graph"]) == "BLOCK" and f(p["benign_graph"]) == "ALLOW") for n, f in dets.items()})
        res["pairs"] = {"n": len(pairs), "tool_names_identical": all(PL.tool_multiset(p["benign_graph"]) == p["tools"] for p in pairs), "paired_correct": {n: rate(sum(1 for r in pr if r[n]), len(pr)) for n in dets}, "edits": dict(Counter(p["edit"]["operator"] for p in pairs))}
        # ---- minimizer ----
        cases = [m for m in kept if m["oracle"]["status"] == "OK" and m["oracle"]["V"] and DT.d2(m["graph"]) == "ALLOW"][:minimize_cases]; mz = []
        for m in cases:
            pred = lambda g: (not ir.feasibility(g)) and (lambda j: j["status"] == "OK" and j["V"] is True)(o.judge(g)) and DT.d2(g) == "ALLOW"
            padded = MZ.pad(m["graph"]); assert not ir.feasibility(padded) and pred(padded)
            g2, ev = MZ.minimize(padded, pred); mz.append({"id": m["id"], "nodes_original": len(m["graph"]["nodes"]), "nodes_before": len(padded["nodes"]), "nodes_after": len(g2["nodes"]), "evaluations": ev, "oracle_V_unchanged": o.judge(g2)["V"] is True, "d2_still_misses": DT.d2(g2) == "ALLOW", "one_minimal": MZ.is_one_minimal(g2, pred), "minimal_graph_digest": ir.digest(g2)[:16]})
        res["minimizer"] = mz
        res["oracle_total_runs"] = o.runs
    res["wall_s"] = round(time.time() - t0, 1)
    res["limits"] = ["seeds, operators, detectors and the authorization rule are all written by the same author; failure modes found are those of author-written detectors, not of any third-party policy engine",
                     "oracle effect is observed (loopback receiver process) but authority is DECLARED in the graph; a wrong declared rule is a wrong ground truth",
                     "the byte oracle knows single derived forms (raw, reverse, hex, rot13, b64 middle); stacked transforms and partial sanitizers make bytes and lineage disagree and are labelled UNKNOWN, not scored",
                     "operator predictions are syntax heuristics; semantic-preservation error rate is the measured disagreement with the oracle, and is nonzero by construction for the low-confidence operators",
                     "the unconstrained baseline is a scripted random editor, not a language model; no LLM generator was run and none is claimed",
                     "family split uses 4 dev and 2 test families; drops are measured on a tiny number of families",
                     "detector latency is a single-process microbenchmark of Python functions on a toy graph, not a production policy engine",
                     "the shared loopback receiver journals at end-of-headers; a POST written in two segments lost its body about 1 in 2000 sends. P43 writes each request in one segment (0 in 6000 afterwards). Earlier phases that sent POSTs with urllib are exposed to the same rare race; their frozen results are not re-run",
                     "12 seeds across 6 families: coverage claims apply to these causal families only"]
    return res
