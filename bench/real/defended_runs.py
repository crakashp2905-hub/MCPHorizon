"""Published defenses vs undefended, from RECORDED live runs shipped with AgentDyn (arXiv 2602.03117)
and AgentDojo.  Pipeline dir = <model>[-<defense>].  Same attack, same tasks -> paired comparison
against the undefended pipeline of the same base model.  Our replay rules are evaluated on the
undefended pipeline's runs as OFFLINE ESTIMATES (not comparable 1:1; see caveats)."""
import json, os, sys, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from bench.real import agentdojo as A

DEFENSES = ("drift", "progent", "camel", "tool_filter", "spotlighting_with_delimiting", "transformers_pi_detector",
            "piguard_detector", "prompt_guard_2_detector", "repeat_user_prompt")


def split(pipeline):
    for d in DEFENSES:
        if pipeline.endswith("-" + d):
            return pipeline[: -len(d) - 1], d
    return pipeline, "none"


def table(runs, attack="important_instructions"):
    g = collections.defaultdict(lambda: {"att": [], "clean": []})
    for r in runs:
        if r.error:
            continue
        base, d = split(r.model)
        if r.attack == attack:
            g[(base, d)]["att"].append(r)
        elif r.attack == "none":
            g[(base, d)]["clean"].append(r)
    rows = []
    for (base, d), v in sorted(g.items()):
        att, cl = v["att"], v["clean"]
        if not att:
            continue
        rows.append({"base_model": base, "defense": d,
                     "asr": A._rate(sum(1 for r in att if r.security), len(att)),
                     "utility_under_attack": A._rate(sum(1 for r in att if r.utility), len(att)),
                     "utility_clean": A._rate(sum(1 for r in cl if r.utility), len(cl)) if cl else None})
    return rows


def pooled(rows):
    """Pool over base models per defense (sum k, n) -> one line per defense."""
    acc = collections.defaultdict(lambda: [0, 0, 0, 0, 0, 0, 0])
    for r in rows:
        a = acc[r["defense"]]
        a[0] += r["asr"]["k"]; a[1] += r["asr"]["n"]; a[2] += r["utility_under_attack"]["k"]; a[3] += r["utility_under_attack"]["n"]
        if r["utility_clean"]:
            a[4] += r["utility_clean"]["k"]; a[5] += r["utility_clean"]["n"]
        a[6] += 1
    out = {}
    for d, a in acc.items():
        out[d] = {"asr": A._rate(a[0], a[1]), "utility_under_attack": A._rate(a[2], a[3]),
                  "utility_clean": A._rate(a[4], a[5]) if a[5] else None, "base_models": a[6]}
    return out


def paired(rows):
    """Macro-average over base models of (defense - undefended) for the SAME base model."""
    none = {r["base_model"]: r for r in rows if r["defense"] == "none"}
    acc = collections.defaultdict(list)
    for r in rows:
        n = none.get(r["base_model"])
        if r["defense"] == "none" or n is None:
            continue
        acc[r["defense"]].append((r["asr"]["rate"] - n["asr"]["rate"],
                                  r["utility_under_attack"]["rate"] - n["utility_under_attack"]["rate"],
                                  (r["utility_clean"]["rate"] - n["utility_clean"]["rate"]) if r["utility_clean"] and n["utility_clean"] else None))
    out = {}
    for d, v in acc.items():
        cl = [x[2] for x in v if x[2] is not None]
        out[d] = {"models": len(v), "mean_asr_delta": sum(x[0] for x in v) / len(v),
                  "mean_utility_under_attack_delta": sum(x[1] for x in v) / len(v),
                  "mean_utility_clean_delta": (sum(cl) / len(cl)) if cl else None}
    return out


def main(root, out):
    runs = list(A.iter_runs(root))
    rows = table(runs)
    res = {"per_model": rows, "pooled_by_defense": pooled(rows), "paired_vs_undefended": paired(rows), "n_runs": len(runs)}
    sc, asc = A.build_scope(runs)
    ctx = {"scope": sc, "argscope": asc}
    und = [r for r in runs if split(r.model)[1] == "none" and r.attack == "important_instructions" and not r.error]
    ours = {}
    for dn, df in A.DEFENDERS.items():
        resid = sum(1 for r in und if r.security and not any(A.call_tainted(c, r) and df(r, c, ctx) for c in r.calls if A.is_effectful(c[0])))
        clean = [r for r in runs if split(r.model)[1] == "none" and r.attack == "none" and not r.error and r.utility]
        fb = sum(1 for r in clean if any(df(r, c, ctx) for c in r.calls if A.is_effectful(c[0])))
        ours[dn] = {"residual_asr_upper_bound": A._rate(resid, len(und)), "false_block_clean": A._rate(fb, len(clean))}
    res["ours_offline_replay_on_undefended"] = ours
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    for d, v in sorted(res["pooled_by_defense"].items(), key=lambda x: x[1]["asr"]["rate"]):
        uc = v["utility_clean"]["rate"] if v["utility_clean"] else float("nan")
        print(f"{d:30s} ASR {v['asr']['rate']:.3f} [{v['asr']['ci95'][0]:.3f},{v['asr']['ci95'][1]:.3f}] n={v['asr']['n']:5d} util|atk {v['utility_under_attack']['rate']:.3f} util|clean {uc:.3f} models={v['base_models']}")
    for d, v in sorted(res["paired_vs_undefended"].items(), key=lambda x: x[1]["mean_asr_delta"]):
        print(f"PAIRED {d:30s} dASR {v['mean_asr_delta']:+.3f} dUtil|atk {v['mean_utility_under_attack_delta']:+.3f} dUtil|clean {v['mean_utility_clean_delta'] if v['mean_utility_clean_delta'] is None else round(v['mean_utility_clean_delta'],3)} models={v['models']}")
    for dn, v in ours.items():
        print(f"OURS {dn:30s} residualASR<= {v['residual_asr_upper_bound']['rate']:.3f} false-block {v['false_block_clean']['rate']:.3f}")


if __name__ == "__main__":
    main(sys.argv[sys.argv.index("--root") + 1], sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "bench/real/results/agentdyn_defended_runs.json")
