"""Compare published defenses (recorded AgentDojo runs, same model gpt-4o-2024-05-13,
same attack `important_instructions`) with our replay rules on the undefended slice.
Published-defense numbers are MEASURED LIVE by AgentDojo authors' pipelines (recorded runs);
ours are OFFLINE REPLAY ESTIMATES -> not directly comparable; shown side by side with caveats."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from bench.real import agentdojo as A

BASE = "gpt-4o-2024-05-13"
ATTACK = "important_instructions"
PUBLISHED = {BASE: "none (undefended)", BASE + "-tool_filter": "tool_filter (Debenedetti et al. 2024, AgentDojo)",
             BASE + "-spotlighting_with_delimiting": "spotlighting w/ delimiting (Hines et al. 2024)",
             BASE + "-transformers_pi_detector": "PI detector, DeBERTa (ProtectAI)",
             BASE + "-repeat_user_prompt": "prompt sandwiching (repeat user prompt)"}


def live_rows(runs):
    rows = {}
    for m, label in PUBLISHED.items():
        att = [r for r in runs if r.model == m and r.attack == ATTACK and not r.error]
        clean = [r for r in runs if r.model == m and r.attack == "none" and not r.error]
        asr = sum(1 for r in att if r.security)
        ua = sum(1 for r in att if r.utility)
        uc = sum(1 for r in clean if r.utility)
        rows[label] = {"model": m, "asr": A._rate(asr, len(att)), "utility_under_attack": A._rate(ua, len(att)),
                       "utility_clean": A._rate(uc, len(clean))}
    return rows


def replay_rows(runs):
    """Our rules on the UNDEFENDED gpt-4o slice. residual_asr counts every successful attack the rule
    does not provably block as still succeeding (unlabelled successes count as not blocked)."""
    sc, asc = A.build_scope(runs)
    ctx = {"scope": sc, "argscope": asc}
    att = [r for r in runs if r.model == BASE and r.attack == ATTACK and not r.error]
    clean = [r for r in runs if r.model == BASE and r.attack == "none" and not r.error]
    out = {}
    for dn, df in A.DEFENDERS.items():
        resid = 0
        for r in att:
            if not r.security:
                continue
            eff = [c for c in r.calls if A.is_effectful(c[0])]
            if not any(A.call_tainted(c, r) and df(r, c, ctx) for c in eff):
                resid += 1
        fb = sum(1 for r in clean if r.utility and any(df(r, c, ctx) for c in r.calls))
        cu = sum(1 for r in clean if r.utility)
        out[dn] = {"residual_asr_upper_bound": A._rate(resid, len(att)),
                   "clean_utility_if_blocked_calls_fail": A._rate(cu - fb, len(clean)), "false_block": A._rate(fb, cu)}
    return out


def main(root, out):
    runs = list(A.iter_runs(root))
    res = {"live_published_defenses": live_rows(runs), "offline_replay_ours": replay_rows(runs),
           "reported_by_authors_not_reproduced": {
               "CaMeL (arXiv 2503.18813)": "77% tasks with provable security vs 84% undefended (AgentDojo)",
               "AuthGraph (arXiv 2605.26497)": "AgentDojo GPT-4o ASR 40%->1%, 76% task completion (author-reported)",
               "AgentCap (arXiv 2611.00729)": "0% ASR with GPT-5.4 on AgentDojo and InjecAgent (author-reported)",
               "Progent (arXiv 2504.11703)": "numbers not retrieved; do not cite a figure"}}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    for k, v in res["live_published_defenses"].items():
        print(f"{k:55s} ASR {v['asr']['rate']:.3f} [{v['asr']['ci95'][0]:.3f},{v['asr']['ci95'][1]:.3f}] n={v['asr']['n']} util(atk) {v['utility_under_attack']['rate']:.3f} util(clean) {v['utility_clean']['rate']:.3f}")
    for k, v in res["offline_replay_ours"].items():
        print(f"{k:55s} residualASR<= {v['residual_asr_upper_bound']['rate']:.3f} false-block {v['false_block']['rate']:.3f}")


if __name__ == "__main__":
    main(sys.argv[sys.argv.index("--root") + 1], "bench/real/results/defense_comparison.json")
