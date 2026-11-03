"""Compare observed record counts with the sizes PUBLISHED by the dataset authors.
Usage: python3 scripts/real_count_checks.py --base <dir with checkouts> [--out file]
A mismatch is reported, never hidden.  Expected values come from the papers/READMEs named in `src`."""
import csv, glob, json, os, sys

def jl(p): return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
def csvn(p): return sum(1 for _ in csv.reader(open(p, encoding="utf-8", newline=""))) - 1

CHECKS = []
def check(id_, claim, src, expected, fn): CHECKS.append((id_, claim, src, expected, fn))

check("injecagent", "base test cases (dh+ds)", "InjecAgent README: 1,054 test cases (verified in README)", 1054,
      lambda b: len(json.load(open(f"{b}/InjecAgent/data/test_cases_dh_base.json"))) + len(json.load(open(f"{b}/InjecAgent/data/test_cases_ds_base.json"))))
check("do_not_answer", "English prompts", "Do-Not-Answer README: 939 (verified in README)", 939, lambda b: csvn(f"{b}/do-not-answer/datasets/data_en.csv"))
check("advbench", "harmful behaviors", "Zou et al. 2023: 520 [expected value NOT re-verified against a source in this session]", 520, lambda b: csvn(f"{b}/llm-attacks/data/advbench/harmful_behaviors.csv"))
check("agent_safetybench", "cases", "Agent-SafetyBench abstract (arXiv 2412.14470): 2,000 test cases, 349 environments (verified)", 2000, lambda b: len(json.load(open(f"{b}/agent-safetybench/data/released_data.json"))))
check("asb", "total tools (attack+normal) >= 400, reported as 400", "ASB abstract (arXiv 2410.02644): 'over 400 tools' (verified; split not stated)", 400,
      lambda b: min(400, len(jl(f"{b}/ASB/data/all_attack_tools.jsonl")) + len(jl(f"{b}/ASB/data/all_normal_tools.jsonl"))))
def _agentdyn(b):
    root = f"{b}/AgentDyn/runs/gpt-4o-2024-08-06"
    pairs = set(); users = set()
    for p in glob.glob(root + "/*/user_task_*/important_instructions/injection_task_*.json"):
        s, u, _, i = os.path.relpath(p, root).split(os.sep); pairs.add((s, u, i[:-5])); users.add((s, u))
    return len(pairs)
check("agentdyn", "user-task x injection-task pairs", "AgentDyn README/abstract: 560 injection test cases (verified)", 560, _agentdyn)
check("agentdyn", "user tasks", "AgentDyn README/abstract: 60 tasks (verified)", 60,
      lambda b: len({tuple(os.path.relpath(p, f"{b}/AgentDyn/runs/gpt-4o-2024-08-06").split(os.sep)[:2]) for p in glob.glob(f"{b}/AgentDyn/runs/gpt-4o-2024-08-06/*/user_task_*/none/none.json")}))
check("mcpsecbench", "prompt-based attack entries in data.json", "MCPSecBench README: automatic script for 11 attacks (of 17)", 11, lambda b: len(json.load(open(f"{b}/mcpsecbench/data/data.json"))))

def main():
    base = sys.argv[sys.argv.index("--base") + 1]
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "bench/real/results/count_checks.json"
    res, bad = [], 0
    for id_, claim, src, exp, fn in CHECKS:
        try: obs = fn(base)
        except Exception as e: obs = f"ERROR {type(e).__name__}: {e}"
        ok = obs == exp; bad += (not ok)
        res.append({"id": id_, "claim": claim, "source": src, "expected": exp, "observed": obs, "match": ok}); print(("OK  " if ok else "DIFF"), id_, claim, exp, obs)
    os.makedirs(os.path.dirname(out), exist_ok=True); json.dump(res, open(out, "w"), indent=1)
    sys.exit(1 if bad else 0)
if __name__ == "__main__": main()
