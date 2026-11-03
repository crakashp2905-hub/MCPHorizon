# Real-data evaluation (AgentDojo replay) — assumptions and limits

Status: **CANDIDATE**. Author-run only; no independent replication.

## What is real
- 36,679 recorded trajectories of real LLM agents (28 pipelines: GPT-3.5/4/4o, Claude 3/3.5/3.7, Gemini, Llama, Command-R, plus defended variants) from AgentDojo (MIT, ETH SPY Lab), pinned in `bench/real/MANIFEST.json` (commit + tree sha256; verify with `scripts/real_manifest.py --root <checkout>`). Data is not vendored.
- `security == True` means the **attacker goal was achieved** (agentdojo `benchmark.py`; for DoS attacks it is `not utility`). 105 runs with infrastructure errors are excluded (the benchmark sets security=True for some of those artificially).

## What is NOT real / limits
1. **Offline replay.** A defender sees the recorded call sequence. Blocking a call would change what the model does next; we do not simulate that. "Caught" = the defender would block at least one injection-tainted effectful call, i.e. a necessary-condition proxy for stopping the attack, not a measured prevention rate.
2. **Attack labelling is heuristic.** A call is "tainted" if an argument string/identifier token comes from the injected text and was not written by the user. 723 of 5,161 successful attacks (14%) have no tainted effectful call (e.g. short ids, DoS, read-only exfil); they are excluded from `attack_caught` and counted as *misses* in `attack_caught_lower_bound`. Provenance defenders are partially aligned with this label by construction — treat their catch rate as optimistic; the **false-block rate on clean runs is independent of the label** and is the more trustworthy number for them.
3. **Mined-scope defenders are oracle-ish.** `scope_loo` and `scope_args_loo` learn what is benign from clean, utility-passing runs of the same user task by *other* models (leave-one-model-out). A deployment would not have these runs. They are upper-bound baselines, not products.
4. Effectful-tool classification is a name heuristic (`send_/create_/delete_/add_/remove_/append_/share_/post_/invite_/reschedule_/reserve_/schedule_/update_` + `get_webpage` as egress).
5. AgentDojo's suites (4) and tasks are fixed and public (possible training contamination for the models; irrelevant to rule-based defenders but relevant to generality). Four suites, 97 user tasks: generalisation to other agents/tool ecosystems is untested. InjecAgent and ASB are cloned and pinned but **not yet evaluated**.
6. This evaluates *detection-style rules on logs*, not the commit-time cryptographic authorization (P13/ledger), which has no real-agent evaluation yet.
