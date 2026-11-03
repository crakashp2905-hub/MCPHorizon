# Dataset collection and validation (2026-11-04) — CANDIDATE

24 datasets/repos registered in `bench/real/REGISTRY.json`, each pinned by git commit (shallow clones; data NOT vendored). `bench/real/datasets.py` produced `bench/real/results/dataset_validation.json` (commit, origin URL, license, tree sha256, parse results, record/duplicate counts, credential-like strings, LFS stubs). `scripts/real_count_checks.py` compares counts to published sizes (`results/count_checks.json`).

**What "validated" means:** provenance + integrity + parseability + hygiene + published-size consistency. It does **not** mean third-party labels are correct, and it does not mean a dataset has been *used* in an evaluation (see "Used in evaluation").

## Result summary
- 22 of 24 contain parseable data. `camel` (code only) and `pyrit` (no bundled seed data at the pinned commit) contribute no data and are excluded from the "≥20 datasets" count.
- Defects found by validation: `ASB/data/agent_task_pot_all.jsonl` is an **HTML page**, not JSONL (42 bad lines; the upstream file is corrupt); garak's `tsconfig*.json` are tooling files (now excluded by rule).
- License findings: `R-Judge` and `tensor-trust-data` ship **no license file** (all rights reserved by default — do not redistribute; research use at own risk); `WASP` is **CC-BY-NC** (non-commercial); `PurpleLlama` data is under the **Llama community license** (custom restrictions). Everything else MIT/Apache-2.0.
- Published-size checks: InjecAgent 1,054 ✓, Do-Not-Answer 939 ✓, AgentDyn 60 tasks / 560 injection cases ✓, MCPSecBench 11 scripted prompt attacks ✓; AdvBench 520, Agent-SafetyBench 2,000, ASB 400 attack tools match our *recollection* of the papers but were **not re-verified against a source** (flagged in the script).
- Duplicates are reported, not removed (e.g. Do-Not-Answer's 78k records include many repeated model-response rows; `records` there is not the prompt count).
- MCPSecBench ships only 11 prompt entries as data (plus an experiments CSV): it is small; MCPTox and MCP-SafetyBench have **no public code/data link** in the pages fetched, so they could not be collected.

## Used in evaluation (honest)
| Dataset | Role | Evaluated against our rules? |
|---|---|---|
| AgentDojo (36.7k recorded runs) | main replay benchmark | **Yes** (`agentdojo_results.json`) |
| AgentDyn (47.7k recorded runs, 9 published defenses incl. Progent/DRIFT/CaMeL) | defended-run comparison, open-ended tasks | **Yes** (`agentdyn_defended_runs.json`) |
| InjecAgent, ASB, MCPSecBench, WASP, Agent-SafetyBench, ToolEmu, R-Judge, SABER, tau-bench, AgentPoison | tool-call / agent-safety cases | **No** — pinned and validated only; schemas differ (no recorded agent trajectory) |
| BIPIA, Tensor Trust, Open-Prompt-Injection, JailbreakBench, HarmBench, AdvBench, in-the-wild jailbreaks, Do-Not-Answer, garak, PurpleLlama | text-level injection/jailbreak | **No** — text-level, outside tool-call scope; kept for diversity and for future model-in-the-loop work |

## Not done
Label correctness audits, deduplication across datasets (train/test contamination between collections), re-verification of the three unconfirmed published sizes, and any evaluation requiring a live model.
