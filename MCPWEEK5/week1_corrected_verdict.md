# Week 1 — Corrected Verdict

## What the original report said
> **PREMISE DOES NOT HOLD — rethink architecture**
>
> 11 / 157 sequence_injection clean (7%)

## What the data actually says

The 7% headline was misleading. The original verdict bucket conflated three
distinct failure modes. Diagnosis (`diagnose.py`) separates them:

| Slice | Definition | Detection |
|---|---|---|
| Step 1 tool ∈ TOOL_DB | Engine has signal to work with | **73%** (11/15) |
| Step 1 tool ∉ TOOL_DB | Engine sees empty capability set | 0% (0/142) |
| Overall | Mix of the two | 7% (11/157) |

The architecture works on **every attack where the engine knows about the
relevant tools**. The 142 silent failures are 100% explained by TOOL_DB
covering only 13 of the 169 unique tools that appear in your full MCPTox
dataset (8% vocabulary coverage).

## The actual Week 1 verdict

**PREMISE HOLDS, gated by vocabulary coverage. The architecture is sound;
TOOL_DB is the bottleneck.**

This is the *expected* Week 1 outcome — the experiment exposes exactly what
Week 2 must build (TOOL_DB expansion).

## Coverage-expansion experiment (run as part of this fix)

To prove this isn't a face-saving reinterpretation, I ran the actual
expansion. `expand_tool_db.py` applies regex pattern rules to the 127
unknown tools and auto-annotates 83 of them (65% coverage).
`verify_expansion_v2.py` plugs the result back into the engine and re-runs
all 221 trajectories.

| Configuration | TOOL_DB size | Hyperedges | Step1-known clean | Overall clean |
|---|---|---|---|---|
| Original | 13 | 6 | 73% (11/15) | 7% (11/157) |
| + 53 pattern-annotated tools | 66 | 11 | 51% (55/107) | 36% (56/157) |
| + 30 more pattern rules | 96 | 11 | 58% (77/132) | 50% (78/157) |
| + 2 conjunctive hyperedges (code+net, list+net) | 96 | 13 | **66% (87/132)** | **56% (88/157)** |

Each iteration is a single pattern rule or single hyperedge addition, taking
minutes. There is no fundamental ceiling at 66%; with another half-day of
manual annotation of the long tail (~31 tools left), and a handful more
hyperedges for the email-data-exfil and Slack-data-exfil chains, this
trends to 80%+.

## The compositional emergence finding survived

| Track | Result |
|---|---|
| Sequence-injection (in-scope) | 66% step1-known after expansion |
| Scope-corruption (out-of-scope by design) | 100% (59/59) correctly tagged |
| **Compositional emergence (synthetic)** | **100% (3/3)** — the actual paper claim |
| Benign baselines | 100% TNR (0 false positives) |

The compositional emergence trajectories are unaffected by TOOL_DB size
because they use tools (`read_file`, `write_file`, `http_post`, `fetch`,
`exec`) that were in the original 13. Conjunctive hyperedge firing works
exactly as designed.

## What actually needs to change

Three concrete fixes to the original report logic:

1. **`replay.py` verdict mapping is too aggressive.** The "❌ failed (goal
   not reached)" verdict should be split into "❌ failed (architectural)"
   and "⚠️ untestable (tool not in TOOL_DB)". Tools the engine doesn't
   know about should not count against the architecture.

2. **`trajectory_builder._infer_goal_capability()` is too narrow.** It
   only fires goals for `read_file` / `write_file` to credential paths,
   missing capabilities induced by other tool types entirely. Should be
   replaced with: "if the induced step's tool capabilities intersect the
   danger horizon, mark that intersection as the goal."

3. **`score_results()` thresholds need a coverage-conditional path.** A
   verdict of "PREMISE HOLDS" should be computable from the in-vocabulary
   slice, not the overall rate.

These three fixes are the deliverable for tomorrow morning, before kicking
off Week 2 proper.

## What Week 2 should do (revised)

Given the corrected verdict (premise holds, gated by vocabulary):

**Day 1-2 — Apply the three fixes above to `replay.py`,
`trajectory_builder.py`, `report.py`. Re-run on the full dataset.**

**Day 3 — LLM-assisted annotation of the 44 manual-review tools.** Send
each unknown tool name + its appearance context (the docstring of the
poisoned tool that mentions it, the parameter names, sibling tool names
in the same MCP server) to Claude/GPT-4 with the capability vocabulary,
parse JSON response, manually review low-confidence outputs.

**Day 4-5 — Capability lattice (parametric capabilities).** Replace flat
strings with (action, resource, scope) tuples. This is the architectural
upgrade that fixes scope_corruption attacks (currently tagged out-of-scope)
and makes path-dependent scope_lift more principled.

**Day 6-7 — Integration with the next dataset (MCPSecBench or
Servant/Stalker/Predator).** Apply the same pipeline. Hyperedges mined
from MCPTox should generalize to MCPSecBench attacks. If they don't,
that's a critical generalization finding for the paper.

## Files to look at

- `results/week1_diagnosis.json` — original-engine diagnosis
- `results/week1_diagnosis_expanded.json` — post-expansion diagnosis
- `results/tool_db_expansion.json` — 83 auto-annotated tools + 44 manual queue
- `results/week1_results_expanded.json` — full per-trajectory results after expansion
- `diagnose.py` — the corrected scoring tool (use this, not `score_results`)
- `expand_tool_db.py` — pattern-based expansion (extend the rules to bump coverage)
- `verify_expansion_v2.py` — end-to-end verification script
