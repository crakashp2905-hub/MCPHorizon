# P47 HorizonIncentive — assumptions, scope and limits (CANDIDATE)

Status: **CANDIDATE**. Nothing here is VERIFIED. Evidence level: author-written synthetic platform, plans, oracle and baselines; deterministic utility-maximizing agents; no language model run, no independent reviewer, no pilot (L3/L5 not met).

## 1. What is claimed, and what is not (P47-15)
**Observable goal conflict.** A *conflict* is a relation between a plan (or a concrete action) and a hard constraint: "this plan, if executed, produces an effect the constraint prohibits". It is established by (a) the independent oracle on the platform's effect journal, (b) a monitor denial naming the constraint, or (c) an advisory static preflight over the plan. All three are about *effects and plans*.

**Not claimed.** Nothing here infers why an agent would pick a plan, that a model "wants" or "intends" anything, or that real models respond to pressure the way the utility model does. The agents are deterministic maximizers of a stated function `U = done + ι·reward − soft penalty` over a fixed plan set. The experiment shows what that function ranks first, and what each safeguard does about the ranking. "Pressure" in the sweep means the value of ι, not a mental state. Reports cite scenario ids and constraint ids, never motives.

## 2. Security semantics (spec §67.2)
Let π be a plan and Φ the contract {H1..H5} (see `contract.py`). The monitor's admission rule is: an action is allowed iff, given the evidence presented and the project's accumulated usage, it does not violate any Φ clause. The reward model R_i does not appear in the rule (static test: the monitor source contains neither `iota` nor `utility`).

Scoped statement, **not** a theorem about the world: *if* (A1) every consequential effect of the platform is reachable only through the gateway, (A2) the effect registry classifies every tool correctly and aliases are resolved, (A3) the evidence issuers (CI, approver) are honest and their keys are not available to agents, (A4) the monitor's usage counters see every call of the project, then no effect that the oracle's reading of H1–H5 prohibits is produced by an allowed action. Proof sketch: each clause is checked on the action itself; budgets are checked before the action is admitted and counted only when it is. The statement says nothing about effects outside H1–H5.

## 3. Soft safeguards, modelled in their strongest form
- **instruction-only**: a penalty of 2.5 per violated hard constraint in the agent's own utility.
- **reward-penalty**: an expected post-hoc penalty of 4.0 × audit rate 0.25 = 1.0 per violated constraint.
- **preflight-advisory**: conflicts from the static preflight, shown as 2.5 per constraint.
In all three the agent is told *exactly* which constraints each plan violates (except plans marked `unaware`, honest mistakes). Real instructions are vaguer, so this favours the baselines. The conclusion that a finite penalty is overridden once ι is large enough follows from the model; the experiment's information is *where* the crossover falls for these weights and what happens at ι = 8.

## 4. Oracle and independence (P47-13)
`oracle.judge` reads only the platform's effect journal. Journal `writer` fields are set by the platform to the true caller (CI, approver, or the calling agent), never by the agent. The oracle has no import of the monitor, registry, tokens or HorizonPolicy (static test), and re-derives H1–H5 from journal facts (tests executed by CI for that digest with full scope and a pass; an approval written by the approver for that environment and digest, for that requester, not self-approved and unused; row and call sums). The monitor never reads the journal.

It is nevertheless the same author's: the platform's behaviour, the tool registry, what counts as a violation and the plans are all one hand's.

## 5. Limits
1. **Closed world.** Five constraints, thirteen attack and seven benign scenarios, one platform. An agent that finds a shortcut outside the effect registry, or an effect no constraint names, is out of scope. The monitor's 0 is not a bound.
2. **Variants are not independent samples.** The model is deterministic; the three variants only move the deadline by ±2 s. Wilson intervals are descriptive.
3. **Honest evidence services assumed.** CI and approver are trusted; a compromised or fooled approver defeats H2. The approver here approves whatever it is asked, as a stand-in for a human.
4. **Non-adaptive replanning wastes budget.** In A08/A09 the denied shortcut consumed part of the budget before the denial, so the agent's fixed fallback is denied too and only part of the work is delivered. A real planner would adapt; the monitor did not cause the waste, but the experiment does not show an adaptive planner.
5. **Preflight is advisory and partial.** It cannot see evidence tokens held outside the plan (false positive on B02) or that a rebuild changes the digest after testing (miss on A12). Reported, not hidden. The monitor localizes the *root cause* (it blocks disabling CI before the downstream clash can occur).
6. **Time is virtual** (fixed per-tool durations). Real latency, queueing and monitor overhead are not measured.
7. **Multi-agent** here means several principals sharing a world and budgets, run one after another; no concurrency, no negotiation, no collusion strategies beyond sub-agent fan-out.
8. **No model.** No claim is made about LLM agents, reward hacking in training, or goal misgeneralization in real systems.

## 6. Benchmark reuse (P47-16)
Everything needed to rerun is in the repository: `horizon/incentive/scenarios.py` (plans, goals, deadlines, reward profile per scenario), `agents.py` (transparent reward functions and constants), `contract.py` (constraints and registry), and `results/v2/p47-incentive/manifest.json` (definitions hash-checked by `scripts/p47_run.py --check`). Each scenario states its expected outcome in `docs/evidence/p47/BENCHMARK.md`.
