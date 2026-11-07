# Validation datasets and novelty pitch candidates (2026-11-08)

Status: PROPOSAL. Datasets below were identified from web-search snippets only. **Licences were NOT verified** (page fetches needed an approval nobody gave); check each repository's LICENSE before ingesting or redistributing. Downloaded data is untrusted: put in its own directory, run Python with `-I`, never commit large data. Nothing here has been run.

## 1. Datasets and benchmarks worth using (by what they validate)

| Resource | What it offers (per its paper/snippet) | Validates in MCPHorizon | Caveats |
|---|---|---|---|
| AgentDojo (ETH/Invariant; NeurIPS 2024 D&B) | 97 tasks, 629 security cases, 4 suites (Workspace, Travel, Banking, Slack); utility checked on environment STATE, not an LLM judge; extensible | Primary live utility-under-attack test (S1-10, S5-08): the provenance gate and permits as a defense | Many defenses already reach ~0 ASR on it (AgentDyn paper); success here is weak evidence. Licence unverified. |
| AgentDyn (arXiv 2602.03117, v3 May 2026) | Manually designed, open-ended, dynamic tasks built because AgentDojo-style defenses look saturated; reports defenses (e.g. CaMeL, Progent, DRIFT) with utility/ASR trade-offs | Harder held-out-style test; baseline numbers for CaMeL/Progent give published comparators (S5-03) | Newer, less reproduced; licence unverified. |
| InjecAgent (UIUC) | 1,054 cases, 17 user tools, 62 attacker tools; single-turn; direct harm vs data stealing | Cheap offline replay of the provenance gate (does a gate flag the attacker tool args?) | Single-turn, no planning; offline replay cannot show downstream adaptation. |
| Agent Security Bench (ASB) | Attacks/defenses across agents, tools, memory | Memory-poisoning and plan-level families | Licence unverified. |
| MCPTox (USTC, arXiv 2508.14925) | 1,312 malicious cases on 45 real MCP servers / 353 tools; tool-poisoning in tool METADATA | MCP tool-description poisoning (a repo copy `MCPTox/` already exists) | Poisoned tool is never executed; effect-level test needs the hidden action to run. |
| MCP-SafetyBench (arXiv 2512.15163, ICLR 2026) | Real MCP servers, multi-turn, 5 domains, 20 attack types over server/host/user | Real-server, multi-step test for the MCP path (A4/S1-09) | Needs real server setup and a capable model. |
| MCPSecBench (arXiv 2508.13220) | 17 attack types over 4 surfaces; playground | Transport/host-level attacks beyond prompt injection (copy `MCPSecBench/` already exists) | Already used in earlier weeks; check for contamination. |
| MCP Security Bench (MSB, arXiv 2510.15994) | Runs real tools via MCP, robustness metric balancing security and utility | Direct security-utility metric to adopt | Verify availability and licence. |
| Gray Swan / UK AISI Indirect Prompt Injection Arena (arXiv 2603.15714) | 272k attack scenarios from a public competition, 13 models, concealment-aware attacks | Human-authored, ADAPTIVE attacks: the closest thing to independently authored attacks (the biggest credibility gap) | Access terms unknown; may be gated. |
| AgentHarm, WASP, OS-Harm, Agent-SafetyBench | Misuse, web/computer-use injection | Out of scope for the first supported class (self-hosted Linux, MCP tools, files + HTTP) except for AgentHarm refusals | WASP was previously flagged CC-BY-NC in project notes. |
| Own fixtures (this repo) | Synthetic canary worlds | Regression only | Author-written: never counts as held-out. |

**Recommended order:** (1) AgentDojo as a harness for clean/attacked utility with state-based checks; (2) MCP-SafetyBench or MSB for the real MCP path; (3) MCPTox/MCPSecBench for metadata and transport attacks; (4) Gray Swan arena data if obtainable for independently authored adaptive attacks; (5) AgentDyn as the hard check that a result is not saturation.

**Metrics to report for every run (blueprint 7.4):** attacker-effect rate with numerator/denominator, clean AND attacked utility, false blocks, UNKNOWN burden, per-attack-family clusters (not per-prompt), cluster-aware intervals.

**Honest limit:** these benchmarks mostly score tool CALLS by a model, not independently witnessed sink effects. MCPHorizon's distinctive claim (receiver-owned effect evidence) needs fixtures with real sinks; use the benchmarks for utility/attack coverage and our own sink-owned journals for the effect evidence.

## 2. Novelty pitch candidates (each with a falsifier; none is established)

Prior art already covers: capability/information-flow control (CaMeL, tracked capabilities), tool-firewall defenses (minimizer/sanitizer), gateways and runtime isolation (OpenShell and vendors), idempotency/verify-before-retry (LIMBO, Rubicon, CapLease, fencing tokens).

1. **Abstention as a first-class, scoped output.** A boundary compiler that returns `UNKNOWN` with a machine-checkable certificate when two worlds are observationally equivalent but differ in authorization-relevant effect (finite-model indistinguishability certificate + minimal missing-witness suggestion). Differs from "monitor says safe/unsafe". *Falsifier:* existing partial-observability theory plus a trivial monitor gives the same decisions on the same worlds. *Evidence needed:* independently authored paired worlds; false-certification rate.
2. **Witness-independence typing.** Evidence is graded by who can write it (agent/tool-server zone = self-reported; receiver/operator zone = independent) and a claim can never exceed its weakest witness. *Falsifier:* equivalent to standard audit-log trust models. *Evidence:* show real systems whose logs fail this test.
3. **Counterexample-guided boundary synthesis** with an independent checker and portfolio-exhausted negative certificates. *Falsifier:* a static template library picks the same plan on held-out cases (blueprint falsifier). Current Forge is a toy, so this is a hypothesis, not a result.
4. **Fail-closed assurance plane with ordered revocation.** Signed, hash-chained claims whose revocation is totally ordered against permit issuance (no permit after revoke across processes) and a commit-time deny-only gate. *Falsifier:* trivially achieved by any transactional DB. *Evidence:* wire into HTTP/process effects and measure invalidation latency p50/p99; this is more engineering contribution than science.
5. **Narrow, defensible paper:** bounded exhaustive verification plus code-level conformance of an at-most-once commit protocol with a sink-side fence-and-observe reconcile; two real bugs found by the method. Strongest evidence we have. *Falsifier:* the closest prior work already contains the fence-and-observe reconcile (read their full texts, not abstracts, first).
6. **Negative-result paper / benchmark critique:** simple provenance/identifier gates tie sophisticated defenses on saturated benchmarks (AgentDojo-style) while utility under attack collapses; propose reporting attacked-task utility and sink-witnessed effects. Backed by our own ties (SecBench) and 0/24 attacked utility. *Falsifier:* AgentDyn-style results already make this point. Needs a larger model and a real baseline run.

**Recommended pitch order:** 5 (publishable core), then 1+2 (the abstention/witness story, the most distinctive idea once independent worlds exist), with 6 as the evaluation framing. Do not claim "first" for any of them without the dated prior-art audit in blueprint section 6.3 signed by an independent reviewer.
