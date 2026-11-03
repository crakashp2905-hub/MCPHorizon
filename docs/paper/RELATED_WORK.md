# Prior-work search (2026-11-04) — CANDIDATE, not exhaustive

Method: ~12 web searches + abstract-level reads (arXiv abstract pages) of the closest hits. **Only abstracts were read, not full papers**; claims below are limited to what the abstracts state. A full read by a human reviewer is still required before any novelty claim. Absence of a hit is not evidence of absence.

## Closest prior work (read at abstract level)
| Work | What it does | Overlap with MCPHorizon | Evaluated on |
|---|---|---|---|
| CaMeL — Defeating Prompt Injections by Design (arXiv 2503.18813) | Control/data-flow extraction from trusted query + capabilities enforced at tool calls | Argument provenance / policy at tool boundary | AgentDojo: 77% tasks w/ provable security vs 84% undefended |
| Progent (arXiv 2504.11703) | Deterministic privilege policies over tool names + args, LLM-generated, SMT-checked monotonic updates | Task-scope allowlist (our `scope`/`scope_args` baselines) | AgentDojo, ASB |
| FIDES — Securing AI Agents with Information-Flow Control (arXiv 2505.23643) | IFC labels for agent planners | Provenance rule | (not read beyond title/abstract page) |
| MELON (arXiv 2502.05174) | Masked re-execution + tool-call comparison | Different (detection) | AgentDojo |
| DRIFT (arXiv 2506.12104) | Dynamic rule-based defense + injection isolation | Task-scope rules | AgentDojo |
| AuthGraph (arXiv 2605.26497) | Provenance graph vs user-authorization graph alignment | Provenance-vs-authorization | AgentDojo GPT-4o ASR 40%→1%, 76% completion (author-reported) |
| **AgentCap** (arXiv 2611.00729, Oct 31 2026) | MCP wrapper; per-call intent + policy; short-lived budget-limited **capability tokens** validated at the tool boundary; delegation chains | **Substantial**: signed/limited authorization tokens at MCP boundary | AgentDojo, InjecAgent; 0% ASR with GPT-5.4 (author-reported) |
| **CapLease** (arXiv 2608.01710, Aug 2026) | Durable authorization state; Issue-Prepare-Commit; defeats "semantic replay" (fresh token for same authorization) | **Substantial**: single-use nonce, replay resistance, durable ledger, crash recovery | Scenario tests (no public benchmark) |
| Verified Tool Calls (arXiv 2608.02645) | Postcondition verification, verify-before-retry, idempotency keys under non-atomic failures | Overlaps our at-most-once dispatch / UNKNOWN reconciliation idea | Simulated failures |
| ScopeGate / "Capability Gates Are Not Authorization" (arXiv 2606.28679) | Per-call value check: scope, authorization, ceiling, idempotency, default-deny; audit of LangChain/LlamaIndex/Stripe toolkit | Per-call value authorization + idempotency | Framework audit, adaptive run |
| Industry/blog: signed MCP receipts (several), MCP discussion #3215 on signed authorization + execution receipts | Evidence after the call | Receipts (not prevention) | n/a |

## Consequences for our claims (honest positioning)
1. **Do NOT claim novelty** for: tool-boundary authorization, signed/limited tokens, single-use nonces, durable ledgers, idempotency/at-most-once, argument provenance, task-scope allowlists. All have close published/preprint precedent (AgentCap, CapLease, Verified Tool Calls, ScopeGate, Progent, CaMeL).
2. Possibly distinguishing (UNVERIFIED — needs a deeper search and expert review): (a) a **canonical effect** representation bound across gate, ledger and *sink-side journals* with reconciliation of UNKNOWN outcomes only from sink observation; (b) **explicit UNKNOWN/unidentifiable verdicts** (HorizonSpectra: DISCOVERED / UNIDENTIFIABLE / BOUNDED_COVERAGE) with negative certificates instead of silent allow/deny; (c) a **claim registry with dependency-closure suspension**; (d) exhaustive revocation-race model checking; (e) mutation-tested, assumption-labelled evidence discipline. For (b)–(c) the searches (incl. an extended query on black-box identifiability of authorization boundaries) returned no close match, which is weak evidence only.
3. A fair paper framing today: **a systems/evaluation paper on commit-time authorization semantics with honest negative results**, positioned against AgentCap/CapLease, not as a new defense class.
4. Required before submission: head-to-head with Progent/CaMeL/AgentCap numbers on the same models and attacks (not just author-reported), a full read of the papers above, and a second-person novelty check.

## Not found / not checked
MCPTox and MCP-SafetyBench papers describe benchmarks but gave no code link in the abstract pages fetched (so they are not collectable here). Defenses not yet read: Task Shield, AgentSpec, ShieldAgent, Invariant Guardrails, AgentSentry (2602.22724).
