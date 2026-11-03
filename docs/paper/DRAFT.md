# Mediating Agent Effects Under Partial Observability: Commit-Time Authorization, Measured Unknowns, and a Synthetic Benchmark
**DRAFT v0 — 2026-11-04 — not peer reviewed; all results below are from fixtures/models run by the authors. Novelty is UNCONFIRMED (no systematic prior-art search has been done).**

## Abstract (provisional)
Tool-using LLM agents act on the world through protocols (MCP, HTTP-style tool calls, code execution, delegation). We study a defender that must decide ALLOW / BLOCK / UNKNOWN for each effect while some effect channels are unobservable. We report (i) a commit-time authorization design (exact-effect permits, at-most-once dispatch, sink-side outcomes, claims that suspend when dependencies break), (ii) seven analysis tools — measured-UNKNOWN coverage, permit near-miss fuzzing, a differential reference kernel, causal sink diffing, witness-independence scoring, an exhaustive revocation-race model and a signed negative-result registry, (iii) a finite model that synthesizes where to run, enforce and witness an operation or returns a re-checkable "not certifiable" certificate, and (iv) MCPHorizon-Effects v0, a 960-scenario synthetic benchmark. A negative finding is central: a rule defender written after reading the generator saturates v0 (0 false certifications, perfect decisions), so template benchmarks cannot rank strong defenders; we describe what is needed instead. No real LLM agent, real MCP deployment or independent evaluator has been used yet.

## 1 Problem and threat model
Defender sits between an untrusted agent/tools and protected sinks. Adversary controls tool outputs/descriptions, remote services and the agent's reasoning; host kernel and trust roots are assumed uncompromised (explicit non-goal otherwise). Unobservable off-host effects are out of reach: for them the only sound answer is UNKNOWN or relocation (Sec. 4).

## 2 Design (implemented, CANDIDATE)
2.1 Scoped request state: cache, cancellation, idempotency keyed by tenant/server/session/principal/typed id (12 tests, 8/8 mutants killed).
2.2 CanonicalEffect + commit-time verification: any single-field change of args, destination, session, server, tenant, principal, effect, policy version or expiry is refused; replay refused; unknown effect types fail closed (16 tests, 7 mutants).
2.3 Durable ledger: REQUESTED→AUTHORIZED→STARTED→COMMITTED|BLOCKED|UNKNOWN→RECONCILED; exactly one of 100 concurrent callers dispatches; nonce reservation single-winner; crash leaves STARTED→UNKNOWN, never retried (17 tests, 12 mutants). Single-node SQLite only.
2.4 Sink-side outcome: file sink with its own journal; reconciliation only from sink observation (15 tests). OS-level separation: sink under its own uid with 0700 data dir and SO_PEERCRED gateway check; an agent uid is refused (10 tests, root-only).
2.5 HorizonZero claims: dependency-closure suspension on expiry/epoch/digest/missing/revocation; outcome states separate prevention from observation (16 tests, 14 mutants; a test caught a nested-propagation bug).

## 3 Analysis tools (Sec. 2 of `docs/evidence/novel`)
| Tool | Result (fixtures/models) | Caveat |
|---|---|---|
| Measured UNKNOWN | zero-probe items are UNKNOWN; Wilson lower bound on covered fraction | method only |
| Permit fuzzing | 0 of 25+ near-miss mutations accepted; only audit-only `decision_id` free; fuzzer detects a deliberately weak verifier | single verifier, same author |
| Differential kernel | 5,000 generated cases, 0 mismatches vs. pure reference | same language/author: finds drift, not shared spec errors |
| Sink diffing | log-only "blocking" flagged | toy workflows |
| Witness independence | shared key/root/operator ⇒ dependent; claim needs ≥2 clusters | thresholds ad hoc |
| Race model | check-then-act violates 1/3 schedules; atomic and epoch-fenced 0; check-after detects only | exhaustive model, not system rates |
| Negative registry | chain/sig tamper, reorder, drop all detected | test key |

## 4 Bounded boundary synthesis (HorizonForge slice)
Finite model over {placement, data form, controls, witnesses}; independent checker; enumerative synthesizer returning CERTIFIED_WITH_SCOPE / CERTIFIABLE_AFTER_RELOCATION / NOT_CERTIFIABLE_WITHIN_MODEL with a certificate listing the checker's violation for every enumerated plan. Raw secret to an opaque remote ⇒ not certifiable; permitting an approved aggregate or an attested sandbox ⇒ relocation found. Finite indistinguishable-world certificates name the missing witness channel. *Open:* complexity, SMT backend, real workflows, comparison against shield synthesis / proof-carrying contracts (Sec. 8).

## 5 Black-box effect tomography (Spectra slice)
Fixture-owned journals only; probes over a finite channel-graph class; verdicts DISCOVERED / UNIDENTIFIABLE / BOUNDED_COVERAGE / UNKNOWN. Off-host leak and its matched safe world are both UNIDENTIFIABLE (never certified). A soundness bug (early stop certified untried probes) was found and fixed. Efficiency vs random probing is a toy measurement, not a claim.

## 6 Benchmark: MCPHorizon-Effects v0
960 scenarios, 12 families × {attack, benign} × 40; scenarios and labels in separate files; splits: train 352, dev 80, heldout_template 208, heldout 320 (families F09–F12, unseen effect types); F11 unidentifiable by design. Baselines (all 960): allow-all FCU 440/440, benign 480/480; deny-all FCU 0/440, benign 0/480; keyword rule FCU 280/440 (63.6%). **Reference rule defender: FCU 0/440, every decision matches the label on all splits ⇒ v0 is saturated and circular** (rules written after reading the generator; held-out numbers are not unseen-attack evidence).

## 7 What would make this a publishable empirical paper (not done)
(a) Independently authored held-out families and adaptive attacks against a named defender; (b) LLM-generated paraphrased traces and real tool-using agents (needs model access — blocked: model hosts return 403 from the sandbox); (c) real MCP/HTTP/Code Mode effect journals; (d) strong baselines — runtime shielding, proof-carrying contracts, IFC/taint — under equal control and observation budgets; (e) preregistered primary endpoints (false-certified-unsafe, benign utility, UNKNOWN correctness) with cluster-bootstrap intervals; (f) independent clean-host replication and expert novelty critique. Weight-space repair (HorizonPatch/Sentinel/Transfer): only model-free plumbing exists; no result.

## 8 Related work (to be verified; from the research specs, NOT re-checked)
Proof-carrying contracts (PC2), HAACE and TRAIL drafts, TRACE, runtime-contract and partial-monitoring papers, shield synthesis (CEGIS), partial-observability verification, AgentLoupe/CausalTrace, refusal-direction and circuit-guided weight editing. A dated search ledger and closest-work matrix must be produced before any novelty wording.

## 9 Limitations
Author-run only; same author wrote implementation, checkers and benchmark; fixtures not systems; single-node state; Linux-only OS separation requiring root; reference defender circular; no human or external review; no claim of production readiness or universal protection.

## 10 Reproducibility
Every module has `docs/evidence/*/ASSUMPTIONS_AND_LIMITS.md` with a one-line reproduce command; dataset `python3 bench/dataset/generate.py --check`; scorer `python3 bench/dataset/evaluate.py`.
