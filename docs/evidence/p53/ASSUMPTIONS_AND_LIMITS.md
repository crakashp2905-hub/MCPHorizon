# P53 HorizonContinuity — assumptions and limits (CANDIDATE)

Status: **CANDIDATE**. Nothing here is VERIFIED. The promotion gate (protected sinks independently mediated on a real runtime, survival of a missing-telemetry failure on real services, a preregistered disruption budget, independent review) is not met and is not simulated.

## Property (P53-01)
For a migration from environment A to B, let K_A be the source contract (mandatory controls with required levels) and G_B the guarantees the target attests. A handoff is admissible only if G_B covers every mandatory control of K_A, and the transferred authority, labels, obligations and budgets do not widen permission. An unknown receiving environment yields deny with a reported UNKNOWN outcome; signed state alone does not make the new environment trustworthy.

## Portable envelope (P53-02..05)
Sections (exact set, checked by `core.validate`): task, principal chain, permissions, controls (K_A), labels, obligations, budgets (cap plus ledger pointer), approvals (id, action, expiry), credentials (broker handles only), artifact digests, policy id and version, revocation handle, in-flight operations (done / pending), provenance, issue and expiry times, single-use resume nonce. It is signed by the source runtime's checkpoint service through the shared HorizonPolicy authority (an evidence issuer; admission and resume code never sign). Raw secrets cannot appear: the schema rejects credential value fields and any occurrence of the synthetic canary; the target receives a broker-issued credential bound to its runtime id and the source's is revoked.

## Scoped theorem (what the suite can support, and what it cannot)
*If* (a) the attestor reports what the target really enforces, and the attestation is fresh and bound to the target's identity; (b) the authoritative grants, label registry, budget ledger, revocation feed and credential broker are honest and reachable; (c) the target's sinks are mediated by the runtime's controls; (d) the source's checkpoint service signs only the state it reads from those authorities; and (e) evidence is signed by the shared authority and verified with public keys only, *then* a successful resume leaves every mandatory control enforced at the target at a level at least that of K_A, never widens authority, resumes an envelope at most once, and leaves the source unable to act. This is **not a proof**. It is a statement checked on 14 attack scenarios, 10 benign controls, 3 unsupported or unknown-environment paths and 2 telemetry-offline paths, all written by the same author as the module and the baselines (machine-checkable form: `results/v2/p53-continuity/trust_gaps.json`, properties C1–C5).

## Known trust gap (reported, not hidden)
- **G1 deceived attestor (U02).** If the attestor reports guarantees the runtime does not enforce, the module admits the move and the prohibited effect happens. It is neither prevented nor flagged. This is outside assumption (a).
- **G2 unmediated sinks (U03).** Attestation covers what a runtime supports; the module denies when the attestation says the sinks are not mediated, and cannot know otherwise.
- **G3 unknown providers (U01).** Equivalence cannot be established; the move is denied and reported UNKNOWN. This is availability cost, not security.
- **G4 compromised source.** A source that signs a malicious envelope is bounded only by the no-widening check against the authoritative grant; not exercised.
- **G5 carriers.** MCP/UTCP/Code Mode are a field of the runtime model; the module is not wired through the real adapters (the same boundary P45 and P50 document).

## What the model is
Runtimes are Python objects with a table of what they support and what they enforce by default (`runtime.LIB`); an operation passes through the runtime's effective controls and then reaches an independent receiver. A runtime cannot enforce more than it supports; a sink that is not mediated ignores the controls. The baselines are modelled by what they transfer and verify: state serialization (permissions, credentials, pending calls, approvals as already-validated flags; counters reset; source keeps running), token copying, container snapshot (labels, obligations, local counters, revocation handle; host controls do not travel; no drain), policy-config sync (the target silently enables the controls it supports), a tool-name compatibility check, and a hand-written same-vendor rule. These are the author's reading of those techniques, not reproductions of any named product; the comparison shows what each idea does when applied as described and is not a measurement of any real system.

## Other limits
- No real network, runtime or kernel; hosts are synthetic (`*.test`), the secret is the canary `TEST_CANARY_NOT_SECRET`. Time is a logical clock.
- Each scenario is a script with one migration; chained migrations (A→B→C), partial failures inside the receiver, crashes between freeze and resume, and a source that cannot be reached for rollback (only `source_alive` is modelled) are not covered.
- Several mechanisms overlap; the results list the redundant ablations, and `tests.p53.test_continuity.EachMechanismAlone` exercises each with its overlapping mechanisms off.
- The hand-written same-vendor rule prevents almost everything by never migrating; the cost is shown as unjustified denials and lost migrations, not hidden by counting completed tasks only.
- Handoff latency is model-only (`scripts/p53_bench.py`, machine-specific, not recorded).

## Mutation testing
`scripts/p53_mutants.py` applies each mutant to a copy of the tree and requires `tests/p53` to fail; a timeout counts as killed. Mutants of `scenarios.py` are not included.
