# P16 — Epistemic integrity: what was built and what the numbers do (not) show

**Deployable** (`horizon/epist/assess.py`): propositions with dependencies; evidence with scope, resource version, freshness, attestor (HMAC, shared-key stand-in for signatures), provenance roots; states VERIFIED / UNVERIFIED / CONFLICTED / STALE / UNKNOWN; independence = union-find over provenance roots; evidence-obligation gate for designated high-consequence operations returning REVIEW + a per-proposition REVERIFY requirement (P16-04, 14). The assessor imports nothing from `bench/` and has no truth parameter (tested by AST check).

**Fixtures** (`bench/p16/fixtures.py`): 5 domains × 14 templates (4 benign incl. noisy-but-harmless, untrusted-source; 10 attacks: irrelevant, circular, stale, overwritten, withdrawn, fraudulent attestation, suppression, conflict, schema, independent collusion). Truth sits in `TruthRegistry`, never in `Case.observable()`. Obligation policies exist for the two TRAIN domains only; the three TEST domains fall back to the domain-agnostic default.

**Result** (`results/v2/p16-epistemic/`, 420 cases): harm allowed — open 300/300, malicious-label 240, trust flags 300 (and 30/120 benign false-blocks), taint-only 240, legacy epistemic 240, epistemic 30/300 (all `collusion_independent`), 0/120 benign false-blocks; held-out test domains behave the same. Latency ≈17 µs mean per decision vs ≈1 µs.

## Read this before citing the numbers
1. **The fixtures and the detector were written by the same party, from the same attack taxonomy.** The detector catches each attack class because it was built to. This is a unit-level demonstration that the mechanisms work as specified, not evidence of benefit on attacks I did not think of. GX4's "independent known-truth cases" is **not met**; independent case authoring is a human/external task.
2. Template-generated cases: p-values/CIs describe this fixture set only; 6 replicas per template are not independent samples.
3. **Known miss, by design:** two independent forged records (`collusion_independent`) read VERIFIED. VERIFIED means "obligation met", never "true" (P16-08). Defence needs out-of-band ground truth.
4. Attestation uses a shared-key HMAC as a stand-in; real deployments need asymmetric signatures and key custody (P13 machinery could be reused; not wired).
5. The "legacy epistemic" baseline is my reimplementation of the independent-verifier idea, not the original code's behaviour on these cases; label/taint/trust baselines are simple models.
6. The oracle row in the result file reads the truth registry and is a ceiling, not a system.

## P16-16 — unsupported: natural-language beliefs
Beliefs an agent forms in free text with no observable dependency trace (no evidence ids, no proposition links, no tool-call lineage) are **outside** this model. The system can only reason about claims that are registered as propositions with evidence linkage; a model asserting "the customer seems low-risk" from its weights or an unlogged context is invisible and is not claimed to be covered.
