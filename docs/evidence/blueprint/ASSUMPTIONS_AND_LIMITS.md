# Blueprint slice: roadmap tracker, typed schemas, utility floor and Pareto frontier (CANDIDATE)

Source: `docs/roadmap/BOUNDARY_SYNTHESIS_BLUEPRINT_2026-11-07.md` (user-supplied, pinned by sha256 in `docs/roadmap/blueprint_status.json`).

## What this adds
- `security_hardening/roadmap.py`, `scripts/blueprint_roadmap.py`: all 74 blueprint tasks tracked as OPEN / CANDIDATE / BLOCKED. The checker rejects: unknown statuses (anything like DONE or INDEPENDENTLY_VERIFIED), a `*-GATE` task marked CANDIDATE, CANDIDATE without existing in-repo evidence whose sha256 still matches and a limits note, BLOCKED without a named blocker, OPEN carrying claims, tasks missing from or not in the document, and a changed document digest. Result today: 37 OPEN, 16 CANDIDATE, 21 BLOCKED, 0 independently verified.
- `docs/roadmap/NEGATIVE_RESULTS.md`: append-only register of 12 negative results and post-hoc changes (S0-05).
- `horizon/coverage/schema.py`: closed-enum typed `TrustZone`, `Witness`, `EffectEdge`, `Probe`, `Observation`, `HypothesisWorld` with unknown-field rejection, canonical digest, and `validate_observation`, which grades evidence: a witness inside the agent or tool-server zone is only SELF_REPORTED; `not_seen`/`unobservable` and anything on an uninstrumented edge is UNKNOWN, never absence evidence; a probe must be synthetic with effect ceiling 0.
- `horizon/forge/pareto.py`: floor-constrained solve and (cost, utility-loss) Pareto frontier over the finite Forge portfolio, with an independently coded exhaustive verifier. A blanket denial is reported as `deny_all.is_solution = false`.
- Tests: `tests/blueprint` (48). Mutants: `scripts/blueprint_mutants.py` 50/50 killed (timeout = killed).

## Limits (read before citing)
- Schemas are not yet consumed by Spectra, Coverage or Forge; they only define and validate the vocabulary. S2-01/S2-02 are CANDIDATE, not integrated.
- Utility loss in Forge is binary (raw vs aggregate). The "floor" is therefore coarse; there is no real task-utility oracle. S3-03 does not show that synthesis preserves utility on a real agent.
- Pareto optimality is relative to the enumerated toy portfolio (3 placements, 2 forms, 3 controls, 2 witnesses). It says nothing about real deployments or about C3 outside the model.
- The tracker enforces honesty of the record, not truth of the evidence: a CANDIDATE row means "author-run evidence exists with these limits". Evidence digests detect edits, not correctness. Nothing here is reviewed by an independent party; all `*-GATE`, reviewer-key, independent-fixture, external-reproduction and pilot tasks are BLOCKED on people/infrastructure the author cannot supply.
- Hard roadmap items intentionally NOT attempted here (OPEN): canonical-effect parity and strict base64url (S1-01..03), real OS/TLS/DNS egress control (S1-06/07), real MCP end-to-end path (S1-09), Spectra on receiver-owned fixtures (S2-03), larger Forge IR / SMT (S3-01/02), durable claim registry (S4-*), baselines such as OpenShell-style runtimes (S5-03).
- No novelty, "first", or security-gain claim is made. Prior art listed in the blueprint section 6 still applies.
