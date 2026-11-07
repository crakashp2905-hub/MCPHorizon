# Blueprint slice: roadmap tracker, typed schemas, utility floor and Pareto frontier (CANDIDATE)

Source: `docs/roadmap/BOUNDARY_SYNTHESIS_BLUEPRINT_2026-11-07.md` (user-supplied, pinned by sha256 in `docs/roadmap/blueprint_status.json`).

## What this adds
- `security_hardening/roadmap.py`, `scripts/blueprint_roadmap.py`: all 74 blueprint tasks tracked as OPEN / CANDIDATE / BLOCKED. The checker rejects: unknown statuses (anything like DONE or INDEPENDENTLY_VERIFIED), a `*-GATE` task marked CANDIDATE, CANDIDATE without existing in-repo evidence whose sha256 still matches and a limits note, BLOCKED without a named blocker, OPEN carrying claims, tasks missing from or not in the document, and a changed document digest. Result today: 37 OPEN, 16 CANDIDATE, 21 BLOCKED, 0 independently verified.
- `docs/roadmap/NEGATIVE_RESULTS.md`: append-only register of 14 negative results and post-hoc changes (S0-05).
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

## Addendum: durable assurance claims and probe-selection comparison (S4-01..S4-07, S2-07)
- `horizon/assurance/durable.py`: signed claims in a hash-chained, append-only SQLite log. PERMIT checks and REVOKE/INVALIDATE share one log under `BEGIN IMMEDIATE`, so across processes no PERMIT is logged after a revoke (4 racing worker processes, plus 3 SIGKILL rounds, tested). Anomalies fail closed.
- `ProtectedFileWriter(gate=...)` (file sink only): a denying/erroring gate blocks the effect at commit time. Observed behaviour: the verifier consumes the permit nonce before the gate runs, so a denied effect burns its permit and a fresh one is required.
- **Found limit:** a hash chain does not detect TAIL truncation (rollback to an earlier valid prefix). `head()`/`check_anchor()` detect it only against an external anchor; no independent anchor exists. Tested and documented, not solved.
- **Negative result (S2-07):** on 217 self-authored toy worlds, Spectra's active probe order saved 0.0-0.6 probes on average versus random, static-graph and expert-rule orders, and all three paired bootstrap 95% CIs include 0. No advantage of active selection is demonstrated. Worlds were generated with the same hypothesis class the active method uses (favourable to it) and are neither independent nor held-out.
- Grades above SOURCE_VERIFIED require a different key under a reproducer/auditor issuer; no such independent party exists, so none is claimed. Test keys are generated in memory.
- Not done and still OPEN (37 -> 29 after this slice; 29 listed): S0-01/02, S1-01..03, S1-06..10, S2-03/04/08, S3-01/02/05/08/09/10, S5-03/04/05/07/08, S7-01..05. Reasons: they require core protocol changes needing an owner decision (S1-01..03), root/OS/network infrastructure beyond this sandbox (S1-06/07), a real MCP agent path (S1-09), real task oracles and live agents at scale (S1-10, S5-*), or sandbox-enforced probe isolation which a toy cannot demonstrate (S2-04/08).

## Addendum: strict base64url (S1-02) and dataset/novelty notes
- `effect.b64d` and `audience._unb64` reject non-canonical base64url (re-encode must equal input) and raise domain errors for bad lengths. All 16 padding-bit spellings of a signature were previously accepted; now exactly one is. The old test that asserted acceptance was inverted on purpose (register N13). Owner authorization: the user said "you can do everything from A".
- No Rust/TS change was needed: this repo contains no permit decoder in those languages. If one exists elsewhere it needs the same rule.
- S1-02 is CANDIDATE only for file-write permits. S1-01 (every supported effect) and S1-03 (tool server, session, delegated authority, epoch carried consistently) stay OPEN: the permit has no tool-server/session/delegation fields.
- `docs/research/VALIDATION_DATASETS_AND_NOVELTY_PITCHES.md`: dataset survey and six pitch candidates with falsifiers. Dataset licences are UNVERIFIED (fetch approvals went unanswered); no dataset was downloaded or run.

## Addendum: reference MCP stdio gateway, sink journal hash chain, mutation-harness correction
- `horizon/effects/mcp_gateway.py`: newline-delimited JSON-RPC stdio server (initialize / tools/list / tools/call) exposing one tool, `write_file`. It mints an Ed25519 permit and commits through `ProtectedFileWriter`. Limit: authority is embedded in the gateway process, so agent, gateway and authority are NOT separate principals; this shows the path end to end, not a trust boundary. Policy allows only direct children of a root, non-hidden, with no symlink or `..` tricks (tested).
- `FileSink` journal is now hash-chained (prev, h) under flock; `verify_chain` / `check_anchor` detect edits and reordering. Limit: tail truncation is detectable only against an external anchor, and the OS-separated `sinkproc.py` journal is NOT yet chained.
- Mutation-harness correction (register N14): the evidence-digest test killed every mutant in evidence files, inflating the kill count. It is excluded under `MUTATION_RUN=1`; survivors exposed by that were fixed with tests or redundant code removed. Count now 93/93 on the honest harness, author-run only.
- Tracker: S1-08 and S1-09 moved to CANDIDATE (single host, author tests). S1-01/S1-03 remain OPEN.
