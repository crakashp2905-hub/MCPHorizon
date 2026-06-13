# T3-13 — Addressing the circularity critique

*"The horizon detects only what was pre-encoded."* Three threads; the first two reuse work
the paper already has, the third is a prototype. Reported honestly — including where the
prototype is partial.

## Thread 1 — the epistemic layer already catches danger outside the authored horizon

The cross-agent epistemic predicate (Appendix F) makes **2 net-new catches** the
capability horizon misses: `Colluding_education_04` (`add_unrelated_questions` poisons
`assessment_db`, then a **benign** `explain_concept` actuates across agents) and
`IPI_healthcare_01` (`suggest_unnecessary_diagnostic_tests` corrupts `patient_records`,
then a **benign** `respond_to_patient_query` actuates). Neither composition is enumerated
in the 19-entry capability horizon. So a *principled predicate* — "actuation on an
unverifiable belief descended from a silent falsification" — fires on harm **outside** the
authored set. This is direct evidence the detector is not limited to a hand-listed catalog:
a second, orthogonal principle already extends it.

## Thread 2 — the danger set is DISCOVERABLE, not bespoke

Evidence the rules are recoverable rather than arbitrary: the LLM proposer + empirical
sandbox validator framework (the leave-one-domain-out recovery experiment, T2-10) tests
whether a domain's hand-authored hyperedges can be **re-discovered** from its trajectories
without seeing them, validated at zero false positives on held-out benign runs. *(Status:
T2-10 is the dedicated experiment; this report's claim is gated on its per-domain recovery
numbers. The prior single-shot proposer already validated `h_file_system_access_with_writes`
at TP=2/FP=0, showing the loop surfaces real, non-authored edges.)* High recovery is the
answer to "hand-tuned ruleset for one benchmark": a rule you can re-derive from data is not
bespoke.

## Thread 3 — intrinsic dangerousness (non-enumerative measure), prototyped

`intrinsic_danger.py` derives a danger score from the lattice rather than authoring it:
`danger(action, resource) = irreversibility(action) × blast_radius(resource)`, where
`send`/`execute`/`delete` are irreversible and `external_network`/`sensitive_data`/
`production`/`audit_log`/`trade_order`/… carry high blast radius. A cross-agent composition
is intrinsically dangerous when a high-danger **source** (read-sensitive / write-critical)
meets a high-danger **sink** (send-external / actuate-critical).

**Derived-vs-authored horizon (honest, untuned):**

| Quantity | Value |
|---|---|
| High-danger capabilities (≥ 0.6) | 8 (top: `send(external_network)`=1.0, `execute(external_network)`=0.95, `delete(audit_log)`=0.81, `send(risk_control)`=0.8, …) |
| Authored entries recovered — **any** premise high-danger | **11 / 19** |
| Authored entries recovered — **both** premises high-danger (strict) | **0 / 19** |
| Derived candidate cross-agent compositions surfaced | 15 |
| Falsification-capable tools: authored / derived / overlap | 71 / 91 / **57** (≈80% of authored recovered) |

**What this means — and the honest gap.** The measure agrees with the authored horizon on
**where the irreversible blast radius is**: 11/19 authored entries involve a
capability the measure independently flags high-danger (the actuation/sink side — external
sends, executes, deletes), and it surfaces 15 cross-agent compositions on its own. But it
recovers **0/19 under the strict both-premises test**, and the reason is informative, not a
bug to tune away: the authored compositions pair a high-danger **sink** with an upstream
**poisoning write**, and a write is intrinsically more *reversible* than a send, so the
measure rates the silent-corruption half *below* threshold. Per-capability irreversibility
× blast-radius captures the dangerous *actuation*, but **not** the compositional fact that a
benign-looking upstream corruption makes that actuation harmful — which is exactly the harm
the **epistemic layer** (Thread 1) is built to catch. The two derived signals are
complementary: intrinsic dangerousness covers the irreversible-sink axis; the epistemic
"falsification-capable" notion covers the silent-corruption axis (and is itself ~80%
structurally derivable: 57/71 from "write/modify/delete a faithfulness-bearing artifact
with no verification capability present").

**Scope (do not overstate).** Detection and certification still depend on a horizon;
intrinsic dangerousness is a **prototype**, not a solved replacement. The derived↔authored
overlap is partial *by construction of an honest measure* — we did not tune the weights to
manufacture agreement. The finding is twofold: (i) the authored horizon is **not arbitrary**
— a large fraction of it aligns with an independent irreversibility×blast-radius signal and
~80% of the falsification-capable set is structurally derivable; (ii) the residual gap
(compositional / silent-corruption danger) is precisely what the hyperedge formalism and the
epistemic layer add over a per-capability score — an argument *for* the architecture, not a
circularity.

---

**Paper-structure recommendation.** Promote Appendix F (the epistemic layer) into the main
body as a **fourth contribution**. It is the strongest novelty, the best rebuttal to "this
is just taint tracking," and — per Thread 1 — the clearest evidence the detector catches
danger outside the authored horizon. A validated new detection class should not be buried in
an appendix.

Artifacts: `intrinsic_danger.py`, `intrinsic_danger_results.json`; epistemic results in
`epistemic_eval.json` (Appendix F).
