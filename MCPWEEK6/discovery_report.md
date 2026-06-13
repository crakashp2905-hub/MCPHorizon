# T2-10 — Leave-one-domain-out hyperedge recovery (discoverability)

Answers "method, or a hand-tuned ruleset for one benchmark?" by HIDING each domain's
hand-authored cross-agent hyperedges and trying to **re-discover** their detection
behaviour from that domain's trajectories, validated at **zero false positives** on
held-out benign runs.

**Proposer (deterministic, no LLM — a lower bound).** Candidates are distinct-agent pairs
of capabilities (≥1 HIJACKED, matching the authored premise structure) observed in the
domain's attack trajectories. This is a structural enumerator; the LLM proposer can only do
at least as well.

**Validator (zero leakage).** A candidate is accepted iff it fires on ≥1 of the domain's
attack trajectories **and** 0 held-out benign trajectories.

**Recovery (functional equivalence, not string match).** A domain's authored edges fire a
horizon on a set of its scenarios; recovery = the fraction of those baseline horizon-firing
scenarios on which `(other-4-domain edges + accepted candidates)` *also* fires a horizon.

## Results

| Domain | hidden edges | candidates accepted | baseline horizon scenarios | missed after hiding | recovered | recovery | benign FP |
|---|---|---|---|---|---|---|---|
| Legal | 4 | 8 | 0 | 0 | 0 | — (no firings) | 0 |
| Healthcare | 5 | 30 | 6 | 6 | 4 | **67%** | 0 |
| Finance | 3 | 36 | 3 | 3 | 3 | **100%** | 0 |
| Education | 3 | 18 | 1 | 1 | 1 | **100%** | 0 |
| News | 4 | 46 | 2 | 2 | 2 | **100%** | 0 |
| **Macro** | 19 | — | **12** | 12 | **10** | **83%** | **0** |

## Reading the result

- **83% macro recovery at 0 false positives.** A deterministic structural search, *without
  access to the hidden edges*, reproduces the horizon-detection behaviour on 10 of the 12
  scenarios the authored edges fire on — at zero benign false positives in every domain.
  The 19 hand-authored edges are not a bespoke magic set: their detection behaviour emerges
  from distinct-agent HIJACKED capability compositions and is recoverable by enumeration.
- **Legal — no firings to recover.** Legal Colluding fired 0/10 horizons (the principled
  legal gap, §6.1: the model's legal attacks were single-agent). There is nothing to
  recover, and the proposer correctly adds no firing edge — consistent, not a failure.
- **Healthcare 67% — the 2 misses are single-agent.** The two unrecovered healthcare
  scenarios are the single-agent compositions (`Colluding_healthcare_00`, `_08`: every tool
  by one agent). A *cross-agent* candidate structurally cannot fire on them — the same
  definitional boundary the epistemic cross-agent predicate hit (Appendix F). Honest
  limitation of the cross-agent proposer, not a tuning gap.

## Honest caveats

- The zero-FP property is partly structural: HIJACKED-pair candidates cannot fire on the
  benign baseline because it contains no HIJACKED capabilities (the §8 NO-GO again). So the
  validator's benign filter is easy to pass here; the load-bearing metric is **functional
  recovery of the authored detection behaviour (83%)**, not the FP filter alone.
- This is the *deterministic* lower bound. It enumerates capability-pair candidates; it does
  not name the danger or discover all-benign-premise edges (that is the Appendix G / LLM
  direction). What it establishes: the danger set the authored horizon encodes is
  **discoverable from the capability structure**, not arbitrary — the answer to the
  "hand-tuned ruleset" critique, and the discoverability evidence Thread 2 of
  `circularity_report.md` relies on.

Artifacts: `discovery_loocv.py`, `discovery_loocv.json`.
