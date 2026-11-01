# HCCB: failures, null results, confounding (MG-G6/G7)

Subjects are **scripted toy generators**, not real models (no live code model was available). The experiment validates the pipeline; it says nothing about any real model's context sensitivity, and nothing about developer intent (MG-G2).

## What the committed run shows (`results/v2/p33-hccb`, 800 cells per generator = 4 tasks × 5 context modifiers × 20 seeds + the same for the second generator)
- **context_sensitive** (planted gap: persona_a 0.10, persona_b 0.50 of cells vulnerable): the pipeline recovers it: persona_a vs persona_b risk difference −0.26, Newcombe-Wilson 95% CI [−0.38, −0.13], Holm-adjusted p < 0.001. The irrelevant-modifier negative control (irrelevant_a vs irrelevant_b) is null.
- **invariant** (no planted dependence, 0.25 in every group): after Holm correction **no contrast is significant**, but the *uncorrected* persona_a vs persona_b p is 0.023 and its task-cluster bootstrap interval excludes 0. This is a chance fluctuation we report on purpose: it is why correction across contrasts is pre-specified, and why one uncorrected p must not be read as a finding.
- The exploit oracle agreed with the toy ground-truth variant on every functionally-correct artifact (confirmed vulnerable = toy vulnerable), as it must since the toy's vulnerable variants are the P28 fixtures.
- The scanner (bandit) missed a substantial share of oracle-confirmed vulnerabilities (false negatives per group in `result.json`; classes without a bandit pattern, e.g. authz logic and traversal here, are invisible) and raised no false positives on these fixtures. Static findings are scanner claims, never confirmed severity.

## Confounders and threats
- **Toy circularity:** the same author wrote the generators, the fixtures, the oracle and the policies. Recovery of a planted gap shows the statistics work, not that real models behave this way.
- **Few task clusters:** only 4 tasks. The task-cluster bootstrap intervals are therefore narrow and optimistic; prefer the Newcombe/Fisher results and treat bootstrap as a sensitivity check.
- **Functional filter selection:** rates are computed among functionally-correct artifacts. Differential functional failure by group would bias the contrast; completion rate by group is reported alongside (≈ 94-99% here).
- **Cache by source hash:** identical sources share one evidence record (correct for deterministic scanners/oracles, but it means the 800 cells contain only 12 distinct programs).
- **Single scanner, single language, 4 vulnerability classes**, local ephemeral services only.
- **Adjudication:** the protocol (two masked reviewers, a third for ties, unresolved counted) is implemented and tested, but **no human reviewer has labelled anything**; no inter-rater result exists.
