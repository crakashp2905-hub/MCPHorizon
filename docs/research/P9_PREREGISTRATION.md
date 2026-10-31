# P9 pre-registration (P9-01) — written before the P9 study was run

**Honesty note on status.** SecBench 0.1 dev/test results for `open`, `labels_only` and `full` had already been seen when this was written, and the 0.2 "S" templates were designed after seeing that a simple baseline (B3) matched `full` on 0.1. Therefore **no result here is confirmatory**. The SecBench 0.2 test split is *not* a clean held-out set. A confirmatory run needs a new, independently authored held-out split (not possible from this single-author setup; see Gate G6 below).

## Systems
B0 `open`; B1 `name_heuristic`; B2 `b2_allowlist` (endpoint allowlist); B3 `b3_read_send_pair` (block any send in a run that read a SECRET source); B4 `b4_exact_taint` (block verbatim SECRET values); `labels_only` (P3 service + gates); `full` (+ lineage boundary + epistemic ledger); ablations `full-no-boundary`, `full-no-ledger`, `full-no-manual-trust`. Scripted agents; **no LLM, so P9-02/P9-19 model/temperature/seed items do not apply.**

## Hypotheses (primary metric = attacker success on harmful scenarios; secondary = benign utility), test split, paired by scenario
- H1: `full` has lower attacker success than B0, B1, B2, B4 (exact McNemar, Holm-corrected over the four, alpha 0.05) with risk difference at least 0.25.
- H2: `full` has lower attacker success than `labels_only` (risk difference at least 0.10).
- H3: `full` retains benign utility of at least 0.80 on the test split.
- H4 (competitor hypothesis): `full` is not better than B3 on attack success; its advantage, if any, is benign utility on sensitive-but-benign (S) workflows.
- Ablations (exploratory): removing the boundary, ledger or manual-trust check increases attacker success or loses benign utility on the templates that exercise it.

## Thresholds and rules
Effect thresholds as above; intervals: Wilson 95% per rate, template-cluster bootstrap 95% for paired risk differences (4000 resamples, seed 7). Denominators: all scenarios attempted for the system; refused/blocked count as attack-prevented and as benign-utility loss; TIMEOUT/ERROR are reported separately and count as neither success nor utility. A claim is "supported" only if the Holm-adjusted p is below 0.05 AND the cluster-bootstrap interval excludes 0; otherwise it is reported as not supported.

## Gate G6
Not opened by this phase: needs an independent held-out set, independent annotation (P8-17), real-LLM agents and external review.
