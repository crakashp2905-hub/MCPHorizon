# §6 with variance — execution variance, not detector variance

> **The detector is deterministic given events.** The released tool reproduces all **150/150** per-scenario verdicts from recorded events (§6.8); identical events always yield identical verdicts. **Every interval below is EXECUTION variance** — the stochastic CrewAI + `qwen2.5:7b` orchestration produces different (agent, tool) traces across runs — and contains *zero* detector variance.

## Two uncertainty components

- **Within-run bootstrap 95% CI** (computed): percentile bootstrap over scenarios (per-domain n=10, per-class n=50; 10,000 resamples). This is finite-benchmark *sampling* uncertainty — "had we drawn a different set of same-type scenarios."
- **Across-run execution variance** (under-characterized): re-running the *same* scenarios under identical settings yields different counts because the 7B model stochastically takes the bait. Genuine independent re-runs are on record only for one cell (below); a full n≥5 study of all 150 scenarios (~750 live multi-agent runs at 10–25 min each ≈ weeks of CPU, with frequent timeouts) was not feasible here and is specified as future work.

**Key caveat (do not over-trust the bootstrap).** At boundary cells the within-run bootstrap *under-states* the true uncertainty. Colluding/finance detection is 10/10, so the bootstrap CI is a degenerate [100%–100%] — yet a genuine fresh re-run of the same 10 scenarios produced **8/10** (and horizon 3/10 → 5/10). The real interval is wider than the bootstrap wherever a count sits at 0 or n.

## Revised §6.1 Colluding table

| Domain | Detection (95% CI) | Danger horizon (95% CI) |
|---|---|---|
| Legal | 6/10 = 60% [30%–90%] | 0/10 = 0% [0%–0%] |
| Healthcare | 10/10 = 100% [100%–100%] | 6/10 = 60% [30%–90%] |
| Finance | 10/10 = 100% [100%–100%] | 3/10 = 30% [0%–60%] |
| Education | 7/10 = 70% [40%–100%] | 1/10 = 10% [0%–30%] |
| News | 9/10 = 90% [70%–100%] | 2/10 = 20% [0%–50%] |
| **Total** | **42/50 = 84% [74%–94%]** | **12/50 = 24% [12%–36%]** |

*Across-run note (finance):* two genuine independent CrewAI executions of the 10 finance scenarios gave detection [10, 8] and horizon [3, 5] — material run-to-run variation the within-run CI does not capture (detection bootstraps to [100%–100%]).

## Revised §6.2 DPI table

| Domain | Detection (95% CI) | Danger horizon (95% CI) |
|---|---|---|
| Legal | 4/10 = 40% [10%–70%] | 0/10 = 0% [0%–0%] |
| Healthcare | 8/10 = 80% [50%–100%] | 0/10 = 0% [0%–0%] |
| Finance | 3/10 = 30% [0%–60%] | 0/10 = 0% [0%–0%] |
| Education | 4/10 = 40% [10%–70%] | 0/10 = 0% [0%–0%] |
| News | 7/10 = 70% [40%–100%] | 0/10 = 0% [0%–0%] |
| **Total** | **26/50 = 52% [38%–66%]** | **0/50 = 0% [0%–0%]** |

## Revised §6.4 IPI table

| Domain | Detection (95% CI) | Danger horizon (95% CI) |
|---|---|---|
| Legal | 4/10 = 40% [10%–70%] | 1/10 = 10% [0%–30%] |
| Healthcare | 4/10 = 40% [10%–70%] | 2/10 = 20% [0%–50%] |
| Finance | 4/10 = 40% [10%–70%] | 1/10 = 10% [0%–30%] |
| Education | 0/10 = 0% [0%–0%] | 0/10 = 0% [0%–0%] |
| News | 2/10 = 20% [0%–50%] | 0/10 = 0% [0%–0%] |
| **Total** | **14/50 = 28% [16%–40%]** | **4/50 = 8% [2%–16%]** |

## Honest status of the across-run study

Genuine independent re-runs exist only for Colluding/finance (2 runs). The locked vs map-corrected counts elsewhere are the SAME execution re-scored, not independent runs, so they do NOT measure execution variance. A full n>=5 across-run study of all 150 scenarios (~750 live multi-agent runs at 10-25 min each on CPU) was not feasible in this environment; it is specified as future work. The within-run bootstrap CIs above are the rigorous, computable uncertainty and already show the point estimates over-claim precision.

**Reporting recommendation.** Present §6 counts as `k/n` with the within-run 95% CI, and state plainly that (a) all variance is execution variance (the detector is deterministic, 150/150), and (b) the across-run component is under-characterized and can exceed the bootstrap at boundary cells, pending an n≥5 study. Do not report the per-domain counts (n=10) as if they were precise to the unit.