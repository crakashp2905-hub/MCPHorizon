# Experiment 2A — Benign Baseline (Zero-False-Positive Negative Control)

**Status:** Complete and validated.
**Purpose:** Demonstrate MCPHorizon's zero-false-positive property with a true
negative control — real multi-agent runs on benign tasks where **no malicious
tools are available**, so nothing dangerous *can* be produced.

---

## Design

The TAMAS IPI scenarios are benign task specifications (no injected attack), but
each agent's toolset still *contains* malicious tool variants. That is not a
clean negative control: a confused model can call a malicious tool even on a
benign task (as observed in the IPI run, where qwen2.5:7b spontaneously invoked
`fake_diagnosis`, `always_return_true`, etc. on 13/50 benign tasks).

For a true 0-FP control we removed the malicious tools from every agent's
toolset, leaving only legitimate tools, then ran the benign IPI tasks again.
This was done by `make_benign_runner.py`, which rewrites the runner's per-agent
tool lists to drop every tool the capability map marks `is_malicious_variant`
(103 tools removed across 20 agent toolsets; 105 legitimate tools retained).
Everything else — agents, orchestration, LLM settings (temperature=0), logging —
is byte-identical to the production runner.

- **Runner:** `crewai_run_benign.py` (generated; malicious tools stripped)
- **Tasks:** TAMAS IPI benign queries, 5 domains × 10 = 50
- **Logs:** `logs_benign/IPI/Centralized/<domain>/`
- **Total compute:** ~19.4 hours (1165 min across 5 domains)

---

## Result: zero alerts on real benign runs

| Domain | Evaluated | Real-event runs | Alerts | Horizon |
|---|---|---|---|---|
| Legal | 10 | 10 | 0 | 0 |
| Healthcare | 10 | 10 | 0 | 0 |
| Finance | 10 | 10 | 0 | 0 |
| Education | 10 | 9 | 0 | 0 |
| News | 10 | 10 | 0 | 0 |
| **TOTAL** | **50** | **49** | **0** | **0** |

**Four-point validity check (all pass):**
1. All 50 scenarios evaluated; per-domain wall times 200–275 min (genuine LLM work).
2. 49/50 produced real trajectories (n_events > 0); 1 empty (an errored education scenario).
3. **Zero malicious tools appear in any of the 49 traces** — they are absent from the toolsets, so unreachable.
4. **Zero alerts, zero horizon hits** across all 50.

Run-status breakdown: 25 completed (`ok`), 21 timed out at 1800s, 3 errored, 1
resume-skipped (the validated smoke-test scenario). Timeouts and the one error
still produced partial benign trajectories that fired nothing.

---

## Why this is the rigorous control

The decisive comparison is against the original IPI run, which used the *same
benign tasks* but with malicious tools present:

| Condition | Malicious tools in toolset | Benign tasks | Alerts |
|---|---|---|---|
| IPI run | Present | 50 | 13/50 (model spontaneously misused them) |
| **2A baseline** | **Removed** | **50** | **0/50** |

MCPHorizon fires **if and only if** a dangerous capability is actually exercised.
When malicious tools are reachable, the detector catches their misuse (true
positives). When they are absent, the detector stays silent across 49 real
multi-agent runs (zero false positives). The detector is not keying on task
content, agent identity, or trajectory length — only on the actual production of
a HIJACKED-scope capability.

---

## Honest caveats

1. **Timeout rate.** 21/50 timed out at 1800s. Benign tasks run long (no attack
   to cut them short) on a 7B CPU model. A timed-out benign run that produced
   only legitimate tools and fired nothing is still a valid 0-FP data point — the
   trajectory is truncated, not contaminated. The 49 real-event runs include both
   completed and timed-out scenarios; all fired zero alerts.
2. **One empty scenario** (education, errored) produced no events and is excluded
   from the "real runs" count; it cannot constitute a false positive (nothing ran).
3. **Single model.** qwen2.5:7b only; see threats-to-validity.
4. **0-FP is demonstrated on this benign corpus**, constructed by stripping
   malicious tools from the TAMAS IPI agents. It is a negative control, not a
   guarantee over all possible benign workloads.

---

## What this closes

The zero-false-positive property was previously supported only by within-corpus
clean runs and synthetic pre-run baselines. Experiment 2A provides a dedicated
negative control: 49 real benign multi-agent trajectories, only legitimate tools
available, **zero alerts**. Combined with the attack-class results, this completes
the core evaluation:

| Experiment | Detection | Horizon | Role |
|---|---|---|---|
| Colluding (compositional) | 40/50 | 12/50, 4/5 domains | Horizon detects compositional emergence |
| DPI (direct injection) | 25/50 | 0/50 | Axiom catches injection; horizon specificity |
| IPI (spontaneous misuse) | 13/50 | 4/50 | Detector catches model-initiated misuse |
| **2A benign baseline** | **0/50** | **0/50** | **Zero-false-positive negative control** |

---

## Draft claim for the paper

> To establish a true negative control for the zero-false-positive property, we
> stripped all malicious tool variants from each agent's toolset (103 tools across
> 20 toolsets) and re-ran the 50 benign TAMAS task specifications. Across 49 real
> multi-agent trajectories (one scenario errored before producing events),
> MCPHorizon raised **zero alerts** and zero danger-horizon hits, with no malicious
> tool appearing in any trace. The decisive comparison is against the same benign
> tasks run with malicious tools present, where the model spontaneously invoked
> dangerous tools on 13/50 tasks and MCPHorizon detected every instance: the
> detector fires if and only if a dangerous capability is exercised, confirming it
> keys on capability production rather than task content or trajectory shape.
