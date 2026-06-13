# Week 2 Lift Report

```
==============================================================================
Week 1 → Week 2 detection lift
==============================================================================

Metric                                                 Week 1          Week 2
------------------------------------------------------------------------------
Tool DB size                                              119            ~208
Hyperedges                                                 13   12 parametric
Capability vocab                                      34 flat 8×33×scope lattice

sequence_injection clean                                    —          97/141
scope_corruption clean (NEW in Week 2)                  0 / —           58/59
compositional_emergence clean                    (synth only)             3/3
benign_baseline (TNR)                                   2 / 2             2/2

IN-SCOPE detection rate                                 70.9%           77.8%
In-scope testable                                         141             203
In-scope clean                                            100             158

VERDICT: PREMISE PARTIALLY HOLDS — lattice helps but architectural gaps remain

Absolute detection lift: +6.9%  (70.9% → 77.8%)
Scope-corruption coverage: 0% (Week 1) → 98.3% (Week 2)

```

## Per-class breakdown

| Attack class | Total | Clean | Untestable | Failed |
|---|---|---|---|---|
| sequence_injection | 141 | 97 | 0 | 44 |
| scope_corruption | 59 | 58 | 0 | 1 |
| compositional_emergence | 3 | 3 | 0 | 0 |
| benign_baseline | 2 | 2 | 0 | 0 |

