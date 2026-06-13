# Generalization Report — LOOCV mode

```
==============================================================================
LOOCV Generalization Report
==============================================================================

Holding out each attack class and measuring detection rate on the
held-out partition. This tests whether the parametric lattice
generalizes to attack classes whose specific instances were not
used to inform hyperedge design.

Held-out class                   Test  Train  Clean     Rate
------------------------------------------------------------------------------
benign_baseline                     2    203      0    0.0%
compositional_emergence             3    202      3  100.0%
scope_corruption                   59    146     59  100.0%
sequence_injection                141     64     97   68.8%

```

## Per-class detailed breakdown

### Held out: `benign_baseline`

- Test: 2, Train (informational): 203
- Detection rate: **0.0%** (0/0)

### Held out: `compositional_emergence`

- Test: 3, Train (informational): 202
- Detection rate: **100.0%** (3/3)

### Held out: `scope_corruption`

- Test: 59, Train (informational): 146
- Detection rate: **100.0%** (59/59)

### Held out: `sequence_injection`

- Test: 141, Train (informational): 64
- Detection rate: **68.8%** (97/141)

