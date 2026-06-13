# Tool-Surface Generalization

```
==============================================================================
Tool-Surface Generalization Report
==============================================================================

Stratifying detection rate by the resource surface each attack
targets. Surfaces with high detection demonstrate the lattice's
structural coverage; surfaces with low detection identify
residual gaps in either tool DB or hyperedge set.

Surface               Total  In-scope  Clean     Rate
------------------------------------------------------------------------------
calendar                  3         3      3  100.0%
code_execution            7         7      7  100.0%
contacts                  3         3      3  100.0%
database                  3         3      3  100.0%
email                    30        30     30  100.0%
environment               6         6      6  100.0%
messaging                15        15     15  100.0%
network                  40        39     36   92.3%
repo                     16        16     13   81.2%
filesystem               46        45     32   71.1%
other                     2         2      1   50.0%
external_service         31        31     10   32.3%
generic                   3         3      0    0.0%

Macro-average across 13 surfaces: 79.0%
Worst-case surface: generic at 0.0%
Best-case surface: calendar at 100.0%

```

## Per-surface per-class breakdown

| Surface | Class | Clean | Total | Rate |
|---|---|---|---|---|
| calendar | sequence_injection | 2 | 2 | 100.0% |
| calendar | scope_corruption | 1 | 1 | 100.0% |
| code_execution | scope_corruption | 3 | 3 | 100.0% |
| code_execution | sequence_injection | 4 | 4 | 100.0% |
| contacts | sequence_injection | 3 | 3 | 100.0% |
| database | sequence_injection | 3 | 3 | 100.0% |
| email | scope_corruption | 4 | 4 | 100.0% |
| email | sequence_injection | 26 | 26 | 100.0% |
| environment | sequence_injection | 6 | 6 | 100.0% |
| external_service | sequence_injection | 6 | 27 | 22.2% |
| external_service | scope_corruption | 4 | 4 | 100.0% |
| filesystem | sequence_injection | 20 | 33 | 60.6% |
| filesystem | scope_corruption | 9 | 9 | 100.0% |
| filesystem | compositional_emergence | 3 | 3 | 100.0% |
| generic | sequence_injection | 0 | 3 | 0.0% |
| messaging | sequence_injection | 8 | 8 | 100.0% |
| messaging | scope_corruption | 7 | 7 | 100.0% |
| network | scope_corruption | 25 | 25 | 100.0% |
| network | sequence_injection | 11 | 14 | 78.6% |
| other | sequence_injection | 0 | 1 | 0.0% |
| other | scope_corruption | 1 | 1 | 100.0% |
| repo | sequence_injection | 8 | 11 | 72.7% |
| repo | scope_corruption | 5 | 5 | 100.0% |
