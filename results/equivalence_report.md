# Datalog ↔ Python Equivalence Report

Empirical proof of Spera's theorem (adapted): closure_python ≡ closure_datalog on every trajectory.

| Corpus | Trajectories | Matches | Mismatches | Pass rate |
|---|---|---|---|---|
| MCPTox (205 trajectories) | 205 | 205 | 0 | 100.0% |
| MCPSecBench (13 trajectories) | 13 | 13 | 0 | 100.0% |

## Timing

| Corpus | Python (ms) | Datalog (ms) | Python/Datalog ratio |
|---|---|---|---|
| MCPTox (205 trajectories) | 21.0 | 16.5 | 1.27x |
| MCPSecBench (13 trajectories) | 0.9 | 0.6 | 1.48x |

## MCPTox (205 trajectories): no mismatches — equivalence verified

## MCPSecBench (13 trajectories): no mismatches — equivalence verified
