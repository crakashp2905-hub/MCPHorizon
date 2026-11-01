# P39 results — HorizonEmergence (CANDIDATE, synthetic, loopback only)

Generated from `results/v2/p39-emergence/result.json` (write-once). Outcomes come from the receiver journal (separate process); model predictions are never used as labels.

## Labeled corpus

252 minimal source→transform*→sink chains; **4 leak** to the unapproved endpoint B per the journal; 12 are *oracle-blind* (nested encodings the receiver cannot recognise) and are not scored.

## Detectors on the same chains (P39-13)

| detector | TP | FP | FN | TN | UNKNOWN (leaked) | recall [95% CI] | FPR [95% CI] |
|---|---|---|---|---|---|---|---|
| D0 | 0 | 0 | 4 | 236 | 0 (0) | 0.000 [0.000, 0.490] | 0.000 [0.000, 0.016] |
| D3 | 4 | 116 | 0 | 120 | 0 (0) | 1.000 [0.510, 1.000] | 0.491 [0.428, 0.555] |
| direct_taint | 2 | 16 | 2 | 220 | 0 (0) | 0.500 [0.150, 0.850] | 0.068 [0.042, 0.107] |
| emergence | 2 | 4 | 0 | 216 | 18 (2) | 1.000 [0.342, 1.000] | 0.018 [0.007, 0.046] |
| emergence_refined | 2 | 0 | 0 | 232 | 6 (2) | 1.000 [0.342, 1.000] | 0.000 [0.000, 0.016] |

Strict reading: counting UNKNOWN as *not detected*, emergence catches 2 of 4 leaking chains (the other 2 sit behind unmodeled endpoint C).

UNKNOWN is reported separately and is neither an alert nor a pass. Only 4 chains leak, so recall intervals are wide: **the corpus cannot distinguish recall differences among detectors that catch all modeled leaks.** The `emergence` false positives are all `weak_sanitize` chains the model conservatively treats as taint-preserving; `emergence_refined` applies one oracle-derived refinement (evidence = one disproved chain) and is evaluated on the other chains, but the refinement is scoped to the oracle's variant set — weak_sanitize still leaks a *partial* string.

## Discovery recall and verified-candidate precision vs search budget (P39-14)

40 seeded worlds (random op/target subsets), 27 positive. Unguided = mean over 5 seeds (a world counts as found if ≥ half the seeds found it). Budget = evaluated (state, action) transitions.

### guided

| budget | recall (found/positive) [95% CI] | verified | disproved | verified precision [95% CI] |
|---|---|---|---|---|
| 5 | 0.741 (20/27) [0.553, 0.868] | 20 | 0 | 1.000 [0.839, 1.000] |
| 10 | 0.926 (25/27) [0.766, 0.979] | 25 | 0 | 1.000 [0.867, 1.000] |
| 20 | 0.926 (25/27) [0.766, 0.979] | 26 | 1 | 0.963 [0.817, 0.993] |
| 40 | 0.926 (25/27) [0.766, 0.979] | 30 | 8 | 0.789 [0.636, 0.889] |
| 80 | 0.926 (25/27) [0.766, 0.979] | 38 | 13 | 0.745 [0.611, 0.845] |
| 160 | 0.926 (25/27) [0.766, 0.979] | 38 | 16 | 0.704 [0.572, 0.809] |
| 320 | 0.926 (25/27) [0.766, 0.979] | 38 | 28 | 0.576 [0.456, 0.688] |
| 640 | 0.926 (25/27) [0.766, 0.979] | 38 | 40 | 0.487 [0.380, 0.596] |
| 1280 | 0.926 (25/27) [0.766, 0.979] | 38 | 40 | 0.487 [0.380, 0.596] |

### guided+refined

| budget | recall (found/positive) [95% CI] | verified | disproved | verified precision [95% CI] |
|---|---|---|---|---|
| 5 | 0.741 (20/27) [0.553, 0.868] | 20 | 0 | 1.000 [0.839, 1.000] |
| 10 | 0.926 (25/27) [0.766, 0.979] | 25 | 0 | 1.000 [0.867, 1.000] |
| 20 | 0.926 (25/27) [0.766, 0.979] | 26 | 0 | 1.000 [0.871, 1.000] |
| 40 | 0.926 (25/27) [0.766, 0.979] | 30 | 0 | 1.000 [0.886, 1.000] |
| 80 | 0.926 (25/27) [0.766, 0.979] | 38 | 0 | 1.000 [0.908, 1.000] |
| 160 | 0.926 (25/27) [0.766, 0.979] | 38 | 0 | 1.000 [0.908, 1.000] |
| 320 | 0.926 (25/27) [0.766, 0.979] | 38 | 0 | 1.000 [0.908, 1.000] |
| 640 | 0.926 (25/27) [0.766, 0.979] | 38 | 0 | 1.000 [0.908, 1.000] |
| 1280 | 0.926 (25/27) [0.766, 0.979] | 38 | 0 | 1.000 [0.908, 1.000] |

### unguided

| budget | recall (found/positive) [95% CI] | verified | disproved | verified precision [95% CI] |
|---|---|---|---|---|
| 5 | 0.000 (0/27) [0.000, 0.125] | 7 | 0 | 1.000 [0.646, 1.000] |
| 10 | 0.111 (3/27) [0.038, 0.281] | 29 | 0 | 1.000 [0.883, 1.000] |
| 20 | 0.926 (25/27) [0.766, 0.979] | 122 | 0 | 1.000 [0.970, 1.000] |
| 40 | 0.926 (25/27) [0.766, 0.979] | 131 | 3 | 0.978 [0.936, 0.992] |
| 80 | 0.926 (25/27) [0.766, 0.979] | 151 | 22 | 0.873 [0.815, 0.914] |
| 160 | 0.926 (25/27) [0.766, 0.979] | 189 | 72 | 0.724 [0.667, 0.775] |
| 320 | 0.926 (25/27) [0.766, 0.979] | 190 | 77 | 0.712 [0.655, 0.763] |
| 640 | 0.926 (25/27) [0.766, 0.979] | 190 | 139 | 0.578 [0.523, 0.630] |
| 1280 | 0.926 (25/27) [0.766, 0.979] | 190 | 195 | 0.493 [0.444, 0.543] |

## Unknown and unmodeled capability (P39-15)

Positive worlds whose only leak path goes through endpoint C, whose delegation the analyst did not model: **W28, W30**. The search reports C paths as UNKNOWN (18 unknown chains in the corpus run), never as safe and never as verified. Scope assumption: endpoints A and B are modeled exactly; C is unmodeled; the real receiver redirects on every port, which only the oracle sees.

## Witness (P39-16)

Candidate `read_secret → b64 → get:A/redir->B` was discovered by the search and verified by the journal (leak to B: **True**). Matched safe control: same endpoint and shape with `hash` in place of `b64` — leak to B: **False** (B still received a connection: 1).

## Limits

* synthetic loopback endpoints and one canary
* oracle variant set misses nested encodings (oracle_blind chains unscored) and partial leaks (weak_sanitize)
* refinement is evidence-scoped to the oracle variant set
* worlds are random op/target subsets of a hand-written library: coverage of designed-for classes only
* positive worlds are rare by construction (4 leaking chains in 252)
