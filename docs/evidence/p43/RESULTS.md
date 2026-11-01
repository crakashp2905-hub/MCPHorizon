# P43 results — HorizonMutation (CANDIDATE)

Generated from `results/v2/p43-mutation/result.json` (write-once). Ground truth V comes from a two-way oracle: bytes really sent to loopback receivers (journal written by a separate process) and a labeled-lineage computation; disagreement or an unobserved send is UNKNOWN and never scored. Authority is the declared graph rule (see taxonomy doc).

Seed 43. 12 seed graphs (6 root causal families × attack/benign twin); 214 depth-1 + 160 depth-2 mutants; 0 candidates rejected by preconditions; 101 real sends, 285 answered from the memo of an earlier identical real send. Oracle status over all mutants: {'OK': 344, 'UNKNOWN': 30}. UNKNOWN reasons: {'lineage-vs-bytes': 10, 'partial-sanitizer': 20}.

## Generators compared (P43-13/14)

| generator | generated | oracle OK | confirmed violating | diversity (distinct effect paths / OK) | unique failure modes found in D1,D2,D2b,D3 | invalid rate | UNKNOWN rate | semantic-preservation error | preservation accuracy | flip accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| fixed_handcrafted | 12 | 12 | 6 | 0.833 | 9 | — | — | — | — | — |
| horizon_mutation_before_dedup | 374 | 344 | 115 | 0.250 | 51 | 0.000 [0.000, 0.010] | 0.083 [0.059, 0.115] | 0.010 [0.003, 0.037] | 0.990 [0.963, 0.997] | 0.462 [0.363, 0.563] |
| horizon_mutation_constrained | 92 | 77 | 14 | 1.000 | 16 | 0.000 [0.000, 0.040] | 0.174 [0.110, 0.264] | 0.000 [0.000, 0.092] | 1.000 [0.908, 1.000] | 0.571 [0.391, 0.735] |
| lexical_perturbation | 80 | 80 | 34 | 0.125 | 9 | 0.000 [0.000, 0.046] | 0.000 [0.000, 0.046] | 0.000 [0.000, 0.046] | 1.000 [0.954, 1.000] | — |
| llm_generator | — | — | — | — | — | — | — | — | — | — |
| unconstrained_scripted_random_NOT_AN_LLM | 160 | 113 | 56 | 0.159 | 9 | 0.287 [0.223, 0.362] | 0.006 [0.001, 0.035] | 0.076 [0.035, 0.156] | 0.924 [0.844, 0.965] | 0.147 [0.065, 0.301] |

* `fixed_handcrafted`: the 12 seeds. `lexical_perturbation`: payload-text prefixes only. `unconstrained_scripted_random`: a random graph editor with no preconditions — a **scripted stand-in, not an LLM**; NOT RUN: no live model in this environment; no number is reported.
* Predicted relation is a syntax heuristic; "preservation accuracy" = of mutants predicted SAME, the share where the oracle's V is equal; "flip accuracy" = of predicted CHANGE, the share where it differs; "semantic-preservation error" = predicted SAME but V changed.

### Per operator (constrained generator, after dedup; predicted→observed)

| operator | counts |
|---|---|
| OP-DEST-CHANGE | CHANGE->CHANGE: 6, CHANGE->SAME: 4, SAME->SAME: 8 |
| OP-PROTO-SWAP | SAME->SAME: 5, unknown: 1 |
| OP-ROLE-TRANSFER | pred_unknown: 5 |
| OP-SANITIZE-INSERT | CHANGE->CHANGE: 9, CHANGE->SAME: 8, SAME->SAME: 25, pred_unknown: 5, unknown: 15 |
| OP-TEMPORAL-DELAY | CHANGE->CHANGE: 1 |

## Dedup (P43-10)

374 mutants in; 260 exact duplicates by semantic effect path (dest, transform chain, approval class at execution and at decision, authority tier); 22 near duplicates (Jaccard ≥ 0.9 on graph features, same family and same V); 92 kept.

## Policies under test (kept, oracle-OK mutants)

| policy | recall on confirmed violations | benign disruption (false block) | median decision µs |
|---|---|---|---|
| D1-lexical | 6/14 = 0.429 [0.214, 0.674] | 1/63 = 0.016 [0.003, 0.085] | 5.6 |
| D2-lineage-v1 | 13/14 = 0.929 [0.685, 0.987] | 4/63 = 0.064 [0.025, 0.152] | 1.6 |
| D2b-lineage-v2 | 14/14 = 1.000 [0.785, 1.000] | 0/63 = 0.000 [0.000, 0.058] | 2.5 |
| D3-restrictive | 14/14 = 1.000 [0.785, 1.000] | 38/63 = 0.603 [0.480, 0.715] | 2.4 |

On the 12 fixed seeds alone: D1-lexical recall 0.667, disruption 0.333; D2-lineage-v1 recall 1.000, disruption 0.167; D2b-lineage-v2 recall 1.000, disruption 0.000; D3-restrictive recall 1.000, disruption 0.667.

### Ablation (overlapping evidence)

| configuration | recall | benign disruption |
|---|---|---|
| D2+D3 (overlapping evidence) | 1.000 [0.785, 1.000] | 0.667 [0.544, 0.770] |
| D2-lineage-v1 | 0.929 [0.685, 0.987] | 0.064 [0.025, 0.152] |
| D2b-lineage-v2 | 1.000 [0.785, 1.000] | 0.000 [0.000, 0.058] |
| D3-restrictive | 1.000 [0.785, 1.000] | 0.603 [0.480, 0.715] |

### Unique failure modes (policy, error, last operator, family)

* D1-lexical / FALSE_BLOCK / OP-PROTO-SWAP / F-APPROVAL
* D1-lexical / MISSED_VIOLATION / OP-DEST-CHANGE / F-DERIVED
* D1-lexical / MISSED_VIOLATION / OP-DEST-CHANGE / F-MULTIHOP
* D1-lexical / MISSED_VIOLATION / OP-SANITIZE-INSERT / F-APPROVAL
* D1-lexical / MISSED_VIOLATION / OP-SANITIZE-INSERT / F-DIRECT
* D2-lineage-v1 / FALSE_BLOCK / OP-SANITIZE-INSERT / F-BRANCH
* D2-lineage-v1 / MISSED_VIOLATION / OP-TEMPORAL-DELAY / F-APPROVAL
* D3-restrictive / FALSE_BLOCK / OP-DEST-CHANGE / F-DERIVED
* D3-restrictive / FALSE_BLOCK / OP-DEST-CHANGE / F-MULTIHOP
* D3-restrictive / FALSE_BLOCK / OP-PROTO-SWAP / F-APPROVAL
* D3-restrictive / FALSE_BLOCK / OP-PROTO-SWAP / F-DERIVED
* D3-restrictive / FALSE_BLOCK / OP-SANITIZE-INSERT / F-APPROVAL
* D3-restrictive / FALSE_BLOCK / OP-SANITIZE-INSERT / F-DELEGATED
* D3-restrictive / FALSE_BLOCK / OP-SANITIZE-INSERT / F-DERIVED
* D3-restrictive / FALSE_BLOCK / OP-SANITIZE-INSERT / F-DIRECT
* D3-restrictive / FALSE_BLOCK / OP-SANITIZE-INSERT / F-MULTIHOP

## Family split vs random split (P43-11), policy D4 learns violating sink signatures

Dev families ['F-DIRECT', 'F-DERIVED', 'F-DELEGATED', 'F-BRANCH']; test families ['F-APPROVAL', 'F-MULTIHOP']; family overlap between sides: none.

| split | signatures learned | recall on dev side | recall held out | false-block held out |
|---|---|---|---|---|
| family split, deduplicated | 6 | 1.000 [0.610, 1.000] | 0.500 [0.215, 0.785] | 0.130 [0.045, 0.321] |
| random split, deduplicated | 4 | 1.000 [0.610, 1.000] | 0.250 [0.071, 0.591] | 0.115 [0.040, 0.290] |
| family split, raw (near-duplicates kept) | 6 | 1.000 [0.950, 1.000] | 0.786 [0.641, 0.883] | 0.274 [0.185, 0.386] |
| random split, raw (near-duplicates kept) | 9 | 1.000 [0.943, 1.000] | 1.000 [0.930, 1.000] | 0.258 [0.188, 0.343] |

Held-out sets are small (see n in the rates); the raw random split shows leakage from near-duplicate mutants of the same seed, which the family split removes.

## Matched attack/benign pairs (P43-12)

14 oracle-confirmed pairs (attack V=true, twin V=false, identical tool-name multiset); edits used: {'OP-DEST-CHANGE': 14}.

| policy | pairs where attack blocked AND twin allowed |
|---|---|
| D1-lexical | 0.429 [0.214, 0.674] |
| D2-lineage-v1 | 0.929 [0.685, 0.987] |
| D2b-lineage-v2 | 1.000 [0.785, 1.000] |
| D3-restrictive | 1.000 [0.785, 1.000] |

## Regression minimizer (P43-15)

| failing case | nodes original | nodes padded | nodes minimal | evaluations | oracle V unchanged | policy still misses | 1-minimal |
|---|---|---|---|---|---|---|---|
| M0121-f3937e | 2 | 6 | 2 | 8 | True | True | True |

## Limits

* seeds, operators, detectors and the authorization rule are all written by the same author; failure modes found are those of author-written detectors, not of any third-party policy engine
* oracle effect is observed (loopback receiver process) but authority is DECLARED in the graph; a wrong declared rule is a wrong ground truth
* the byte oracle knows single derived forms (raw, reverse, hex, rot13, b64 middle); stacked transforms and partial sanitizers make bytes and lineage disagree and are labelled UNKNOWN, not scored
* operator predictions are syntax heuristics; semantic-preservation error rate is the measured disagreement with the oracle, and is nonzero by construction for the low-confidence operators
* the unconstrained baseline is a scripted random editor, not a language model; no LLM generator was run and none is claimed
* family split uses 4 dev and 2 test families; drops are measured on a tiny number of families
* detector latency is a single-process microbenchmark of Python functions on a toy graph, not a production policy engine
* the shared loopback receiver journals at end-of-headers; a POST written in two segments lost its body about 1 in 2000 sends. P43 writes each request in one segment (0 in 6000 afterwards). Earlier phases that sent POSTs with urllib are exposed to the same rare race; their frozen results are not re-run
* 12 seeds across 6 families: coverage claims apply to these causal families only
