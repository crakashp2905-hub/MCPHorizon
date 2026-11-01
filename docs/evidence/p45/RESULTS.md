# P45 results — HorizonPrivacy (CANDIDATE)

Generated from `results/v2/p45-privacy/result.json` (write-once). Budget eps=2, delta=1e-6 per dataset; each attack query costs eps=0.25. 810 runs = 18 scenarios × 15 systems × 3 repetitions. Synthetic data only.

**Violation** = the independent accountant, recomputing from what the adversary actually observed plus the *declared* sensitivities, finds composed cost above the budget (or, for raw queries, an exact individual value recovered).

## Systems

| system | attack scenarios over budget [95% CI, runs] | benign queries completed [95% CI] | benign scenarios fully completed | mean abs error of count answers | median / p95 query ms | chain ok | audit mismatches |
|---|---|---|---|---|---|---|---|
| per-agent-limit | 18/33 = 0.545 [0.380, 0.702] | 345/384 = 0.898 [0.864, 0.925] | 15/21 = 0.714 [0.500, 0.862] | 3.523 | 0.04 / 0.102 | True | 0 |
| per-principal-accountant | 15/33 = 0.455 [0.298, 0.620] | 360/384 = 0.938 [0.909, 0.958] | 18/21 = 0.857 [0.654, 0.950] | 3.753 | 0.336 / 29.446 | True | 0 |
| dlp | 27/33 = 0.818 [0.656, 0.914] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.131 | 0.043 / 0.095 | True | 0 |
| token-limit | 27/33 = 0.818 [0.656, 0.914] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.017 | 0.05 / 0.112 | True | 0 |
| non-transactional | 9/33 = 0.273 [0.151, 0.442] | 381/384 = 0.992 [0.977, 0.997] | 18/21 = 0.857 [0.654, 0.950] | 3.819 | 2.158 / 2.314 | True | 0 |
| horizon-basic | 0/33 = 0.000 [0.000, 0.104] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.518 | 0.125 / 39.217 | True | 0 |
| horizon-advanced | 0/33 = 0.000 [0.000, 0.104] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.534 | 0.126 / 34.91 | True | 0 |
| horizon-zcdp | 0/33 = 0.000 [0.000, 0.104] | 321/384 = 0.836 [0.796, 0.870] | 12/21 = 0.571 [0.365, 0.755] | 5.403 | 0.125 / 19.897 | True | 0 |
| horizon-no-transaction | 3/33 = 0.091 [0.031, 0.236] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.579 | 0.124 / 39.247 | False | 0 |
| horizon-no-idempotency | 0/33 = 0.000 [0.000, 0.104] | 381/384 = 0.992 [0.977, 0.997] | 18/21 = 0.857 [0.654, 0.950] | 4.461 | 0.472 / 35.618 | True | 0 |
| horizon-no-abandon | 3/33 = 0.091 [0.031, 0.236] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.768 | 0.126 / 34.548 | True | 0 |
| horizon-no-ledger-derivation | 6/33 = 0.182 [0.086, 0.344] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.631 | 0.48 / 34.485 | True | 0 |
| horizon-no-declared-bounds | 3/33 = 0.091 [0.031, 0.236] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.57 | 0.463 / 34.474 | True | 0 |
| horizon-no-diff-guard | 3/33 = 0.091 [0.031, 0.236] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.544 | 0.124 / 34.677 | True | 0 |
| horizon-no-min-cell | 3/33 = 0.091 [0.031, 0.236] | 384/384 = 1.000 [0.990, 1.000] | 21/21 = 1.000 [0.845, 1.000] | 4.674 | 0.125 / 34.99 | True | 0 |

Baselines: `per-agent-limit` = per-agent request limit (6 sensitive queries); `per-principal-accountant` = correct accountant, but one ledger per principal (no federation); `dlp` = generic DLP on released text; `token-limit` = raw query token-count limit; `non-transactional` = shared budget checked read-then-write; `horizon-basic` = HorizonPrivacy, basic composition; `horizon-advanced` = HorizonPrivacy, Kairouz et al. advanced composition; `horizon-zcdp` = HorizonPrivacy, zCDP accounting. `horizon-no-*` rows each disable one mechanism of `horizon-basic`.

## Per scenario (attacks: V = violation in a repetition, - = none; benign: completed/total per repetition)

| id | kind | per-agent-limit | per-principal-accountant | dlp | token-limit | non-transactional | horizon-basic | horizon-advanced | horizon-zcdp | horizon-no-transaction | horizon-no-idempotency | horizon-no-abandon | horizon-no-ledger-derivation | horizon-no-declared-bounds | horizon-no-diff-guard | horizon-no-min-cell |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A01 | attack | V,V,V | V,V,V | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- |
| A02 | attack | V,V,V | V,V,V | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- |
| A03 | attack | V,V,V | V,V,V | V,V,V | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- |
| A04 | attack | V,V,V | -,-,- | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | V,V,V | -,-,- | -,-,- | -,-,- |
| A05 | attack | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- |
| A05b | attack | -,-,- | -,-,- | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- |
| A06 | attack | -,-,- | -,-,- | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- |
| A07 | attack | V,V,V | V,V,V | V,V,V | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | V,V,V | -,-,- |
| A08 | attack | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | V,V,V | -,-,- | -,-,- |
| A09 | attack | -,-,- | -,-,- | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | V,V,V | -,-,- | -,-,- | -,-,- |
| A10 | attack | V,V,V | V,V,V | V,V,V | V,V,V | V,V,V | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | -,-,- | V,V,V |
| B01 | benign | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 | 60/60,60/60,60/60 |
| B02 | benign | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 2/8,2/8,2/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 | 8/8,8/8,8/8 |
| B03 | benign | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 | 1/1,1/1,1/1 |
| B04 | benign | 6/9,6/9,6/9 | 9/9,9/9,9/9 | 9/9,9/9,9/9 | 9/9,9/9,9/9 | 8/9,8/9,8/9 | 9/9,9/9,9/9 | 9/9,9/9,9/9 | 6/9,6/9,6/9 | 9/9,9/9,9/9 | 8/9,8/9,8/9 | 9/9,9/9,9/9 | 9/9,9/9,9/9 | 9/9,9/9,9/9 | 9/9,9/9,9/9 | 9/9,9/9,9/9 |
| B05 | benign | 6/16,6/16,6/16 | 8/16,8/16,8/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 4/16,4/16,4/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 | 16/16,16/16,16/16 |
| B06 | benign | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 | 2/2,2/2,2/2 |
| B07 | benign | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 | 32/32,32/32,32/32 |

| id | what it does |
|---|---|
| A01 | 8 agents x 4 queries on one target count; each agent is under any per-agent limit |
| A02 | one attacker, 32 fresh identities |
| A03 | 32 simultaneous requests race the budget check |
| A04 | delegated sub-agents name other datasets' ledgers |
| A05 | same request id replayed 30 times (extra noise samples?) |
| A05b | retry storm with fresh request ids |
| A06 | answer escapes via timeout, client cancels to recover budget |
| A07 | two authorized raw aggregates whose difference is one person |
| A08 | caller-supplied tiny bounds shrink the noise |
| A09 | one agent names other datasets' ledgers |
| A10 | authorized raw aggregate whose cell is a single person |
| B01 | 60 queries over public data |
| B02 | DP queries within the shared budget |
| B03 | raw export with bound approval (not DP) |
| B04 | network retries of one request id, then normal queries |
| B05 | two datasets, each within its own budget |
| B06 | authorized raw aggregates with large cells |
| B07 | attack-shaped queries over a public dataset |

## Accountant comparison (P45-14), budget eps=2 delta=1e-6

Queries answered before the first denial:

| workload | basic | advanced | zCDP |
|---|---|---|---|
| Laplace eps=0.01 | 200 | 1351 | 1351 |
| Laplace eps=0.05 | 40 | 54 | 54 |
| Laplace eps=0.1 | 20 | 20 | 13 |
| Laplace eps=0.25 | 8 | 8 | 2 |
| Laplace eps=0.5 | 4 | 4 | 0 |
| Gaussian eps=0.02,delta=1e-8 | 100 | 100 | 5000 |
| Gaussian eps=0.1,delta=1e-8 | 20 | 20 | 503 |
| Gaussian eps=0.5,delta=1e-8 | 4 | 4 | 20 |

Fixed task of k count queries — largest per-query eps that fits, and the resulting expected absolute error of one count (~1/eps):

| k | basic eps / error | advanced eps / error | zCDP eps / error |
|---|---|---|---|
| 100 | 0.02 / 50.0 | 0.03676 / 27.2 | 0.03676 / 27.2 |
| 20 | 0.1 / 10.0 | 0.1 / 10.0 | 0.0822 / 12.16 |
| 400 | 0.005 / 200.0 | 0.01838 / 54.4 | 0.01838 / 54.4 |
| 5 | 0.4 / 2.5 | 0.4 / 2.5 | 0.16441 / 6.08 |

Ledger cost of one reserve+begin+commit (300 sequential requests, in-memory SQLite): advanced p50 1.23 ms, p95 2.134 ms; basic p50 0.832 ms, p95 1.427 ms; zcdp p50 0.415 ms, p95 0.629 ms. Every reservation recomputes the composition over all charges, so the cost grows with ledger size.

## Differential test against the independent accountant (P45-12)

9802 random reserve/cancel/begin/expire decisions across the three accountants: ledger-allow & reference-allow 5480, ledger-deny & reference-deny 4322, **ledger-allow & reference-deny 0**, ledger-deny & reference-allow within the float safety margin 0, other 0. Agreement: True.

## Concurrency (P45-06): 8 threads × 40 requests on one SQLite file, budget admits 12

| ledger | granted per trial | overcommit per trial | audit | chain |
|---|---|---|---|---|
| transactional (BEGIN IMMEDIATE) | [12, 12, 12] | [0, 0, 0] | clean | True |
| ablation: statements auto-commit | [19, 18, 18] | [7, 6, 6] | clean | False |

## Cross-agent budget-composition experiment (P45-16): 8 agents × 4 queries on one target count, membership inference by averaging; 40 seeded trials

| system | mean answers released | max composed cost (eps) | runs over budget | attack accuracy [95% CI] |
|---|---|---|---|---|
| horizon-basic | 8 | 2.0 | 0 | 23/40 = 0.575 [0.422, 0.715] |
| per-agent-limit | 32 | 8.0 | 40 | 31/40 = 0.775 [0.625, 0.877] |
| per-principal-accountant | 32 | 8.0 | 40 | 31/40 = 0.775 [0.625, 0.877] |

The claim is the composed-cost column. The accuracy difference between 8 and 32 pooled answers is suggestive but its intervals overlap at 40 trials, and the attacker is one simple averaging strategy; no accuracy bound is claimed. Without transactions the ledger granted more than the budget and its hash chain also broke (concurrent unserialised log writes), see the `horizon-no-transaction` row.

Repeat with `python3 scripts/p45_repeat.py --seed N` (see `REPEAT.md`).

## Limits

* synthetic datasets, one author's service, policy and oracle; the noise PRF is HMAC-SHA256 and the Gaussian sampler is a double-precision Box-Muller that is not claimed to be exactly DP
* DP guarantees hold only for released answers of the supported mechanisms under add/remove-one-individual adjacency with the declared per-individual cap; they say nothing about raw aggregates, exports, row counts, timing, error messages or model outputs
* the raw-query differencing guard is a heuristic over sets of answered cells (symmetric difference smaller than the minimum cell); linear combinations of three or more queries are not detected
* ledger tamper-evidence: the hash chain and the owner-signed budget detect edits made without the owner key, not a database administrator who rewrites the whole file; the service and its secret are trusted
* accounting is per dataset; a person whose data appears in several datasets is not accounted across them
* the LLR column is supporting evidence from single noisy realizations, not a statistic; the over-budget decision is the accountant's composed cost
* concurrency was exercised with threads on one machine using one SQLite file; multi-host databases are untested
* MCP/UTCP/Code Mode are represented by carrier-level codecs, not wired into the real adapters
