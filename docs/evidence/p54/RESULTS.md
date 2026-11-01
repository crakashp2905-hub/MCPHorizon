# P54 results — integration and assurance (CANDIDATE)

Generated from `results/v2/p54-integration/result.json` (write-once). This phase adds **no new mechanism**: it audits, freezes, joins and re-checks the evidence of P39–P53. Nothing here is VERIFIED, and a PASS below means only that the named checks held on the candidate evidence in this repository.

## ES-G1..ES-G16

| gate | status | what it requires | failed checks | note |
|---|---|---|---|---|
| ES-G1 | **PASS** | Existing P0-P38 evidence audit and immutable baseline hashes | — | 99 of 710 tasks have no mapped command and are labelled BLOCKED for new security claims |
| ES-G2 | **FAIL** | Unified identities and effect semantics reused across modules | no_signer_or_authority_created_outside_fixtures_and_evidence_services | files in the P39-P53 packages that create their own signer or authority outside a fixture or evidence service: horizon/coverage/regress.py, horizon/obligation/diff.py, horizon/reach/network.py, horizon/vision/browser_run.py |
| ES-G3 | **FAIL** | Provenance and effect oracle distinguishes data transfer from tool coexistence | P39_oracle_independent_of_system_code | P39 has only 2 true leaks; the static check finds its oracle importing the system's Endpoints model |
| ES-G4 | **PASS** | Verified emergent candidate in synthetic environment with matched safe control | — | candidate only; small suites written by the same author |
| ES-G5 | **PASS** | Typed obligation prevents commit after omitted or stale prerequisite | — | — |
| ES-G6 | **PASS** | Counterfactual detects broad unauthorized change but permits correct scoped change | — | — |
| ES-G7 | **PASS** | Monitor declares UNKNOWN on simulated blind spot | — | — |
| ES-G8 | **PASS** | Mutation oracle distinguishes true verdict-preserving vs flipping variants | — | — |
| ES-G9 | **PASS** | Indirect remote effects evaluated with appropriate trust and visibility | — | P44 prevented 42 of 45 attack runs; the rest are negative findings, not hidden |
| ES-G10 | **PASS** | Privacy/budget ledger prevents concurrent task overspend | — | P50 keeps one UNKNOWN reservation charged after a failure |
| ES-G11 | **PASS** | Fallback, migration and temporal checks preserve the mandatory security floor | — | P53 U02 (deceived attestor) is a known trust gap; P52 unsupported paths are flagged UNKNOWN, not prevented |
| ES-G12 | **PASS** | Verified approval binds to exact committed effect | — | — |
| ES-G13 | **PASS** | Browser tests use trusted origin plus server-side effect oracle | — | P51 benign completed 9 of 11 (B09, B11 blocked); the browser run is recorded, not re-run here |
| ES-G14 | **PASS** | Adversarial evaluator tampering yields UNKNOWN or verified rejection | — | X01 (all collectors omit consistently) is outside P49's assumptions and is a known false PASS |
| ES-G15 | **PASS** | All modules have paired controls, fair baselines and statistical/error reports | — | — |
| ES-G16 | **SKIP** | Independent clean-environment reproduction and exact scope-limited claims | — | needs a person outside this session to check out the repository and rerun; same-machine reproduction is recorded under `reproduction` but is not independent |

13 PASS, 2 FAIL, 1 SKIP. FAIL entries are real findings about this repository and are not worked around.

## P0–P38 prerequisites (P54-01) and the freeze (P54-02)

611 of 710 original task IDs have a command in `spec/acceptance.json`; the other **99 are BLOCKED** for new security claims. Mapped does not mean verified.

| phase | mapped / total | status |
|---|---|---|
| P0 | 0 / 20 | BLOCKED |
| P1 | 14 / 20 | BLOCKED-PARTIAL |
| P2 | 23 / 24 | BLOCKED-PARTIAL |
| P3 | 15 / 20 | BLOCKED-PARTIAL |
| P4 | 20 / 22 | BLOCKED-PARTIAL |
| P5 | 21 / 24 | BLOCKED-PARTIAL |
| P6 | 24 / 26 | BLOCKED-PARTIAL |
| P7 | 24 / 24 | COMPLETE-MAPPED |
| P8 | 21 / 22 | BLOCKED-PARTIAL |
| P9 | 17 / 24 | BLOCKED-PARTIAL |
| P10 | 19 / 24 | BLOCKED-PARTIAL |
| P11 | 11 / 20 | BLOCKED-PARTIAL |
| P12 | 0 / 18 | BLOCKED |
| P13 | 14 / 16 | BLOCKED-PARTIAL |
| P14 | 12 / 14 | BLOCKED-PARTIAL |
| P15 | 14 / 14 | COMPLETE-MAPPED |
| P16 | 16 / 16 | COMPLETE-MAPPED |
| P17 | 14 / 14 | COMPLETE-MAPPED |
| P18 | 16 / 16 | COMPLETE-MAPPED |
| P19 | 14 / 14 | COMPLETE-MAPPED |
| P20 | 14 / 14 | COMPLETE-MAPPED |
| P21 | 14 / 14 | COMPLETE-MAPPED |
| P22 | 12 / 18 | BLOCKED-PARTIAL |
| P23 | 18 / 18 | COMPLETE-MAPPED |
| P24 | 14 / 18 | BLOCKED-PARTIAL |
| P25 | 18 / 18 | COMPLETE-MAPPED |
| P26 | 18 / 18 | COMPLETE-MAPPED |
| P27 | 18 / 18 | COMPLETE-MAPPED |
| P28 | 18 / 18 | COMPLETE-MAPPED |
| P29 | 18 / 18 | COMPLETE-MAPPED |
| P30 | 17 / 18 | BLOCKED-PARTIAL |
| P31 | 16 / 16 | COMPLETE-MAPPED |
| P32 | 16 / 16 | COMPLETE-MAPPED |
| P33 | 16 / 16 | COMPLETE-MAPPED |
| P34 | 16 / 16 | COMPLETE-MAPPED |
| P35 | 15 / 16 | BLOCKED-PARTIAL |
| P36 | 16 / 16 | COMPLETE-MAPPED |
| P37 | 16 / 16 | COMPLETE-MAPPED |
| P38 | 12 / 16 | BLOCKED-PARTIAL |

`results/v2/p54-integration/freeze.json` holds the digest of the 710 task-ID list and a sha256 of every file under `results/v2/` (except P54's own) as of the start of P54. `python3 scripts/p54_run.py --check` fails if any of them changes.

## Paired headline per module (recorded results, Wilson 95%)

Each pair is the module's own: attacks prevented / attack runs, and benign tasks completed / benign runs (for the three detection/coverage modules: detected / true positives, and correctly passed / benign). Counts are scenarios, not independent trials; every suite was written by the author of the module and its baselines.

| module | family | headline system | attacks prevented [CI] | benign completed [CI] | notes |
|---|---|---|---|---|---|
| P39 HorizonEmergence | detection | emergence | 2/2 [0.34, 1.00] | 216/220 [0.95, 0.99] | pair = detected leaks / true leaks; benign = correctly passed safe chains |
| P40 HorizonObligation | guard | runtime | 42/42 [0.92, 1.00] | 33/33 [0.90, 1.00] | — |
| P41 HorizonCounterfactual | guard | counterfactual | 42/42 [0.92, 1.00] | 30/30 [0.89, 1.00] | — |
| P42 HorizonCoverage | coverage | horizon_coverage | 11/11 [0.74, 1.00] | 1/1 [0.21, 1.00] | pair = detected loss of assurance / injected regressions; benign = healthy control without false alarm |
| P43 HorizonMutation | detection | D2b-lineage-v2 | 14/14 [0.78, 1.00] | 63/63 [0.94, 1.00] | pair = detected verdict flips / oracle-confirmed flips; benign = verdict-preserving variants passed |
| P44 HorizonReach | guard | reach | 42/45 [0.82, 0.98] | 36/36 [0.90, 1.00] | — |
| P45 HorizonPrivacy | guard | horizon-advanced | 33/33 [0.90, 1.00] | 384/384 [0.99, 1.00] | — |
| P46 HorizonDowngrade | guard | guard | 36/36 [0.90, 1.00] | 21/21 [0.85, 1.00] | 9 of 36 attack runs were stopped without completing |
| P47 HorizonIncentive | guard | monitor | 39/39 [0.91, 1.00] | 21/21 [0.85, 1.00] | — |
| P48 HorizonConsent | guard | consent | 21/21 [0.85, 1.00] | 8/8 [0.68, 1.00] | — |
| P49 HorizonEvalIntegrity | evaluation-integrity | evalint | 16/16 [0.81, 1.00] | 6/6 [0.61, 1.00] | 9 of 16 compromised runs were UNKNOWN (unverifiable), not PASS |
| P50 HorizonBudget | guard | budget | 11/11 [0.74, 1.00] | 8/8 [0.68, 1.00] | — |
| P51 HorizonVisionGuard | guard | vision-guard | 11/11 [0.74, 1.00] | 9/11 [0.52, 0.95] | benign blocked: B09, B11 |
| P52 HorizonTemporal | guard | temporal | 13/13 [0.77, 1.00] | 10/10 [0.72, 1.00] | — |
| P53 HorizonContinuity | guard | continuity | 14/14 [0.78, 1.00] | 10/10 [0.72, 1.00] | — |

| family | modules | attacks prevented (pooled, descriptive) | benign completed (pooled, descriptive) |
|---|---|---|---|
| coverage | P42 | 11/11 [0.74, 1.00] | 1/1 [0.21, 1.00] |
| detection | P39, P43 | 16/16 [0.81, 1.00] | 279/283 [0.96, 0.99] |
| evaluation-integrity | P49 | 16/16 [0.81, 1.00] | 6/6 [0.61, 1.00] |
| guard | P40, P41, P44, P45, P46, P47, P48, P50, P51, P52, P53 | 304/307 [0.97, 1.00] | 570/572 [0.99, 1.00] |

Pooling across modules mixes different scenario sets and is shown only so the families can be compared at a glance.

## Negative findings (P54-14)

| module | finding | source |
|---|---|---|
| P39 | P39: 4 of 220 benign runs did not complete (headline system emergence) | `results/v2/p39-emergence/result.json` |
| P44 | P44: 3 of 45 attack runs were NOT prevented (headline system reach) | `results/v2/p44-reach/result.json` |
| P51 | P51: 2 of 11 benign runs did not complete (headline system vision-guard) | `results/v2/p51-vision/result.json` |
| P44 | some forbidden destinations were reached: attacks prevented are less than all attack runs | `results/v2/p44-reach/result.json` |
| P46 | a quarter of attack runs ended without completing the task (the guard stopped them; the task was not done) | `results/v2/p46-downgrade/result.json` |
| P47 | benign runs with a justified denial exist: the monitor refused something the contract really forbade | `results/v2/p47-incentive/result.json` |
| P49 | under compromise a share of runs are UNVERIFIABLE rather than PASS: the module declines to vouch for them, it does not recover the truth | `results/v2/p49-evalint/result.json` |
| P50 | failure runs leave reservations in an UNKNOWN state that stay charged | `results/v2/p50-budget/result.json` |
| P51 | two benign tasks (B09, B11) are blocked by the guard | `results/v2/p51-vision/result.json` |
| P52 | paths the gateway does not support (U01, U02) are only flagged UNKNOWN, not prevented | `results/v2/p52-temporal/result.json` |
| P53 | U02 (a deceived attestor) is a known trust gap: reported, not prevented | `results/v2/p53-continuity/trust_gaps.json` |

## One receipt service, oracle independence, authority sites (P54-05, P54-09)

All 15 modules get a receipt from one `ReceiptService` (one issuer, role `receipts`, kind ATTESTATION on the shared `HorizonPolicy`); `INTACT` means the recorded result and the oracle and system files still hash as when the receipt was issued. It is evidence integrity only.

| module | receipt | oracle files reach system-under-test code (static, transitive intra-package imports) |
|---|---|---|
| P39 | INTACT | **yes**: horizon/emergence/oracle.py → model |
| P40 | INTACT | no |
| P41 | INTACT | no |
| P42 | INTACT | no |
| P43 | INTACT | no |
| P44 | INTACT | no |
| P45 | INTACT | no |
| P46 | INTACT | no |
| P47 | INTACT | no |
| P48 | INTACT | no |
| P49 | INTACT | no |
| P50 | INTACT | no |
| P51 | INTACT | no |
| P52 | INTACT | no |
| P53 | INTACT | no |

Signers/authorities created in `horizon/` outside the shared authority: 33 sites. By role: evidence-service: 2 files; fixture: 14 files; other: 6 files. **Not fixtures or evidence services (duplicate authority until proven otherwise): `horizon/agents/isolation.py`, `horizon/coverage/regress.py`, `horizon/obligation/diff.py`, `horizon/reach/network.py`, `horizon/telemetry/collector.py`, `horizon/vision/browser_run.py`.**

## Protocol equivalence (P54-06)

60 generated workflows over mcp_modern, mcp_legacy, utcp, code_mode (shared decision function; verdict may not depend on protocol). Discrepancies: 13, of which unexpected (not in `results/v2/p14-parity/expected_discrepancies.json`): **0**. The expected one is `utcp/PAYLOAD_ENCODING`: UTCP serializes the body as JSON, so the same target and verdict carry different bytes. Metamorphic URL-spelling violations: 0. Alias traps allowed: 0 of 4. Non-equivalent fixtures all flagged: True. Carrier codec round trip (P50): codemode, mcp, os, utcp. Browser adapter: recorded in results/v2/p51-vision-browser/browser.json, not re-run here. Native adapters: none available in this environment.

## Concurrency, replay and retry (P54-11)

| check | ok | detail |
|---|---|---|
| budget: concurrent reserves never exceed the cap | True | {"expected": 10, "granted": 10} |
| budget: a retried request id is charged once; a reused id with another query is refused | True | {"reuse_reason": "REQUEST_ID_REUSE", "used": {"compute_units": 30}} |
| privacy: concurrent reserves never exceed epsilon | True | {"expected": 8, "granted": 8} |
| temporal: with CAS exactly one concurrent writer wins and no update is lost | True | {"winners": 1} |
| temporal (control): last-writer-wins loses updates, so the oracle can see them | True | {"lost": 3} |
| continuity: a replayed signed envelope is refused and spends the shared budget once | True | {"first": "MIGRATED", "replay": "ROLLED_BACK", "violations": []} |
| continuity: a source that keeps running after migration is stopped (no double spend) | True | {"status": "MIGRATED", "violations": []} |

## Lost coverage and tampered evaluator records (P54-10)

* P49 evaluator, every scenario where the run really violated policy and the stated assumptions hold: **17 violating runs, 0 false PASS**; verdicts seen: FAIL, UNVERIFIABLE.
* Outside P49's assumptions: X01 → PASS. X01 (all three collectors omit consistently) is outside the stated assumptions of P49; it is a known false PASS and is reported, not counted.
* Control: the four weaker graders on the same runs give false PASS counts app-logging 11/17, audit-no-root-sep 6/17, self-report 16/17, shared-grader 17/17.
* Receipt verdicts under edited evidence: expired → UNKNOWN, intact → INTACT, none → UNKNOWN, oracle_edited → TAMPERED, other_authority → UNKNOWN, other_module → UNKNOWN, result_edited → TAMPERED, system_edited → TAMPERED.
* P53 with the revocation feed offline and the handle revoked: prohibited effect False, flagged UNKNOWN True; benign migration with the feed offline completed: False (it rolls back: safe, but not available).
* Recorded, not re-run: P42 detected 11 of 11 injected regressions with healthy-control false alarm False; P52 telemetry-offline: attack violated False, benign completed False.

## Reproduction on this machine (P54-07, P54-08, P54-13)

Same machine, same author. **Not** the independent clean-checkout review of P54-16.

| module | level | ok | what ran |
|---|---|---|---|
| P39 | definitions-only + module tests | True | `--check`: definitions match recorded run; tests: 26 passed, 1 deselected in 1.74s |
| P40 | definitions-only + module tests | True | `--check`: definitions match recorded run; tests: 41 passed, 1 deselected in 10.61s |
| P41 | definitions-only + module tests | True | `--check`: definitions match recorded run; tests: 29 passed, 1 deselected in 16.15s |
| P42 | definitions-only + module tests | True | `--check`: definitions match recorded run; tests: 36 passed, 8 deselected in 91.07s (0:01:31) |
| P43 | rerun | True | fresh run's paired headline equals the recorded one |
| P44 | rerun | True | fresh run's paired headline equals the recorded one |
| P45 | rerun | True | fresh run's paired headline equals the recorded one |
| P46 | rerun | True | fresh run's paired headline equals the recorded one |
| P47 | rerun | True | fresh run's paired headline equals the recorded one |
| P48 | rerun | True | fresh run's paired headline equals the recorded one |
| P49 | rerun | True | fresh run's paired headline equals the recorded one |
| P50 | rerun | True | fresh run's paired headline equals the recorded one |
| P51 | rerun | True | fresh run's paired headline equals the recorded one |
| P52 | rerun | True | fresh run's paired headline equals the recorded one |
| P53 | rerun | True | fresh run's paired headline equals the recorded one |

## Static review (P54-12)

* Calls to eval/exec/compile/subprocess/os.system/pickle/shell=True in `horizon/`: **23**, in 17 files (the process-based sandboxes, mock receivers and the code-mode executor spawn local helper processes by design; `horizon/downgrade/gateway.py` uses exec/compile for its rule engine). Listed in `result.json`.
* Hostnames appearing as string literals in library code that are not reserved/synthetic: `json-schema.org` (horizon/schema_defs.py), `pypi.org` (horizon/runtime/artifacts.py) (both are documentation or schema identifiers, not fetched; `scripts/p30_no_external.py` is the enforcing scan).
* Secret scan, no-external-contact scan, inventory and README freeze are checked by CI, not re-derived here.
