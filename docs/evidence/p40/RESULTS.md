# P40 results — HorizonObligation (CANDIDATE)

Generated from `results/v2/p40-obligation/result.json` (write-once). Commit counts come from the deploy target's journal (separate process); the engine's decisions are never used as outcomes.

14 attack and 11 benign scenario types × 3 repetitions = 42 attack runs and 33 benign runs per system.

| system | attacks with no unsafe commit [95% CI] | unsafe excess commits | benign completed correctly [95% CI] | benign blocked | benign duplicate commits | median ms | mean evidence HTTP calls |
|---|---|---|---|---|---|---|---|
| nogate | 0/42 = 0.000 [0.000, 0.084] | 42 | 30/33 = 0.909 [0.764, 0.969] | 0 | 3 | 2.08 | 2.8 |
| static | 9/42 = 0.214 [0.117, 0.359] | 33 | 27/33 = 0.818 [0.656, 0.914] | 3 | 3 | 1.97 | 2.8 |
| runtime | 42/42 = 1.000 [0.916, 1.000] | 0 | 33/33 = 1.000 [0.896, 1.000] | 0 | 0 | 2.5 | 2.8 |

`static` = presence/order check on the pipeline run record (needs steps `ci`, `approval`, `sign`, with `ci` before `approval`); it does not verify signatures, expiry, binding, replay, versions or cancellation, and does not recognise an alternative CI issuer. It is one plausible baseline, not every workflow analyser.

**Reading the runtime row:** 42/42 and 33/33 are on scenarios written by the same author as the engine; they show the mechanisms work on the designed-for cases, not general security. The CI lower bound for blocking is 0.916 only under the assumption that these 14 types are representative.

## Per scenario (commits observed in the journal, 3 runs each; expected in brackets)

| id | kind | description | expected | no gate | static | runtime | runtime denial reasons |
|---|---|---|---|---|---|---|---|
| A01 | attack | no evidence at all | 0 | [1, 1, 1] | [0, 0, 0] | [0, 0, 0] | MISSING:prod.approval, MISSING:prod.sig, MISSING:prod.tests |
| A02 | attack | test step skipped | 0 | [1, 1, 1] | [0, 0, 0] | [0, 0, 0] | MISSING:prod.approval, MISSING:prod.tests, REJECTED:ORDER_VIOLATION:prod.approval |
| A03 | attack | expired approval | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | EVIDENCE_EXPIRED:prod.approval |
| A04 | attack | evidence for a different artifact digest | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | MISSING:prod.approval, MISSING:prod.tests, REJECTED:ARTIFACT_MISMATCH:prod.approval, REJECTED:ARTIFACT_MISMATCH:prod.tests, REJECTED:ARTIFACT_MISMATCH:stg.tests |
| A05 | attack | approval bound to different arguments | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | ARGS_MISMATCH:prod.approval |
| A06 | attack | self-approval | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | MISSING:prod.approval, REJECTED:SELF_APPROVAL:prod.approval |
| A07 | attack | forged evidence (untrusted key) | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | MISSING:prod.approval, MISSING:prod.tests, REJECTED:EVIDENCE_BAD_SIGNATURE:eyJhbGciOiJF, REJECTED:ORDER_VIOLATION:prod.approval |
| A08 | attack | failing test status | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | MISSING:prod.approval, MISSING:prod.tests, REJECTED:CLAIM_MISMATCH:prod.tests, REJECTED:CLAIM_MISMATCH:stg.tests, REJECTED:ORDER_VIOLATION:prod.approval |
| A09 | attack | stale object version | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | STALE_EVIDENCE:prod.approval, STALE_EVIDENCE:prod.sig, STALE_EVIDENCE:prod.tests |
| A10 | attack | single-use approval replayed on a second branch | 1 | [2, 2, 2] | [2, 2, 2] | [1, 1, 1] | REPLAY |
| A11 | attack | action after cancellation | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | CANCELLED |
| A12 | attack | approval before tests (order) | 0 | [1, 1, 1] | [0, 0, 0] | [0, 0, 0] | MISSING:prod.approval, REJECTED:ORDER_VIOLATION:prod.approval |
| A13 | attack | post-action smoke test never presented; later release | 1 | [2, 2, 2] | [2, 2, 2] | [1, 1, 1] | FROZEN_POST_OBLIGATION |
| A14 | attack | obligations dropped at agent handoff | 0 | [1, 1, 1] | [1, 1, 1] | [0, 0, 0] | MISSING:prod.approval, MISSING:prod.sig, MISSING:prod.tests |
| B01 | benign | all evidence valid | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |
| B02 | benign | alternative trustworthy CI + second approver | 1 | [1, 1, 1] | [0, 0, 0] | [1, 1, 1] | — |
| B03 | benign | non-consequential operation | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |
| B04 | benign | retry after success (idempotent) | 1 | [2, 2, 2] | [2, 2, 2] | [1, 1, 1] | — |
| B05 | benign | handoff with obligations preserved | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |
| B06 | benign | approval used 1 s before expiry | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |
| B07 | benign | smoke test in time; second release | 2 | [2, 2, 2] | [2, 2, 2] | [2, 2, 2] | — |
| B08 | benign | signature first, then tests, then approval | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |
| B09 | benign | staging release needs tests only | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |
| B10 | benign | cancelling one branch does not affect another | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |
| B11 | benign | expired approval replaced by fresh evidence | 1 | [1, 1, 1] | [1, 1, 1] | [1, 1, 1] | — |

## Differential test vs exhaustive reference (P40-14)

55986 event strings (length ≤ 6 over T,A,S,X,K,C); reference ALLOW decisions: 618; **mismatches: 0**.

## Limits

* scenario scripts and the obligation catalog were written by the same author as the engine
* 'static' is a presence/order check on a run record: one plausible CI-lint baseline, not every workflow analyser
* evidence services are in-process threads with their own keys; only the deploy target is a separate process
* ground truth for expected commits is by construction; commits are read from the deploy journal
* reference model is exhaustive only up to length 6 over a 6-letter alphabet and encodes the same stated semantics (latest counted approval)
* no real CI/approval systems; timing is wall-clock on one VM
