# P52 results — HorizonTemporal (CANDIDATE)

Generated from `results/v2/p52-temporal/result.json` (write-once). **Ground truth is the effect service's own record** (a snapshot of live state at the moment of each effect, the approval ledger and the ordered event log), judged by an independent oracle that never calls the gateway. Every scenario is run under **every interleaving** of its actors' steps, so a result is a statement about all orders of that scenario, not a sample. Verified effects (a prohibited effect really happened) and UNKNOWN (the gateway could not know) are reported separately.

Intervals are Wilson over scenarios and descriptive: the suite is small, scripted and written by the same author as the gateway.

## 1865 runs = 27 scenarios × 23 systems (all interleavings)

| system | attacks with a violating interleaving [95% CI] | violating / all attack interleavings | benign completed in every interleaving [95% CI] | benign with a stale effect | benign not completed | unjustified re-approvals | unsupported paths violated | of those, flagged UNKNOWN | revoked approval + feed offline: effect | benign + feed offline |
|---|---|---|---|---|---|---|---|---|---|---|
| one-time-check | 12/13 [0.67, 0.99] | 21/34 | 9/10 [0.60, 0.98] | B02, B06, B10 | B06 | 0 | 2/2 [0.34, 1.00] | 2 | yes | completed |
| jwt-expiry | 12/13 [0.67, 0.99] | 21/34 | 9/10 [0.60, 0.98] | B02, B06 | B06 | 0 | 2/2 [0.34, 1.00] | 2 | yes | completed |
| op-token-no-object | 9/13 [0.42, 0.87] | 18/34 | 10/10 [0.72, 1.00] | B02 | none | 0 | 2/2 [0.34, 1.00] | 2 | yes | completed |
| restrictive-rule | 1/13 [0.01, 0.33] | 2/34 | 3/10 [0.11, 0.60] | none | B01, B02, B03, B04, B05, B09, B10 | 0 | 0/2 [0.00, 0.66] | 0 | no | blocked |
| last-write-wins | 1/13 [0.01, 0.33] | 2/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-actor | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-object-id | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-object-version | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-object-class | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-content | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-grant | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-policy-slice | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-policy-recheck | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-revocation | 1/13 [0.01, 0.33] | 2/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | yes | completed |
| temporal-no-destination | 1/13 [0.01, 0.33] | 2/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-redirect | 1/13 [0.01, 0.33] | 3/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-nonce | 1/13 [0.01, 0.33] | 1/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-expiry | 2/13 [0.04, 0.42] | 2/34 | 10/10 [0.72, 1.00] | B10 | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-authoritative-clock | 1/13 [0.01, 0.33] | 1/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-atomic | 5/13 [0.18, 0.64] | 5/41 | 10/10 [0.72, 1.00] | B02 | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-idempotent | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | no | blocked |
| temporal-no-fail-closed | 0/13 [0.00, 0.23] | 0/34 | 10/10 [0.72, 1.00] | none | none | 0 | 2/2 [0.34, 1.00] | 2 | yes | completed |

| baseline / system | what it does |
|---|---|
| one-time-check | authorized once when the approval was requested; the effect only needs the approval to exist |
| jwt-expiry | signature and expiry only, on the worker's own clock; no state binding, no single use |
| op-token-no-object | token bound to operation, actor and host, single use, authoritative expiry; not bound to the object, its version or the policy |
| restrictive-rule | hand-written: token at most 5 s old, single use, never for queued work |
| last-write-wins | the full gateway but object writes are unconditional |
| temporal | HorizonTemporal: state vector bound into a short-lived approval, revalidated at the effect boundary inside one transaction, destination re-resolved and pinned, redirects checked, fail closed |
| temporal-no-<mechanism> | full gateway with one mechanism disabled |

Re-approvals are counted separately: a re-approval after a real change (B02, B10) is justified and expected; one on an unchanged state would be a false block (column `unjustified re-approvals`).

## Per scenario (`V a/b` = a of b interleavings produce a violation; benign: ok / BLOCKED, `*` = a stale effect occurred in some order; `(UNKNOWN)` = the system flagged it)

| id | kind | one-time-check | jwt-expiry | op-token-no-object | restrictive-rule | last-write-wins | temporal |
|---|---|---|---|---|---|---|---|
| A01 | attack | V2/4 | V2/4 | V2/4 | ok | ok | ok |
| A02 | attack | V2/3 | V2/3 | V2/3 | ok | ok | ok |
| A03 | attack | V2/4 | V2/4 | V2/4 | ok | ok | ok |
| A04 | attack | V2/4 | V2/4 | V2/4 | ok | ok | ok |
| A05 | attack | V1/1 | ok | ok | ok | ok | ok |
| A06 | attack | V1/1 | V1/1 | ok | ok | ok | ok |
| A07 | attack | V2/4 | V2/4 | V2/4 | ok | ok | ok |
| A08 | attack | V3/4 | V3/4 | V3/4 | ok | ok | ok |
| A09 | attack | V1/1 | V1/1 | ok | ok | ok | ok |
| A10 | attack | V2/2 | V2/2 | V2/2 | V2/2 | V2/2 | ok |
| A11 | attack | V1/1 | V1/1 | ok | ok | ok | ok |
| A12 | attack | V2/4 | V2/4 | V2/4 | ok | ok | ok |
| A13 | attack | ok | V1/1 | V1/1 | ok | ok | ok |
| B01 | benign | ok | ok | ok | BLOCKED | ok | ok |
| B02 | benign | ok* | ok* | ok* | BLOCKED | ok | ok |
| B03 | benign | ok | ok | ok | BLOCKED | ok | ok |
| B04 | benign | ok | ok | ok | BLOCKED | ok | ok |
| B05 | benign | ok | ok | ok | BLOCKED | ok | ok |
| B06 | benign | BLOCKED* | BLOCKED* | ok | ok | ok | ok |
| B07 | benign | ok | ok | ok | ok | ok | ok |
| B08 | benign | ok | ok | ok | ok | ok | ok |
| B09 | benign | ok | ok | ok | BLOCKED | ok | ok |
| B10 | benign | ok* | ok | ok | BLOCKED | ok | ok |
| F01 | failure | V2/4 | V2/4 | V2/4 | ok | ok(UNKNOWN) | ok(UNKNOWN) |
| F02 | failure | ok | ok | ok | BLOCKED | BLOCKED(UNKNOWN) | BLOCKED(UNKNOWN) |
| U01 | unknown | V3/5(UNKNOWN) | V3/5(UNKNOWN) | V3/5(UNKNOWN) | ok | V1/5(UNKNOWN) | V1/5(UNKNOWN) |
| U02 | unknown | V3/4(UNKNOWN) | V3/4(UNKNOWN) | V3/4(UNKNOWN) | ok | V1/4(UNKNOWN) | V1/4(UNKNOWN) |

| id | what happens |
|---|---|
| A01 | after approval the document is reclassified from PUBLIC to RESTRICTED; the queued export still runs |
| A02 | after approval the document content is replaced by sensitive content (same class) |
| A03 | the principal's export grant is revoked after approval; the queued job still runs with the old credentials |
| A04 | policy is tightened after approval (PUBLIC exports disabled) |
| A05 | the queued job is dispatched long after the approval expired |
| A06 | the same approval is replayed under a new request id (second export) |
| A07 | DNS rebinding: the approved host resolves to a different address when the connection is made |
| A08 | the approved host starts redirecting to a host the policy does not allow |
| A09 | agent B presents agent A's token (handoff without re-approval); B holds no export grant |
| A10 | two writers update the same object from the same base version (conflicting commits) |
| A11 | time skew: the dispatch worker's clock is 80 s behind and accepts an expired token |
| A12 | the approver cancels the approval after issuing it; the queued export still runs |
| A13 | a token issued for one object is used for another (INTERNAL object to an external host) |
| B01 | unchanged object, approved export succeeds |
| B02 | the document is legitimately edited after approval; the operation re-obtains approval and succeeds (a re-approval is justified) |
| B03 | unrelated state changes (other rule, other object, other principal's grant) must not invalidate the approval |
| B04 | queued dispatch well within the approval's lifetime |
| B05 | stable DNS, and a redirect to another host the policy allows |
| B06 | retry with the same request id after the response was lost: one effect, same result |
| B07 | a job is handed from agent A to agent B, which obtains its own approval |
| B08 | concurrent writers on different objects (no conflict), and an unrelated export |
| B09 | dispatch one second before the approval expires |
| B10 | dispatch just after expiry: the operation re-obtains approval and succeeds (a re-approval is justified) |
| U01 | external provider with no conditional write: a reclassification can land between the final check and the provider applying the export |
| U02 | external provider queues the export and applies it later, unrevalidated |
| F01 | the revocation feed is offline while the approver cancels the approval |
| F02 | the revocation feed is offline during the matched legitimate export |

## Ablations: where the outcome changes against the full gateway

| ablation | scenarios that change (outcome → outcome) |
|---|---|
| temporal-no-actor | none (redundant in this suite) |
| temporal-no-object-id | none (redundant in this suite) |
| temporal-no-object-version | none (redundant in this suite) |
| temporal-no-object-class | none (redundant in this suite) |
| temporal-no-content | none (redundant in this suite) |
| temporal-no-grant | none (redundant in this suite) |
| temporal-no-policy-slice | none (redundant in this suite) |
| temporal-no-policy-recheck | none (redundant in this suite) |
| temporal-no-revocation | A12: ok→V2/4; F01: ok(UNKNOWN)→V2/4; F02: BLOCKED(UNKNOWN)→ok |
| temporal-no-destination | A07: ok→V2/4 |
| temporal-no-redirect | A08: ok→V3/4 |
| temporal-no-nonce | A06: ok→V1/1 |
| temporal-no-expiry | A05: ok→V1/1; A11: ok→V1/1; B10: ok→ok* |
| temporal-no-authoritative-clock | A11: ok→V1/1 |
| temporal-no-atomic | A01: ok→V1/5; A02: ok→V1/4; A03: ok→V1/5; A04: ok→V1/5; A12: ok→V1/5; B02: ok→ok*; U02: V1/4(UNKNOWN)→V2/9(UNKNOWN) |
| temporal-no-idempotent | none (redundant in this suite) |
| temporal-no-fail-closed | F01: ok(UNKNOWN)→V2/4; F02: BLOCKED(UNKNOWN)→ok |

Redundant here: temporal-no-actor, temporal-no-object-id, temporal-no-object-version, temporal-no-object-class, temporal-no-content, temporal-no-grant, temporal-no-policy-slice, temporal-no-policy-recheck, temporal-no-idempotent. Several mechanisms overlap: the object-version check subsumes class, content and id changes, the policy re-evaluation subsumes the slice digest and the grant check, and the principal check overlaps the grant check. Redundancy is the defence in depth the design intends, not evidence that a mechanism is unnecessary; `last-write-wins` is the ablation of compare-and-swap writes (A10).

## Machine-checkable invariants (`results/v2/p52-temporal/invariants.json`)

| id | name | holds on the suite | scope |
|---|---|---|---|
| I1 | NO_STALE_EFFECT | True | supported sink (conditional, atomic with the gateway), revocation feed up, authoritative clock |
| I2 | BENIGN_LIVENESS | True | same as I1 |
| I3 | UNKNOWN_NOT_VERIFIED | True | external sinks U01, U02 |
| I4 | FAIL_CLOSED | True | feed offline scenarios F01, F02 |
| I5 | SINGLE_COMMIT | True | A10 |

Statements:

- **I1** for every attack scenario and every interleaving of its steps, the full gateway produces no effect the oracle judges prohibited or stale
- **I2** for every benign scenario and every interleaving, the expected effect occurs exactly as expected, with a re-approval only where the state really changed
- **I3** where the sink cannot be conditioned or applies the effect later, every violating interleaving is reported UNKNOWN by the gateway; none is reported as a verified success
- **I4** with the revocation feed offline the gateway never produces an effect on a revoked approval; it returns UNKNOWN
- **I5** for concurrent writers from one base version exactly one commits (compare-and-swap); no lost update is recorded

## Recorded counterexample interleavings (49)

First violating interleaving per (attack, baseline), plus the unsupported-sink paths where even the full gateway cannot prevent the effect (it flags UNKNOWN). Full list in `invariants.json`.

| scenario | system | interleaving | oracle reasons |
|---|---|---|---|
| A01 | one-time-check | approve → wait → reclassify → dispatch#1 | OBJECT_CHANGED,POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A02 | one-time-check | approve → wait → swap → dispatch#1 | OBJECT_CHANGED,CONTENT_CHANGED,CANARY_EXPORTED |
| A03 | one-time-check | approve → wait → revoke → dispatch#1 | GRANT_CHANGED,FORBIDDEN_BY_POLICY |
| A04 | one-time-check | approve → wait → tighten → dispatch#1 | POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A05 | one-time-check | approve → wait → dispatch#1 | EXPIRED_APPROVAL |
| A06 | one-time-check | approve → d1#1 → d2#1 | REPLAYED_APPROVAL |
| A07 | one-time-check | approve → wait → rebind → dispatch#1 | FORBIDDEN_BY_POLICY |
| A08 | one-time-check | approve → wait → redirect → dispatch#1 | DESTINATION_ESCAPED |
| A09 | one-time-check | approve → b_dispatch#1 | NO_VALID_APPROVAL |
| A10 | one-time-check | w1 → w2 | LOST_UPDATE |
| A11 | one-time-check | approve → wait → dispatch#1 | EXPIRED_APPROVAL |
| A12 | one-time-check | approve → wait → cancel → dispatch#1 | REVOKED_APPROVAL |
| A01 | jwt-expiry | approve → wait → reclassify → dispatch#1 | OBJECT_CHANGED,POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A02 | jwt-expiry | approve → wait → swap → dispatch#1 | OBJECT_CHANGED,CONTENT_CHANGED,CANARY_EXPORTED |
| A03 | jwt-expiry | approve → wait → revoke → dispatch#1 | GRANT_CHANGED,FORBIDDEN_BY_POLICY |
| A04 | jwt-expiry | approve → wait → tighten → dispatch#1 | POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A06 | jwt-expiry | approve → d1#1 → d2#1 | REPLAYED_APPROVAL |
| A07 | jwt-expiry | approve → wait → rebind → dispatch#1 | FORBIDDEN_BY_POLICY |
| A08 | jwt-expiry | approve → wait → redirect → dispatch#1 | DESTINATION_ESCAPED |
| A09 | jwt-expiry | approve → b_dispatch#1 | NO_VALID_APPROVAL |
| A10 | jwt-expiry | w1 → w2 | LOST_UPDATE |
| A11 | jwt-expiry | approve → wait → dispatch#1 | EXPIRED_APPROVAL |
| A12 | jwt-expiry | approve → wait → cancel → dispatch#1 | REVOKED_APPROVAL |
| A13 | jwt-expiry | approve → wait → d_other#1 | OBJECT_CHANGED,CONTENT_CHANGED,POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A01 | op-token-no-object | approve → wait → reclassify → dispatch#1 | OBJECT_CHANGED,POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A02 | op-token-no-object | approve → wait → swap → dispatch#1 | OBJECT_CHANGED,CONTENT_CHANGED,CANARY_EXPORTED |
| A03 | op-token-no-object | approve → wait → revoke → dispatch#1 | GRANT_CHANGED,FORBIDDEN_BY_POLICY |
| A04 | op-token-no-object | approve → wait → tighten → dispatch#1 | POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A07 | op-token-no-object | approve → wait → rebind → dispatch#1 | FORBIDDEN_BY_POLICY |
| A08 | op-token-no-object | approve → wait → redirect → dispatch#1 | DESTINATION_ESCAPED |
| A10 | op-token-no-object | w1 → w2 | LOST_UPDATE |
| A12 | op-token-no-object | approve → wait → cancel → dispatch#1 | REVOKED_APPROVAL |
| A13 | op-token-no-object | approve → wait → d_other#1 | OBJECT_CHANGED,CONTENT_CHANGED,POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A10 | restrictive-rule | w1 → w2 | LOST_UPDATE |
| A10 | last-write-wins | w1 → w2 | LOST_UPDATE |
| U01 | temporal | approve → wait → dispatch#1 → reclassify → dispatch#2 | OBJECT_CHANGED,POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| U02 | temporal | approve → wait → dispatch#1 → reclassify → flush | OBJECT_CHANGED,POLICY_CHANGED,FORBIDDEN_BY_POLICY |
| A12 | temporal-no-revocation | approve → wait → cancel → dispatch#1 | REVOKED_APPROVAL |
| A07 | temporal-no-destination | approve → wait → rebind → dispatch#1 | FORBIDDEN_BY_POLICY |
| A08 | temporal-no-redirect | approve → wait → redirect → dispatch#1 | DESTINATION_ESCAPED |

## What this does and does not show

- The UNKNOWN flag on U01/U02 is produced by the sink interface (a sink that cannot be conditioned, or defers, reports UNKNOWN to every caller), so the baselines also carry it in this table; the claim for the gateway is only that it never reports such an effect as a verified success. Baselines differ in whether they would have prevented anything else.
- Zero violating interleavings for the full gateway is a property of 13 attack scenarios, each with 1–4 interleavings, written by the same author. It is not a proof (the document `ASSUMPTIONS_AND_LIMITS.md` states the scoped theorem and its assumptions).
- Where the effect cannot be made atomic with the check (U01) or is applied later by an external provider (U02), a violating interleaving exists even for the full gateway. It is reported UNKNOWN, not prevented. This is the constraint P52-15 asks to be reported.
- Overhead: `scripts/p52_bench.py` (machine-specific, not recorded). Each decision costs a bounded number of local store reads and one signature verification; the model measures relative cost only.
- Nothing here is promoted beyond CANDIDATE.
