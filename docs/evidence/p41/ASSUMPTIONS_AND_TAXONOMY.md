# P41 — assumptions, snapshot isolation, mismatch taxonomy, irreversibility (CANDIDATE)

## Effect-diff contract (P41-01)
Schema `effect-diff/1.0.0` (`horizon/counterfactual/core.py: Diff, validate_diff`): `adapter`, `op_digest`, ordered `changes` of `{kind, target, key, before, after}` (digests, not values, for DB rows), `irreversible`, `external`, `unknown`. The diff digest is what verdicts bind to. An `Contract` (allowed tables / path prefixes / public prefixes / expected cardinality / destinations / forbidden content classes) is policy-owner input, independent of the agent's ACL. The contract is a *threat-aware limit on effect*, not a description of intent: here the main signal is the declared expected row count.

## Snapshot isolation and consistency, per adapter (P41-02)
| Adapter | Preview is | Consistency assumption | Where it breaks |
|---|---|---|---|
| DB (SQLite) | `Connection.backup` clone in memory, op executed on two independent clones | clone reflects committed state at backup time; triggers and defaults are present in the clone | writers between preview and commit (handled by commit-time re-derivation); non-deterministic SQL (detected by double run → REVIEW); extension functions, `ATTACH`, `PRAGMA` (refused as UNSUPPORTED); other engines |
| File | copy of the root into a temp dir, op applied there | single writer to the root; flock around commit | writers that do not take the lock; hard links, symlinks, special files, huge trees (copy cost) |
| Publication | manifest of files, digests, classes, destination | package directory unchanged between preview and publish (checked by digest at apply) | the remote registry's own behavior after receipt (async processing, mirroring, caching) is not modeled |

## Commit path (P41-07/08)
DB: `BEGIN IMMEDIATE`, re-derive the diff against the *current* state inside the transaction, commit only if its digest equals the approved digest (else roll back with `STATE_CHANGED`). This tolerates unrelated concurrent changes and rejects changes that alter the touched rows or the predicate's scope. Files: flock + recompute. Before commit the gate also re-verifies the attestation (signature, expiry, **current policy revision**) and that the attestation is bound to the exact operation digest.
Publication has no transaction: it is `external` + `irreversible`, so the verdict is at best REVIEW and publishing needs an owner approval bound to the operation and diff digests.

## Mismatch taxonomy (P41-10/11/16)
| Class | Meaning | Severity | Response |
|---|---|---|---|
| NONE | independent receipt equals approved diff | — | none |
| LOW | fewer changes than approved | low | log |
| MEDIUM | extra changes, inside allowed tables and cardinality | medium | incident + freeze task |
| HIGH | extra changes outside allowed tables or cardinality | high | incident + freeze + automatic rollback from the pre-commit backup, then independent re-check (`verified` only if the receipt equals the pre-commit state) |
| CRITICAL (publication) | registry journal differs from the approved manifest | critical | cannot roll back: escalate; freeze |
The post-commit path is exercised in tests with the gate's in-commit verification disabled (a degraded mode standing in for a store without transactions); with verification on, the independent receipt matched the approved diff in every committed run.

## Irreversibility exceptions and negative cases
* Anything `external` or `irreversible` (publication, file removal) is never auto-ALLOWed.
* Preview unreliability (non-deterministic SQL, preview errors) yields REVIEW/UNKNOWN, not ALLOW.
* The rollback demonstrated is row-level restore from a whole-DB backup taken just before commit; it is not safe under concurrent writers and is not claimed to be.
* Negative result worth keeping: the DB preview's `LIMIT`-less cardinality rule means a *legitimate* large bulk update needs a contract that expects it (B04); a wrongly authored contract produces false refusals (the first version of this experiment had one — fixed after it was observed).
