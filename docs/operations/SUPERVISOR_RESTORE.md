# Supervisor ledger: backup, restore and proof of no false VERIFIED (P76-18)

Status: CANDIDATE operator procedure. Exercised only by the automated tests in `tests/supervisor/test_recovery.py` on synthetic ledgers; it has **not** been rehearsed by a human operator on a real campaign ledger.

## Backup (any time, supervisor online)
```python
from orchestrator.recovery import backup
sha = backup(ledger, "backups/ledger-2026-10-31.db")   # SQLite online backup API; refuses if the journal hash chain is already broken
```
Record `sha` somewhere the supervisor cannot rewrite (a separate commit, ticket or paper log). A backup whose hash you did not record elsewhere proves only self-consistency.

## When to restore
Restore when opening the ledger raises `LedgerError` ("not a readable database", "failed integrity check", "schema newer than supported"), when `verify_journal()` is False, or after disk-full left the file unusable. Do **not** edit the live database by hand.

## Restore
```python
from orchestrator.recovery import restore
led = restore("backups/ledger-2026-10-31.db", "ledger.restored.db", principals, expect_sha256=sha)
```
`restore` refuses to overwrite an existing file, checks the recorded hash, then runs `audit_verified`. If anything fails it deletes the restored copy and raises. Only after it returns may you point the supervisor at the restored file.

## What `audit_verified` proves (and does not)
For every VERIFIED task it requires: the hash chain is intact; the last transition to VERIFIED was made by a principal registered as `verifier`; the journaled receipt has `exit_code` 0 and a `git_sha` equal to the stored `verified_sha`; and receipt and journal entry are bound to the current plan digest. A forged status column, a rewritten actor, a swapped plan digest or a missing transition all make restore fail (each is a test).

It does **not** prove the verifier's key was uncompromised, that the acceptance command actually tests the task, or that a hash-chain suffix was not truncated by someone able to rewrite the whole file — the chain is local-trust, not an external anchor. Record the journal head hash outside the ledger regularly if you need truncation to be detectable.

## After restore
1. Run `python3 scripts/horizon_plan.py --ledger ledger.restored.db status`.
2. Run `reclaim_expired` as supervisor: leases from the lost interval are fenced (epochs never reset) and tasks with unconfirmed external effects go to NEEDS_RECONCILIATION, never to automatic retry.
3. Reconcile each such task against the real external system before calling `reconcile(..., evidence)`.
4. Work done after the backup point is lost; re-run it. Any VERIFIED state from that interval must be re-earned.
