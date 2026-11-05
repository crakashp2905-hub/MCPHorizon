# Commit-protocol proof slice (permit -> ledger -> separate-principal sink -> reconciliation) — ASSUMPTIONS AND LIMITS

Status: CANDIDATE. Author-run. NOT independently verified. No novelty claim (see PRIOR_WORK).

## What was done
1. `research/commitproof/model.py`: explicit-state EXHAUSTIVE exploration of the protocol (1 effect, 1 permit, N workers incl. crashes, replays, slow "zombie"
   workers, recovery, reconciliation).  Invariants checked in every reachable state: I1 at most one sink effect; I2 no sink effect without a consumed permit;
   I3a COMMITTED/RECONCILED_COMMITTED => sink evidence; I3b BLOCKED/RECONCILED_BLOCKED => no sink effect (ever); I5 no unresolved dead end.
2. Results (n = number of workers): proposed design safe for n=3..6 (145/385/961/2305 states); designs with one safeguard removed give shortest counterexamples:
   | design | violated | shortest counterexample |
   |---|---|---|
   | reconcile by plain read while recovery may race a live owner | I3b | authorize; begin; recover; reconcile(read); **late sink_write** (5 steps) |
   | retry begin from UNKNOWN | I1 | ...sink_write; crash; recover; retry_begin; sink_write |
   | retry begin while STARTED (timeout) | I1, I3a | begin; sink_write; second dispatcher begins; sink_write |
   | per-worker nonce stores | I1, I3a | two workers each "authorize" locally and write (4 steps) |
   | no orphan expiry | I5 | authorize; crash -> ledger AUTHORIZED forever (permit burned, effect never resolved) |
   The fence (atomic fence-and-observe at the sink) is needed exactly when recovery may fire while the owner is alive; with recovery only after owner death an unfenced
   observe is also safe.
3. Two real defects found in the implementation by this exercise and FIXED: (a) reconciliation used a plain journal read, so a slow worker could write after
   RECONCILED_BLOCKED (now `FileSink.fence_and_observe` / sinkproc `fence`, with a persisted tombstone and `FENCED`/`ALREADY_WRITTEN` refusals); (b) AUTHORIZED effects
   whose authorizer died were never resolved (now `EffectLedger.expire_authorized`, safe because `begin` is an atomic compare-and-set).  `ProtectedFileWriter.write` also
   no longer raises when the ledger has already moved on.
4. Conformance: every transition (576) of every reachable model state (248, design `proposed_expiry_any_time`, 3 workers) is executed on the real ledger + file sink
   + `ProtectedFileWriter.reconcile`; ledger state, permit consumption, sink effect count, fence, worker pcs and owner must equal the model's successor.
5. Mutation checks: model 15/15 (+1 documented equivalent exclusion), implementation 17/17 (conformance + e04 + e05 + e06 tests).

## What this does NOT show
- It is a BOUNDED proof about a MODEL, not about the code: one effect, <=6 workers, no clocks, no multiple effects, no byzantine worker that bypasses the sink
  (that is OS separation, tests/e06, which assumes the sink uid and kernel are not compromised and the gateway uid is not held by the agent), no ledger/sink data loss,
  no malicious or deceptive sink, no first-call disclosure to dishonest remote services (HorizonReach, unsolved).
- Conformance is single-process and covers the abstract steps only; request+authorize is one abstract step (two real transactions); `recover()` is unguarded in the
  code, so the code corresponds to the timeout-recovery design (safe only because of the fence).
- Sink journal and ledger are single-host files (flock / SQLite). Cross-host failover and fenced leadership (B02-03), backup/restore, and permit-to-effect binding are
  not covered here.
- Post-write tampering of the target file makes the reconcile result BLOCKED by existing design (`present_now`); this is outside the model's I3b.
- Reconciliation tells you what the SINK recorded, not what the external world did after the sink.
- No independent reviewer has examined the model, the invariants, or the correspondence; a reviewer should specifically try to find a protocol step missing from the model.
