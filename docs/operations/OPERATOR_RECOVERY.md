# hzd operator recovery procedure (CANDIDATE)

Status: exercised only by automated tests (`tests/blueprint/test_product_pkg.py`) on synthetic homes; **not rehearsed by a human operator** on a real host.

## Routine backup
`hzd backup` → writes `hzd-backup-<ts>.tar.gz` (config, PUBLIC trust, state, runs; **no secret key**) and prints its sha256. Record the hash where `hzd` cannot rewrite it (separate commit, ticket, paper log). A backup whose hash you did not record elsewhere proves only self-consistency. Back up `keys/evidence.pem` through your own key-custody process.

## Detect trouble — `hzd recover` (read-only; exit 1 on any failure)
| component | FAILED means | note |
|---|---|---|
| journal | hash chain broken, **tail truncated** (sink anchor mismatch) or records appended outside the sink | an attacker who rewrites journal *and* anchor together is not detected; keep the anchor/hashes elsewhere |
| ledger | sqlite integrity check failed | |
| bundles | signature/receipt check failed for the listed run ids | treat those runs as unverified |
`unknown_effects` in the ledger report are effects whose outcome is UNKNOWN. They are **listed, never auto-resolved or retried**: reconcile each against the real repository state by hand before re-running anything.

## Restore
1. Stop all `hzd` runs and the dashboard.
2. Move the damaged home aside (do not delete it; it is evidence).
3. `hzd --home <new-dir> restore <backup.tar.gz> --sha256 sha256:<recorded hash>` — refuses an existing directory, a hash mismatch, a non-gzip archive, or any member outside `config.json`, `keys/trust.json`, `state/`, `runs/`; runs `recover` on the result and deletes the restored copy if it fails.
4. The restored home has **no secret key**: place the evidence key at `<new-dir>/keys/evidence.pem` (mode 0600, owned by the service user) before any new `hzd run`. Verification of old bundles works without it.
5. Run `hzd recover` and `hzd verify` on a few bundles. Work done since the backup is not in the restored home; compare the repository against the last bundle's `repo.after` digest to see what changed.

## Key loss or suspected compromise
Old bundles stay verifiable with the old public key. Issue a new key under a new kid (rotation needs a new kid in the trust file) and treat bundles signed after the suspected compromise as untrusted. Rotation tooling is not built here.
