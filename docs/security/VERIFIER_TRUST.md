# Independent verifier: trust assumptions and residual bypass risks (candidate, P85)

Status: CANDIDATE. Written by the implementer; not independently reviewed. CG-07/CG-08 are **not** claimed.

## What the verifier guarantees (each backed by a test in `tests/supervisor/test_verifier2.py`)
- The verdict is derived only from the verifier's own run in a fresh clone checked out at the exact submitted commit. No function parameter accepts a worker-supplied exit code, log or PASS claim. Uncommitted files in the worker's tree are never seen.
- Modification, deletion or type-change of a **pre-existing** protected file (tests, graders, fixtures matched by trusted globs) fails the task and the commands are not run. New files are allowed, except names that can alter test behaviour (`conftest.py`, `sitecustomize.py`, `pytest.ini`, `tox.ini`, `setup.cfg`, `pyproject.toml`, `.coveragerc`, `*.pth`).
- Missing independent telemetry for a required protected sink gives `UNKNOWN`, which the ledger routes to `NEEDS_RECONCILIATION`. Worker-reported observations are recorded but never counted.
- Commands run with a scrubbed environment (no inherited credentials), no stdin, a throw-away HOME, a program allowlist and a timeout.
- The ledger accepts VERIFIED only for a receipt signed by a registered verifier key, bound to task, commit, epoch and plan digest, with consistent `exit_code`/`verdict`. Edited fields, swapped key ids, receipts for other commits, replays after re-lease, and receipts from revoked principals are rejected.
- A verifier crash leaves the task in VERIFYING; nothing is promoted.

## Trust assumptions (if any is false, the guarantees above do not hold)
1. `acceptance`, `protected_globs`, `required_sinks` and `base` come from the trusted plan / main branch, not from the worker's commit.
2. The verifier key (HMAC, symmetric) is held only by the verifier process. The ledger holds the same secret to verify receipts, so **anyone who can read the ledger process's keys can forge verifier receipts**. A real deployment needs asymmetric signatures or a separate signing service.
3. `independent_observed` comes from a protected collector that this repository does **not** implement. The verifier trusts whatever list the caller passes.
4. `env_digest` is recorded as given; the verifier does not compute or check it against a locked dependency set.
5. The host and the git binary are not compromised.

## Residual bypass risks (known, not mitigated here)
- **Not a sandbox.** Acceptance commands run as the verifier's OS user. A hostile test or build step can read files that user can read, use the network, or spawn background processes. Run the verifier under a container/VM with no network and no access to key material before relying on it against adversarial workers.
- **Non-protected behavioural changes.** A worker can change *source* so that existing tests pass vacuously (e.g. special-casing test inputs). File-level tamper detection does not catch this; only stronger oracles (mutation testing, held-out tests) do.
- **Glob coverage.** Anything not matched by `protected_globs` is unprotected. Misconfigured globs silently weaken the check.
- **Shadow-name list is finite.** Other mechanisms that change test discovery or imports (e.g. a new module that shadows a stdlib name, `.env` loaded by a plugin) are not detected.
- **Revocation is process-local.** `revoke_principal` removes the key from one ledger instance; receipts accepted earlier remain accepted unless the task is explicitly invalidated.
- **Hash chain not externally anchored** (see `docs/operations/SUPERVISOR_RESTORE.md`).
- **Single reviewer role.** P85-14 (independent review of critical policy/sandbox changes before VERIFIED) is not implemented.
